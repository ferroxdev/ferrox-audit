//! The native `Psiphon` lane: a signed server list, the SSH/OSSH transport in
//! [`crate::psiphon_ssh`], and the loopback SOCKS edge the proxy dials.

use crate::json::{self, Json};
use crate::psiphon_broker::Value as Cbor;
use crate::psiphon_ssh::{
    ApiEncoding, Channel, ChannelChunk, Identity, KeepAlive, Proxy, Server, Session, TlsShape,
    MAX_PADDING, MIN_PADDING,
};
use crate::psiphon_webrtc::is_bogon;
use crate::socks::{Credential, Destination, Version};
use crypto_secretbox::aead::{Aead as _, KeyInit as _};
use ferrox_core::tls::shaped::{Body, Ext, Profile};
use ferrox_core::tls::Fingerprint;
use flate2::read::ZlibDecoder;
use ring::signature;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{self, IoSlice, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

const SPONSOR_ID: &str = "07D1ACD69B3AC7A2";
const PROPAGATION_CHANNEL_ID: &str = "EE0B7486ACAE75AA";
const CLIENT_VERSION: &str = "453";
const DSL_REQUEST_NAME: &str = "psiphon-dsl";
const DSL_MAX_PAYLOAD: usize = 65_536;
const DSL_VERSION: u64 = 0;
const DSL_DISCOVER: u64 = 1;
const DSL_GET: u64 = 2;
/// The compartment ID the public Android build embeds for its private conduits.
const PRIVATE_COMPARTMENT_ID: &str = "/TYUL7wjyPuXCGAujuiQuxTRlOFhjMglpDX2kzVo/ks";
/// The regions the Android client rejects when its censored-country switch is on.
const CENSORED_COUNTRY_CODES: &[&str] = &["IR", "CN", "RU", "BY", "TM", "KP"];
const UDPGW_HOST: &str = "127.0.0.1";
const UDPGW_PORT: u16 = 7300;
const UDPGW_FLAG_KEEPALIVE: u8 = 1;
const UDPGW_FLAG_REBIND: u8 = 2;
const UDPGW_FLAG_IPV6: u8 = 8;
const UDPGW_MAX_PAYLOAD: usize = 32_768;
const UDPGW_MAX_MESSAGE: usize = 32_768 + 23;
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const RELAY_BUFFER: usize = 256 * 1024;
const RELAY_BATCH: usize = 64;
/// How long a fetched OSL registry and its files are reused before another attempt.
const OSL_REFRESH: Duration = Duration::from_secs(300);
/// How long one server classification keeps a destination on the direct path.
const SPLIT_TUNNEL_CLASSIFICATION_TTL: Duration = Duration::from_hours(24);
/// The reference's cap on cached split-tunnel classifications.
const SPLIT_TUNNEL_CLASSIFICATION_MAX: usize = 65_536;
const FRONTED_VARIANTS: usize = 256;
const FRONTED_SERVERS: usize = 512;
/// The reference's aggressive queue: three fronted CDN protocols at an
/// eight-way fanout per server entry before the next entry.
const CDN_SCAN_STRIDE: usize = 24;
/// The first tactics entry to try on the next establishment pass.
static TACTICS_CURSOR: AtomicUsize = AtomicUsize::new(0);
/// The least time one tactics entry gets before the pass moves on.
const TACTICS_ATTEMPT_MIN: Duration = Duration::from_secs(10);

const CDN_FRONTING_PROTOCOLS: &[&str] = &[
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const CDN_PROTOCOL_OSSH: u8 = 1;
const CDN_PROTOCOL_HTTP: u8 = 2;
const CDN_PROTOCOL_QUIC: u8 = 4;
const DIRECT_PROTOCOLS: &[&str] = &[
    "SSH",
    "OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "QUIC-OSSH",
    "SHADOWSOCKS-OSSH",
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const CONDUIT_PROTOCOLS: &[&str] = &[
    "INPROXY-WEBRTC-SSH",
    "INPROXY-WEBRTC-OSSH",
    "INPROXY-WEBRTC-TLS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
    "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
    "INPROXY-WEBRTC-QUIC-OSSH",
    "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH",
];
const CDN_FASTLY_VERIFY_NAMES: &[&str] = &[
    "www.python.org",
    "pypi.org",
    "fastly.com",
    "www.fastly.com",
    "developer.fastly.com",
    "githubassets.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
];
const CDN_EDGE_VERIFY_NAMES: &[&str] = &[
    "a248.e.akamai.net",
    "a.akamaized.net",
    "a.akamaized-staging.net",
    "a.akamaihd.net",
    "a.akamaihd-staging.net",
    "www.akamai.com",
];
const CDN_EDGE_ADDRESSES: &[(&str, &str)] = &[
    ("edge-a-1", "23.215.0.206"),
    ("edge-a-2", "23.215.0.203"),
    ("edge-b-1", "23.212.250.91"),
    ("edge-b-2", "23.212.250.78"),
    ("edge-c-1", "23.12.147.13"),
    ("edge-c-2", "23.12.147.29"),
    ("edge-d-1", "23.73.207.8"),
    ("edge-d-2", "23.73.207.15"),
    ("edge-original", "92.123.102.43"),
];
const MAX_REQUEST: usize = 16 * 1024;
const DIAL_ATTEMPTS: usize = 64;
const DIAL_WORKERS: usize = 10;
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const HOLD_OFF_LIMIT: Duration = Duration::from_secs(60);
const FLOW_STACK: usize = 128 * 1024;

static NO_CREDENTIAL: Credential = Credential {
    user: String::new(),
    pass: String::new(),
};

/// The outbound as a flow sees it: a native tunnel and the loopback SOCKS edge over it.
#[derive(Clone)]
pub(crate) struct PsiphonOut {
    inner: Option<Arc<Inner>>,
    endpoint: SocketAddr,
    credential: Arc<Credential>,
    version: Version,
    loopback: bool,
    shutdown: Option<Arc<LaneShutdown>>,
}

struct LaneShutdown {
    stopped: Arc<AtomicBool>,
    channels: Arc<Mutex<Vec<crate::psiphon_ssh::ChannelWaiter>>>,
}

impl LaneShutdown {
    fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            channels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            stopped: Arc::clone(&self.stopped),
            channels: Arc::clone(&self.channels),
        }
    }
}

impl Drop for LaneShutdown {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        for channel in lock(&self.channels).iter() {
            channel.wake();
        }
    }
}

struct ShutdownSignal {
    stopped: Arc<AtomicBool>,
    channels: Arc<Mutex<Vec<crate::psiphon_ssh::ChannelWaiter>>>,
}

impl ShutdownSignal {
    fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stopped)
    }

    fn watch(&self, channel: crate::psiphon_ssh::ChannelWaiter) {
        let mut channels = lock(&self.channels);
        channels.retain(crate::psiphon_ssh::ChannelWaiter::is_live);
        channels.push(channel);
    }
}

struct Inner {
    settings: Settings,
    config_state: u64,
    entries: Mutex<Arc<Vec<Server>>>,
    sloks: Arc<crate::psiphon_osl::SlokStore>,
    requests: Arc<crate::psiphon_osl::ServerEvents>,
    osl_seeded: Arc<AtomicBool>,
    osl_attempt: AtomicUsize,
    last_osl: Mutex<Option<Instant>>,
    last_osl_failure: Mutex<Option<Instant>>,
    upgrade_started: Arc<AtomicBool>,
    last_upgrade_attempt: Mutex<Option<Instant>>,
    dsl_running: AtomicBool,
    dsl_last_fetch: Mutex<Option<Instant>>,
    self_ref: Mutex<Weak<Self>>,
    sessions: Mutex<Vec<Arc<Session>>>,
    next_session: AtomicUsize,
    dial_window: AtomicUsize,
    entry_cursor: AtomicUsize,
    affinity: Mutex<Option<(String, u16)>>,
    moved_to_front: Mutex<HashSet<String>>,
    dsl_placeholders: Arc<Mutex<Vec<DslPlaceholder>>>,
    connecting: Mutex<()>,
    session_id: String,
    stopping: AtomicBool,
    endpoint: SocketAddr,
    http_endpoint: Option<SocketAddr>,
    udpgw: Mutex<Option<Arc<UdpGateway>>>,
    conduit: Mutex<Option<(ConduitMode, Arc<crate::psiphon_webrtc::Conduit>)>>,
    conduit_started: OnceLock<Instant>,
    conduit_fallback: AtomicBool,
    conduit_connected: AtomicBool,
    split_untunneled: Mutex<HashMap<String, Instant>>,
    replay: Arc<crate::psiphon_replay::Cache>,
    light: Option<Arc<crate::psiphon_light::Client>>,
    /// One in-proxy dial bucket for the client's life, as the reference holds it: a bucket built per attempt never throttles a client that reconnects.
    inproxy_limiter: Option<Arc<DialRateLimiter>>,
}

/// The reference's protocol hold-off: a jittered delay before a new tunnel is activated.
#[derive(Clone, Debug, Default)]
struct HoldOff {
    names: Vec<String>,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOff {
    /// The hold-off for a protocol, zero when it is not named.
    fn duration(&self, protocol: &str) -> Duration {
        if self.names.is_empty()
            || !self
                .names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
            || !coin(self.probability)
        {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

/// The reference's provider-scoped hold-off: direct and inproxy key on provider/region,
/// fronting keys on the fronting provider ID.
#[derive(Clone, Debug, Default)]
struct HoldOffClass {
    providers: Vec<(String, Vec<String>)>,
    region_scoped: bool,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOffClass {
    fn delay(&self, provider: Option<&str>, region: Option<&str>) -> Duration {
        if self.providers.is_empty() || !coin(self.probability) {
            return Duration::ZERO;
        }
        let Some(provider) = provider else {
            return Duration::ZERO;
        };
        let matched = self.providers.iter().any(|(id, regions)| {
            id == provider
                && (!self.region_scoped
                    || regions
                        .iter()
                        .any(|allowed| allowed.is_empty() || Some(allowed.as_str()) == region))
        });
        if !matched {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

#[derive(Clone, Debug)]
struct LivenessSpec {
    pattern: String,
    min_upstream: usize,
    max_upstream: usize,
    min_downstream: usize,
    max_downstream: usize,
}

/// The reference's liveness probes, keyed by tunnel-protocol pattern.
#[derive(Clone, Debug, Default)]
struct Liveness {
    initial: Vec<LivenessSpec>,
    periodic: Vec<LivenessSpec>,
}

impl Liveness {
    /// The first probe spec naming this protocol in the given state.
    fn spec(&self, protocol: &str, established: bool) -> Option<LivenessSpec> {
        let probes = if established {
            &self.periodic
        } else {
            &self.initial
        };
        let mut matched: Option<&LivenessSpec> = None;
        let mut fallback = None;
        for probe in probes {
            if probe.pattern.is_empty() {
                fallback = Some(probe);
            } else if wildcard_match(&probe.pattern, protocol)
                && matched.is_none_or(|best| probe.pattern.len() > best.pattern.len())
            {
                matched = Some(probe);
            }
        }
        matched.or(fallback).cloned()
    }
}

/// The reference's protocol wildcard: `*` matches any run of bytes, everything else is literal.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(mut rest) = text.strip_prefix(parts.next().unwrap_or_default()) else {
        return false;
    };
    let mut part = parts.next();
    while let Some(current) = part {
        part = parts.next();
        if part.is_none() {
            return current.is_empty() || rest.ends_with(current);
        }
        if current.is_empty() {
            continue;
        }
        let Some(at) = rest.find(current) else {
            return false;
        };
        rest = &rest[at + current.len()..];
    }
    rest.is_empty()
}

/// The dynamic server list fetcher's window, resolved from the config and the
/// handshake tactics in that order.
#[derive(Clone, Debug)]
struct Dsl {
    enable: bool,
    timeout: Duration,
    retry_count: usize,
    retry_delay: Duration,
    retry_jitter: f64,
    ttl: Duration,
    discover_min: usize,
    discover_max: usize,
    get_min: usize,
    get_max: usize,
    prioritize_new: f64,
    prioritize_existing: f64,
}

impl Default for Dsl {
    fn default() -> Self {
        Self {
            enable: false,
            timeout: Duration::from_secs(5),
            retry_count: 0,
            retry_delay: Duration::from_secs(5),
            retry_jitter: 0.3,
            ttl: Duration::from_hours(1),
            discover_min: 1,
            discover_max: 2,
            get_min: 30,
            get_max: 60,
            prioritize_new: 0.5,
            prioritize_existing: 0.25,
        }
    }
}

struct DslTag {
    tag: Vec<u8>,
    version: i32,
    prioritize: bool,
}

struct DslPlaceholder {
    host: String,
    port: u16,
    created: Instant,
}

fn dsl_placeholder_position(
    placeholders: &[DslPlaceholder],
    host: &str,
    port: u16,
) -> Option<usize> {
    placeholders
        .iter()
        .position(|placeholder| placeholder.host == host && placeholder.port == port)
}

fn expire_dsl_placeholder(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    host: &str,
    port: u16,
    ttl: Duration,
) {
    if ttl.is_zero() {
        return;
    }
    lock(placeholders).retain(|placeholder| {
        !(placeholder.host == host
            && placeholder.port == port
            && placeholder.created.elapsed() >= ttl)
    });
}

fn clear_dsl_placeholder(placeholders: &Mutex<Vec<DslPlaceholder>>, host: &str, port: u16) {
    let mut list = lock(placeholders);
    if let Some(at) = dsl_placeholder_position(&list, host, port) {
        list.remove(at);
    }
}

fn retain_dsl_placeholder(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    host: &str,
    port: u16,
    retain: f64,
) {
    if coin(retain) {
        return;
    }
    clear_dsl_placeholder(placeholders, host, port);
}

fn promote_dsl_placeholders(
    placeholders: &Mutex<Vec<DslPlaceholder>>,
    entries: &mut Vec<Server>,
    moved: &mut HashSet<String>,
    max: i64,
) {
    for placeholder in lock(placeholders).iter() {
        if max > 0 && i64::try_from(moved.len()).unwrap_or(i64::MAX) >= max {
            break;
        }
        if move_to_front(entries, &placeholder.host, placeholder.port) {
            moved.insert(format!("{}:{}", placeholder.host, placeholder.port));
        }
    }
}

impl Dsl {
    fn resolved(config: Option<&Json>, tactics: Option<&Json>) -> Self {
        let mut dsl = Self::default();
        dsl.apply(config);
        dsl.apply(tactics);
        if field(config, "DisableDSLFetcher")
            .and_then(Json::as_bool)
            .unwrap_or(false)
        {
            dsl.enable = false;
        }
        dsl
    }

    fn apply(&mut self, fields: Option<&Json>) {
        if let Some(enable) = field(fields, "EnableDSLFetcher").and_then(Json::as_bool) {
            self.enable = enable;
        }
        self.timeout = duration_field(fields, "DSLFetcherTunneledRequestTimeout", self.timeout)
            .min(Duration::from_mins(2));
        self.retry_count = number(fields, "DSLFetcherTunneledRequestRetryCount")
            .map_or(self.retry_count, |count| {
                usize::try_from(count).unwrap_or(usize::MAX)
            });
        self.retry_delay = duration_field(
            fields,
            "DSLFetcherTunneledRequestRetryDelay",
            self.retry_delay,
        )
        .min(Duration::from_mins(1));
        self.retry_jitter = decimal(fields, "DSLFetcherTunneledRequestRetryDelayJitter")
            .unwrap_or(self.retry_jitter)
            .clamp(0.0, 1.0);
        self.ttl = duration_field(fields, "DSLFetcherTunneledFetchTTL", self.ttl)
            .min(Duration::from_hours(24));
        self.discover_min = count_field(
            fields,
            "DSLFetcherTunneledDiscoverServerEntriesMinCount",
            self.discover_min,
        );
        self.discover_max = count_field(
            fields,
            "DSLFetcherTunneledDiscoverServerEntriesMaxCount",
            self.discover_max,
        );
        self.get_min = count_field(
            fields,
            "DSLFetcherTunneledGetServerEntriesMinCount",
            self.get_min,
        );
        self.get_max = count_field(
            fields,
            "DSLFetcherTunneledGetServerEntriesMaxCount",
            self.get_max,
        );
        self.prioritize_new = probability_field(
            fields,
            "DSLPrioritizeDialNewServerEntryProbability",
            self.prioritize_new,
        );
        self.prioritize_existing = probability_field(
            fields,
            "DSLPrioritizeDialExistingServerEntryProbability",
            self.prioritize_existing,
        );
        if self.discover_max < self.discover_min {
            self.discover_max = self.discover_min;
        }
        if self.get_max < self.get_min {
            self.get_max = self.get_min;
        }
    }
}

fn field<'a>(fields: Option<&'a Json>, key: &str) -> Option<&'a Json> {
    fields.and_then(|fields| fields.get(key))
}

fn duration_field(fields: Option<&Json>, key: &str, default: Duration) -> Duration {
    let Some(value) = field(fields, key) else {
        return default;
    };
    if let Some(text) = value.as_str() {
        return go_duration(text).unwrap_or(default);
    }
    value.as_i64().map_or(default, |nanos| {
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(0))
    })
}

fn count_field(fields: Option<&Json>, key: &str, default: usize) -> usize {
    number(fields, key).map_or(default, |count| count.min(256) as usize)
}

/// The reference's token bucket for in-proxy dials; zero disables it.
fn rate_limit(fields: Option<&Json>) -> Option<(usize, Duration)> {
    let quantity = number(fields, "InproxyClientDialRateLimitQuantity").unwrap_or(2);
    if quantity == 0 {
        return None;
    }
    let interval = number(fields, "InproxyClientDialRateLimitIntervalMilliseconds").map_or_else(
        || {
            duration_field(
                fields,
                "InproxyClientDialRateLimitInterval",
                Duration::from_millis(500),
            )
        },
        Duration::from_millis,
    );
    if interval.is_zero() {
        return None;
    }
    Some((usize::try_from(quantity).unwrap_
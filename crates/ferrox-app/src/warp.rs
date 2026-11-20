//! WARP as one outbound: a device registration, a `WireGuard` half and a
//! MASQUE CONNECT-IP half, and the race that picks the first half that carries
//! a real DNS answer. Registering a device is a POST, a MASQUE key enrollment
//! is a PATCH, and switching the device on is a second PATCH. The identity the
//! three calls produce is saved once and reused, so a restart does not create
//! a second account.

use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::warp_scan::{self, Cooldowns, LastEdge, ScanMode};
use ferrox_core::wireguard::transport::{HEADER_SIZE as WG_HEADER_SIZE, TAG_SIZE as WG_TAG_SIZE};

use base64::Engine as _;

use crate::foxy_account::{Endpoint, Reply};

/// The API host Aether dials first, and the host `ZeroNet` still uses.
const API_HOSTS: [&str; 2] = ["api.devices.cloudflare.com", "api.cloudflareclient.com"];
/// The API version both pinned clients call.
const API_VERSION: &str = "v0a4471";
/// The HTTP authority WARP's CONNECT-IP endpoint answers on.
const CONNECT_HOST: &str = "cloudflareaccess.com";
/// The SNI the MASQUE edge presents.
const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
/// WARP's `WireGuard` endpoint port; the API lists many and this one is the documented one.
const WIREGUARD_PORT: u16 = 2408;
/// The MASQUE edge's UDP port.
const QUIC_PORT: u16 = 443;
/// The name the API answers a browser-less registration with.
const REGISTER_AGENT: &str = "WARP for Android";
/// The client version the registration body names.
const CLIENT_VERSION: &str = "a-6.35-4471";
/// The name the race asks through each half before it trusts it.
const PROBE_HOST: &str = "one.one.one.one";
/// The name's port: only the answer matters, not a connection.
const PROBE_PORT: u16 = 53;
/// The name an ironclad edge must carry a real HTTP response for.
const HTTP_PROBE_HOST: &str = "www.gstatic.com";
/// The path whose `204` the reference's ironclad check reads.
const HTTP_PROBE_PATH: &str = "/generate_204";
/// How long an ironclad edge waits for that response.
const HTTP_PROBE_TIMEOUT: Duration = Duration::from_secs(6);
/// The port an ironclad scan asks, unless `ironcladPort` or the environment moves it.
const IRONCLAD_PORT: u16 = 80;
/// How long a failed edge is left out of a rescan.
const COOLDOWN_SECS: u64 = 300;
/// The cap a cooldown or a stale timeout may not pass.
const SCAN_CAP_SECS: u64 = 86_400;
/// How long the race waits for a first successful answer.
const RACE_DEADLINE: Duration = Duration::from_secs(8);
/// The MTU WARP's own clients use.
const DEFAULT_MTU: u16 = 1280;
/// The reference caps the inner hop of gool at this MTU, so its packets fit the outer one.
const GOOL_INNER_MTU: u16 = 1200;
/// The RFC 9484 overhead a MASQUE datagram pays before the inner packet: the
/// reference's `MASQUE_DATAGRAM_OVERHEAD`.
const MASQUE_DATAGRAM_OVERHEAD: usize = crate::quic::MAX_DATAGRAM - DEFAULT_MTU as usize;
/// The narrowest inner datagram a QUIC peer may advertise.
const MIM_MIN_DATAGRAM: usize = 1200;
/// The narrowest inner MTU the reference allows.
const MIM_MIN_MTU: usize = 576;
/// The keepalive WARP's own clients use.
const DEFAULT_KEEPALIVE: u16 = 25;
/// The tunnel's DNS servers, reachable from either half once it is up.
const TUNNEL_DNS: [&str; 2] = ["1.1.1.1", "2606:4700:4700::1111"];

/// The API reply holds the `WireGuard` half's private key only on this side; the
/// peer key, endpoint, reserved bytes and tunnel addresses come back over the
/// wire, and the MASQUE key is the one enrolled after the device exists.
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    device_id: String,
    token: String,
    wireguard: WireGuardIdentity,
    masque: Option<MasqueIdentity>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token re-registers the device and the two identities hold private keys; neither belongs in a log line.
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("wireguard", &self.wireguard)
            .field("masque", &self.masque)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct WireGuardIdentity {
    private: [u8; 32],
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

#[derive(Clone, PartialEq, Eq)]
struct MasqueIdentity {
    private: Vec<u8>,
    server: Vec<u8>,
    addresses: Vec<IpAddr>,
}

impl std::fmt::Debug for WireGuardIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardIdentity")
            .field("private", &"<redacted>")
            .field("peer", &self.peer)
            .field("endpoint", &self.endpoint)
            .field("addresses", &self.addresses)
            .field("reserved", &self.reserved)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MasqueIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueIdentity")
            .field("private", &"<redacted>")
            .field("server", &"<redacted>")
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

/// Which half the outbound may use, before the race has answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Auto,
    WireGuard,
    Masque,
    Gool,
    GoolClassic,
    Mim,
}

impl Mode {
    fn parse(text: Option<&str>) -> Result<Self, String> {
        match text.unwrap_or("auto").to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "wireguard" | "wg" => Ok(Self::WireGuard),
            "masque" => Ok(Self::Masque),
            "gool" | "wg-over-masque" => Ok(Self::Gool),
            "gool-classic" | "wiw" | "warp-in-warp" => Ok(Self::GoolClassic),
            "mim" | "masque-in-masque" => Ok(Self::Mim),
            other => Err(format!(
                "warp mode `{other}` is not auto, wireguard, masque, gool, gool-classic or mim"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::WireGuard => "wireguard",
            Self::Masque => "masque",
            Self::Gool => "gool",
            Self::GoolClassic => "gool-classic",
            Self::Mim => "mim",
        }
    }
}

/// One parsed `warp` outbound setting list. Everything has a WARP default so a
/// one-tap identity file is the whole config.
#[derive(Debug, Clone)]
struct WarpSpec {
    mode: Mode,
    register: bool,
    identity_file: Option<PathBuf>,
    wireguard_identity_file: Option<PathBuf>,
    masque_identity_file: Option<PathBuf>,
    inline: Option<Identity>,
    api: Option<String>,
    api_address: Option<String>,
    endpoint: Option<SocketAddr>,
    mtu: u16,
    keepalive: u16,
    probe_host: String,
    probe_port: u16,
    dns: Vec<IpAddr>,
    masque_address: String,
    masque_port: u16,
    masque_server_name: String,
    masque_host: String,
    masque_path: String,
    scan: Option<ScanMode>,
    peer: Option<SocketAddr>,
    wg_peer: Option<SocketAddr>,
    ironclad_port: u16,
    quick_reconnect: bool,
    last_edge: Option<PathBuf>,
    stale: Option<Duration>,
    cooldown: Duration,
    noize: crate::noize::NoizeSettings,
    quic_v2: bool,
    gool: GoolSettings,
    mim: MimSettings,
}

struct EdgeSpec {
    scan: Option<ScanMode>,
    peer: Option<SocketAddr>,
    wg_peer: Option<SocketAddr>,
    ironclad_port: u16,
    quick_reconnect: bool,
    last_edge: Option<PathBuf>,
    stale: Option<Duration>,
    cooldown: Duration,
}

impl EdgeSpec {
    fn from(settings: &crate::json::Json) -> Result<Self, String> {
        let scan = match settings.get("scan") {
            Some(crate::json::Json::Str(text)) => scan_mode(text),
            Some(crate::json::Json::Bool(true)) => Some(ScanMode::Balanced),
            Some(crate::json::Json::Bool(false)) => None,
            _ => std::env::var("AETHER_SCAN")
                .ok()
                .as_deref()
                .and_then(scan_mode),
        };
        let peer = peer_setting(settings, "peer", "AETHER_PEER")?;
        let wg_peer = peer_setting(settings, "wgPeer", "AETHER_WG_PEER")?;
        let ironclad_port = settings
            .get("ironcladPort")
            .and_then(crate::json::Json::as_port)
            .or_else(|| env_u64("AETHER_IRONCLAD_PORT").and_then(|port| u16::try_from(port).ok()))
            .unwrap_or(IRONCLAD_PORT);
        let quick_reconnect = settings
            .get("quickReconnect")
            .and_then(crate::json::Json::as_bool)
            .or_else(|| env_bool("AETHER_QUICK_RECONNECT"))
            .unwrap_or(false);
        let last_edge = settings
            .get("lastEdge")
            .and_then(crate::json::Json::as_str)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let stale = settings
            .get("stale")
            .and_then(crate::json::Json::as_u32)
            .map(u64::from)
            .or_else(|| env_u64("AETHER_WG_STALE_SECS"))
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(seconds.min(SCAN_CAP_SECS)));
        let cooldown = settings
            .get("cooldown")
            .and_then(crate::json::Json::as_u32)
            .map(u64::from)
            .or_else(|| env_u64("AETHER_WG_ENDPOINT_COOLDOWN_SECS"))
            .map_or(Duration::from_secs(COOLDOWN_SECS), |seconds| {
                Duration::from_secs(seconds.min(SCAN_CAP_SECS))
            });
        Ok(Self {
            scan,
            peer,
            wg_peer,
            ironclad_port,
            quick_reconnect,
            last_edge,
            stale,
            cooldown,
        })
    }
}

/// The inner hop's explicit identity, files and edge.
#[derive(Debug, Clone, Default)]
struct GoolSettings {
    identity_file: Option<PathBuf>,
    inline: Option<Identity>,
    peer: Option<SocketAddr>,
    wiw_outer: Option<SocketAddr>,
    wiw_inner: Option<SocketAddr>,
}

fn gool_settings(settings: &crate::json::Json) -> Result<GoolSettings, String> {
    let identity_file = settings
        .get("goolIdentityFile")
        .and_then(crate::json::Json::as_str)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let inline = settings
        .get("goolIdentity")
        .map(Identity::from_json)
        .transpose()?;
    let peer = match settings.get("goolPeer") {
        None => None,
        Some(crate::json::Json::Str(text)) => Some(
            parse_endpoint(text)
                .ok_or_else(|| format!("warp gool: `goolPeer` is not an address: `{text}`"))?,
        ),
        Some(_) => return Err("warp gool: `goolPeer` must be a string".to_owned()),
    };
    Ok(GoolSettings {
        identity_file,
        inline,
        peer,
        wiw_outer: nested_peer(settings, "wiwOuter", "AETHER_WIW_OUTER_PEER")?,
        wiw_inner: nested_peer(settings, "wiwInner", "AETHER_WIW_INNER_PEER")?,
    })
}

/// The inner MASQUE hop's explicit identity, files and edge.
#[derive(Debug, Clone, Default)]
struct MimSettings {
    identity_file: Option<PathBuf>,
    inline: Option<Identity>,
    outer: Option<SocketAddr>,
    inner: Option<SocketAddr>,
}

fn mim_settings(settings: &crate::json::Json) -> Result<MimSettings, String> {
    let identity_file = settings
        .get("mimIdentityFile")
        .and_then(crate::json::Json::as_str)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let inline = settings
        .get("mimIdentity")
        .map(Identity::from_json)
        .transpose()?;
    let mut outer = nested_peer(settings, "mimOuter", "AETHER_MIM_OUTER_PEER")?;
    let mut inner = nested_peer(settings, "mimInner", "AETHER_MIM_INNER_PEER")?;
    if let Ok(peers) = std::env::var("AETHER_MIM_PEERS") {
        let peers = peers.trim();
        if !peers.is_empty() && !mim_scan_keyword(peers) {
            let mut hops = peers
                .split([',', ';', ' '])
                .filter(|hop| !hop.trim().is_empty());
            let first = hops.next();
            let second = hops.next();
            if hops.next().is_some() {
                return Err("warp mim: `AETHER_MIM_PEERS` names more than two hops".to_owned());
            }
            if outer.is_none() {
                outer = first.map_or(Ok(None), |hop| parse_mim_peer("AETHER_MIM_PEERS", hop))?;
            }
            if inner.is_none() {
                inner = second.map_or(Ok(None), |hop| parse_mim_peer("AETHER_MIM_PEERS", hop))?;
            }
        }
    }
    Ok(MimSettings {
        identity_file,
        inline,
        outer,
        inner,
    })
}

fn mim_scan_keyword(text: &str) -> bool {
    matches!(
        text.to_ascii_lowercase().as_str(),
        "auto" | "scan" | "none" | "off" | "0"
    )
}

fn parse_mim_peer(key: &str, text: &str) -> Result<Option<SocketAddr>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    parse_endpoint(text)
        .map(Some)
        .ok_or_else(|| format!("warp mim: `{key}` is not an address: `{text}`"))
}

fn nested_peer(
    settings: &crate::json::Json,
    key: &str,
    environment: &str,
) -> Result<Option<SocketAddr>, String> {
    let text = settings
        .get(key)
        .and_then(crate::json::Json::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(environment)
                .ok()
                .filter(|text| !text.is_empty())
        });
    text.map(|text| {
        parse_endpoint(&text).ok_or_else(|| format!("warp: `{key}` is not an address: `{text}`"))
    })
    .transpose()
}

fn spec_identity(
    settings: &crate::json::Json,
) -> Result<(Mode, bool, Option<PathBuf>, Option<Identity>), String> {
    let mode = Mode::parse(settings.get("mode").and_then(crate::json::Json::as_str))?;
    let register = settings
        .get("register")
        .and_then(crate::json::Json::as_bool)
        .unwrap_or(false);
    let identity_file = settings
        .get("identityFile")
        .and_then(crate::json::Json::as_str)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let inline = settings
        .get("identity")
        .map(Identity::from_json)
        .transpose()?;
    if inline.is_none() && identity_file.is_none() && !register {
        return Err(
            "warp outbound needs `identityFile`, an inline `identity`, or `register: true`"
                .to_owned(),
        );
    }
    Ok((mode, register, identity_file, inline))
}

impl WarpSpec {
    fn from(settings: &crate::json::Json) -> Result<Self, String> {
        let (mode, register, identity_file, inline) = spec_identity(settings)?;
        let api = settings
            .get("api")
            .and_then(crate::json::Json::as_str)
            .filter(|api| !api.is_empty())
            .map(str::to_owned);
        let api_address = settings
            .get("apiAddress")
            .and_then(crate::json::Json::as_str)
            .filter(|address| !address.is_empty())
            .map(str::to_owned);
        let endpoint = match settings.get("endpoint") {
            None | Some(crate::json::Json::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(parse_endpoint)
                    .ok_or_else(|| "warp: `endpoint` is not host:port".to_owned())?,
            ),
        };
        let mtu = settings
            .get("mtu")
            .and_then(crate::json::Json::as_u32)
            .and_then(|mtu| u16::try_from(mtu).ok())
            .filter(|mtu| *mtu > 0)
            .unwrap_or(DEFAULT_MTU);
        let keepalive = settings
            .get("keepAlive")
            .and_then(crate::json::Json::as_u32)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(DEFAULT_KEEPALIVE);
        let probe_host = settings
            .get("probe")
            .and_then(crate::json::Json::as_str)
            .filter(|host| !host.is_empty())
            .unwrap_or(PROBE_HOST)
            .to_owned();
        let probe_port = settings
            .get("probePort")
            .and_then(crate::json::Json::as_port)
            .unwrap_or(PROBE_PORT);
        let dns = match settings.get("dns").and_then(crate::json::Json::as_arr) {
            Some(items) => items
                .iter()
                .filter_map(crate::json::Json::as_str)
                .filter_map(|text| text.parse().ok())
                .collect(),
            None => TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
        };
        let (masque_address, masque_port, masque_server_name, masque_host, masque_path) =
            masque_settings(settings.get("masque"));
        let edge = EdgeSpec::from(settings)?;
        let noize = crate::noize::NoizeSettings::from_settings(settings)?;
        let quic_v2 = quic_v2_enabled(settings, std::env::var("AETHER_QUIC_V2").ok().as_deref());
        let gool = gool_settings(settings)?;
        let mim = if mode == Mode::Mim {
            mim_settings(settings)?
        } else {
            MimSettings::default()
        };
        Ok(Self {
            mode,
            register,
            identity_file,
            wireguard_identity_file: None,
            masque_identity_file: None,
            inline,
            api,
            api_address,
            endpoint,
            mtu,
            keepalive,
            probe_host,
            probe_port,
            dns,
            masque_address,
            masque_port,
            masque_server_name,
            masque_host,
            masque_path,
            scan: edge.scan,
            peer: edge.peer,
            wg_peer: edge.wg_peer,
            ironclad_port: edge.ironclad_port,
            quick_reconnect: edge.quick_reconnect,
            last_edge: edge.last_edge,
            stale: edge.stale,
            cooldown: edge.cooldown,
            noize,
            quic_v2,
            gool,
            mim,
        })
    }

    /// The identity a config names: inline wins, then a saved file, then a new
    /// registration saved into `identityFile`. A saved file is checked against
    /// the API; a refused one is replaced unless `AETHER_REPROVISION=0`.
    fn identity_in(&self, test: bool) -> Result<Identity, String> {
        if let Some(identity) = &self.inline {
            return Ok(identity.clone());
        }
        let Some(path) = self.identity_file.as_deref() else {
            if !self.register {
                return Err("warp outbound needs `identityFile` or an inline `identity`".to_owned());
            }
            return Err(
                "warp: `register: true` needs an `identityFile` to save the account".into(),
            );
        };
        self.identity_at_in(path, false, test)
    }

    /// The identity files this spec names, in the same shape the register command plans.
    fn key_paths(&self) -> Option<KeyPaths> {
        let base = self.identity_file.as_deref()?;
        Some(KeyPaths::new(
            base,
            self.wireguard_identity_file.as_deref(),
            self.masque_identity_file.as_deref(),
        ))
    }

    /// The path the inner `WireGuard` identity is saved to.
    fn gool_path(&self, paths: &KeyPaths) -> Result<PathBuf, String> {
        if let Some(file) = &self.gool.identity_file {
            return Ok(file.clone());
        }
        if self.identity_file.is_none() {
            return Err(
                "warp gool needs `goolIdentityFile`, an inline `goolIdentity`, or an `identityFile`"
                    .to_owned(),
            );
        }
        Ok(if self.mode == Mode::GoolClassic {
            Slot::WireGuardInner.path(paths)
        } else {
            Slot::Gool.path(paths)
        })
    }

    /// The inner `WireGuard` identity, registered beside the outer one when absent.
    fn gool_identity(&self) -> Result<Identity, String> {
        self.gool_identity_in(false)
    }

    fn gool_identity_in(&self, test: bool) -> Result<Identity, String> {
        if let Some(identity) = &self.gool.inline {
            return Ok(identity.clone());
        }
        if let Some(file) = &self.gool.identity_file {
            return self.identity_at_in(file, true, test);
        }
        let paths = self.key_paths().ok_or_else(|| {
            "warp gool needs `goolIdentityFile`, an inline `goolIdentity`, or an `identityFile`"
                .to_owned()
        })?;
        self.identity_at_in(&self.gool_path(&paths)?, true, test)
    }

    /// The path the inner MASQUE identity is saved to, the sibling Aether uses.
    fn mim_path(&self) -> Result<PathBuf, String> {
        if let Some(file) = &self.mim.identity_file {
            return Ok(file.clone());
        }
        let paths = self.key_paths().ok_or_else(|| {
            "warp mim needs `mimIdentityFile`, an inline `mimIdentity`, or an `identityFile`"
                .to_owned()
        })?;
        Ok(Slot::MasqueInner.path(&paths))
    }

    /// The inner MASQUE identity, registered beside the outer one when absent.
    fn mim_identity(&self) -> Result<Identity, String> {
        self.mim_identity_in(false)
    }

    fn mim_identity_in(&self, test: bool) -> Result<Identity, String> {
        if let Some(identity) = &self.mim.inline {
            return Ok(identity.clone());
        }
        self.identity_at_in(&self.mim_path()?, false, test)
    }

    /// A saved identity's lifecycle, shared by the outer device and gool's inner one.
    fn identity_at_in(&self, path: &Path, inner: bool, test: bool) -> Result<Identity, String> {
        let enroll = !inner && !matches!(self.mode, Mode::WireGuard | Mode::GoolClassic);
        if path.is_file() {
            let saved = match Identity::load(path) {
                Ok(saved) => saved,
                Err(error) if error.corrupt() && self.register && reprovision_enabled() => {
                    if test {
                        return Err(error.into_message());
                    }
                    let identity = register(self, enroll)?;
                    quarantine(path);
                    identity.save(path)?;
                    return Ok(identity);
                }
                Err(error) => return Err(error.into_message()),
            };
            if test {
                return Ok(saved);
            }
            return match refresh_saved(self, &saved) {
                Ok(fresh) if fresh != saved => {
                    if let Err(error) = fresh.save(path) {
                        eprintln!("warp: could not persist the refreshed identity: {error}");
                    }
                    Ok(fresh)
                }
                Ok(_) => Ok(saved),
                Err(error)
                    if should_reprovision(self.register, error.refused, reprovision_enabled()) =>
                {
                    let identity = register(self, enroll)?;
                    quarantine(path);
                    identity.save(path)?;
                    Ok(identity)
                }
                Err(error) => {
                    eprintln!("warp: keeping the saved identity: {}", error.reason);
                    Ok(saved)
                }
            };
        }
        if test {
            return Err(format!(
                "warp: the identity file `{}` does not exist",
                path.display()
            ));
        }
        if !self.register {
            return Err(format!(
                "warp: the identity file `{}` does not exist and `register` is false",
                path.display()
            ));
        }
        let identity = register(self, enroll)?;
        identity.save(path)?;
        Ok(identity)
    }

    fn api_url(&self) -> Vec<String> {
        match self.api.as_deref() {
            Some(api) => vec![api.to_owned()],
            None => API_HOSTS
                .iter()
                .map(|host| format!("https://{host}/{API_VERSION}"))
                .collect(),
        }
    }

    fn for_command(mode: Mode, api: Option<String>, api_address: Option<String>) -> Self {
        Self {
            mode,
            register: true,
            identity_file: None,
            wireguard_identity_file: None,
            masque_identity_file: None,
            inline: None,
            api,
            api_address,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
            masque_address: CONNECT_HOST.to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
            scan: None,
            peer: None,
            wg_peer: None,
            ironclad_port: IRONCLAD_PORT,
            quick_reconnect: false,
            last_edge: None,
            stale: None,
            cooldown: Duration::from_secs(COOLDOWN_SECS),
            noize: crate::noize::NoizeSettings::default(),
            quic_v2: true,
            gool: GoolSettings::default(),
            mim: MimSettings::default(),
        }
    }

    fn last_edge_path(&self) -> PathBuf {
        if let Some(path) = &self.last_edge {
            return path.clone();
        }
        let Some(identity) = &self.identity_file else {
            return PathBuf::from("warp-lastconn.json");
        };
        let name = identity.file_stem().map_or_else(
            || "warp-identity.lastconn.json".to_owned(),
            |stem| format!("{}.lastconn.json", stem.to_string_lossy()),
        );
        identity.with_file_name(name)
    }
}

fn scan_mode(text: &str) -> Option<ScanMode> {
    let text = text.trim();
    if text.is_empty()
        || ["off", "none", "false", "0"]
            .iter()
            .any(|off| text.eq_ignore_ascii_case(off))
    {
        return None;
    }
    Some(ScanMode::parse(text).unwrap_or(ScanMode::Balanced))
}

fn peer_setting(
    settings: &crate::json::Json,
    key: &str,
    environment: &str,
) -> Result<Option<SocketAddr>, String> {
    let text = settings
        .get(key)
        .and_then(crate::json::Json::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(environment)
                .ok()
                .filter(|text| !text.is_empty())
        });
    text.map(|text| parse_endpoint(&text).ok_or_else(|| format!("warp: `{key}` is not host:port")))
        .transpose()
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse().ok()
}

fn quic_v2_enabled(settings: &crate::json::Json, environment: Option<&str>) -> bool {
    settings
        .get("quicV2")
        .and_then(crate::json::Json::as_bool)
        .unwrap_or_else(|| {
            !environment.is_some_and(|value| {
                ["0", "off", "false", "no"]
                    .iter()
                    .any(|off| value.trim().eq_ignore_ascii_case(off))
            })
        })
}

fn env_bool(name: &str) -> Option<bool> {
    let text = std::env::var(name).ok()?;
    if ["1", "true", "on", "yes"]
        .iter()
        .any(|on| text.trim().eq_ignore_ascii_case(on))
    {
        Some(true)
    } else if ["0", "false", "off", "no"]
        .iter()
        .any(|off| text.trim().eq_ignore_ascii_case(off))
    {
        Some(false)
    } else {
        None
    }
}

/// One API origin, its dialled address moved by `apiAddress` while the TLS
/// name and HTTP host stay the origin's.
fn api_endpoint(spec: &WarpSpec, base: &str) -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::parse(base, crate::quic::system_roots())
        .ok_or_else(|| format!("warp: `{base}` is not an https API origin"))?
        .with_h2_fingerprint("chrome_plain")
        .without_resumption();
    if let Some(address) = &spec.api_address {
        let (host, port) = split_host_port(address, 443).ok_or_else(|| {
            format!(
                "warp: apiAddress: `{address}` is no IP address or domain name, with or without a port"
            )
        })?;
        let peer = match host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|error| format!("warp: apiAddress `{host}`: {error}"))?
                .next()
                .ok_or_else(|| format!("warp: apiAddress `{host}` resolves to nothing"))?,
        };
        endpoint.address = Some(peer);
    }
    Ok(endpoint)
}

/// An IP address, an IPv6 one with or without brackets, or a domain name,
/// optionally followed by `:port`.
fn split_host_port(text: &str, default_port: u16) -> Option<(String, u16)> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Some((address.ip().to_string(), address.port()));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some((ip.to_string(), default_port));
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(port) => port.parse().ok().map(|port| (host.to_owned(), port)),
            None if tail.is_empty() => Some((host.to_owned(), default_port)),
            None => None,
        };
    }
    if let Some((host, port)) = text.rsplit_once(':') {
        if host.is_empty() || host.contains(':') || host.parse::<IpAddr>().is_ok() {
            return None;
        }
        return port.parse().ok().map(|port| (host.to_owned(), port));
    }
    Some((text.to_owned(), default_port))
}

/// The `masque` block's five fields, each defaulting to the WARP edge the API names.
fn masque_settings(masque: Option<&crate::json::Json>) -> (String, u16, String, String, String) {
    let field = |key: &str, fallback: &str| {
        masque
            .and_then(|masque| masque.get(key))
            .and_then(crate::json::Json::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback)
            .to_owned()
    };
    let port = masque
        .and_then(|masque| masque.get("port"))
        .and_then(crate::json::Json::as_port)
        .unwrap_or(QUIC_PORT);
    (
        field("address", CONNECT_HOST),
        port,
        field("serverName", CONNECT_SNI),
        field("host", CONNECT_HOST),
        field("path", "/"),
    )
}

fn parse_endpoint(text: &str) -> Option<SocketAddr> {
    let address: SocketAddr = text.trim().parse().ok()?;
    (address.port() != 0).then_some(address)
}

/// The body `POST /reg` sends: a fresh Curve25519 key and the device shape the
/// API answers with the account's own keys and addresses.
fn registration_body(public: &[u8; 32], tos: &str, serial: &str) -> Vec<u8> {
    let pairs = vec![
        ("key", string(&b64(public))),
        ("install_id", string("")),
        ("fcm_token", string("")),
        ("tos", string(tos)),
        ("model", string("PC")),
        ("serial_number", string(serial)),
        ("os_version", string("")),
        ("key_type", string("curve25519")),
        ("tunnel_type", string("wireguard")),
        ("locale", string("en_US")),
    ];
    json_bytes(&obj_pairs(pairs))
}

/// A serial of eight random bytes in hex, the shape the API's POST reads.
fn android_serial() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the OS entropy");
    let mut serial = String::with_capacity(16);
    for byte in bytes {
        std::fmt::Write::write_fmt(&mut serial, format_args!("{byte:02x}")).expect("a hex pair");
    }
    serial
}

/// The body that enrolls the P-256 key the MASQUE half presents.
fn enrollment_body(spki: &[u8]) -> Vec<u8> {
    let pairs = vec![
        ("key", string(&b64(spki))),
        ("key_type", string("secp256r1")),
        ("tunnel_type", string("masque")),
    ];
    json_bytes(&obj_pairs(pairs))
}

const ENABLE_BODY: &[u8] = br#"{"warp_enabled":true}"#;

fn registration_headers(bearer: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Content-Type".to_owned(),
            "application/json; charset=UTF-8".to_owned(),
        ),
        ("User-Agent".to_owned(), REGISTER_AGENT.to_owned()),
        ("CF-Client-Version".to_owned(), CLIENT_VERSION.to_owned()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ];
    if let Some(token) = bearer {
        headers.push(("Authorization".to_owned(), token.to_owned()));
    }
    headers
}

/// A registration can fail before the device exists (another API host may
/// answer) or after it exists (a retry would create a second device); only a
/// refusal of the identity is worth replacing rather than retrying.
#[derive(Debug)]
struct RegisterError {
    fatal: bool,
    refused: bool,
    reason: String,
}

impl RegisterError {
    fn retryable(reason: impl Into<String>) -> Self {
        Self {
            fatal: false,
            refused: false,
            reason: reason.into(),
        }
    }

    fn fatal(reason: impl Into<String>) -> Self {
        Self {
            fatal: true,
            refused: false,
            reason: reason.into(),
        }
    }

    fn refused(reason: impl Into<String>) -> Self {
        Self {
            fatal: true,
            refused: true,
            reason: reason.into(),
        }
    }
}

/// Register against the first host that answers, then enroll and enable; a
/// refusal names the host that refused so a runner's console can act on it.
fn register(spec: &WarpSpec, enroll: bool) -> Result<Identity, String> {
    let mut last = String::new();
    for base in spec.api_url() {
        let endpoint = match api_endpoint(spec, &base) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                last = reason;
                continue;
            }
        };
        match register_with(spec, enroll, &|method, path, headers, body| {
            let url = endpoint.url(path);
            // The reference dials one fresh HTTP/2 connection per call and never retries over HTTP/1.1; a request that reached the peer is not replayed against another host.
            crate::foxy_account::h2_ask_started(&endpoint, method, &url, headers, body).map_err(
                |(reason, sent)| {
                    if sent {
                        RegisterError::fatal(reason)
                    } else {
                        RegisterError::retryable(reason)
                    }
                },
            )
        }) {
            Ok(identity) => return Ok(identity),
            Err(error) if error.fatal => {
                return Err(if last.is_empty() {
                    error.reason
                } else {
                    format!("{} (earlier: {last})", error.reason)
                });
            }
            Err(error) => last = error.reason,
        }
    }
    Err(last)
}

/// The calls, with the transport injected so a test records them and a real run
/// sends them over TLS. A device is saved only once WARP is enabled on it.
fn register_with<F>(spec: &WarpSpec, enroll: bool, call: &F) -> Result<Identity, RegisterError>
where
    F: Fn(&str, &str, &[(&str, &str)], &[u8]) -> Result<Reply, RegisterError>,
{
    let mut private = [0u8; 32];
    getrandom::fill(&mut private)
        .map_err(|error| RegisterError::retryable(format!("warp entropy: {error}")))?;
    clamp(&mut private);
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    let tos = tos_now();
    let serial = android_serial();
    let body = registration_body(&public, &tos, &serial);
    let headers = registration_headers(None);
    let headers = borrow_headers(&headers);
    let reply = call("POST", "/reg", &headers, &body)?;
    // A 2xx is not posted again, even when its body is unreadable: another host would mint a second device.
    let registered = parse_registration(&reply).map_err(|error| {
        if (200..300).contains(&reply.status) {
            RegisterError::fatal(error.reason)
        } else {
            error
        }
    })?;
    let bearer = format!("Bearer {}", registered.token);
    let path = format!("/reg/{}", registered.device_id);
    let discard = || {
        let headers = registration_headers(Some(&bearer));
        let headers = borrow_headers(&headers);
        if let Err(reason) = cleanup_reply(call("DELETE", &path, &headers, &[])) {
            eprintln!("warp: could not delete the failed device registration: {reason}");
        }
    };
    let mut masque = None;

    if enroll {
        let key = rcgen::KeyPair::generate()
            .map_err(|error| RegisterError::fatal(format!("warp MASQUE key: {error}")))?;
        let spki = decode_pem(&key.public_key_pem())
            .ok_or_else(|| RegisterError::fatal("warp MASQUE key: no public key"))?;
        let headers = registration_headers(Some(&bearer));
        let headers = borrow_headers(&headers);
        let reply = match call("PATCH", &path, &headers, &enrollment_body(&spki)) {
            Ok(reply) => reply,
            Err(error) => {
                discard();
                return Err(RegisterError::fatal(format!(
                    "the WARP key enrollment failed: {}",
                    error.reason
                )));
            }
        };
        let server = match parse_masque_server(&reply) {
            Ok(server) => server,
            Err(error) => {
                discard();
                return Err(error);
            }
        };
        masque = Some(MasqueIdentity {
            private: key.serialize_der(),
            server,
            addresses: registered.addresses.clone(),
        });
    }

    let headers = registration_headers(Some(&bearer));
    let headers = borrow_headers(&headers);
    match call("PATCH", &path, &headers, ENABLE_BODY) {
        Err(error) => {
            discard();
            return Err(RegisterError::fatal(format!(
                "the WARP enable failed: {}",
                error.reason
            )));
        }
        Ok(reply) if reply.status / 100 != 2 => {
            discard();
            return Err(RegisterError::fatal(format!(
                "the WARP enable answered {}: {}",
                reply.status,
                reply_snippet(&reply.body)
            )));
        }
        Ok(_) => {}
    }

    Ok(Identity {
        device_id: registered.device_id,
        token: registered.token,
        wireguard: WireGuardIdentity {
            private,
            peer: registered.peer,
            endpoint: spec.endpoint.unwrap_or(registered.endpoint),
            addresses: registered.addresses,
            reserved: registered.reserved,
        },
        masque,
    })
}

fn cleanup_reply(reply: Result<Reply, RegisterError>) -> Result<(), String> {
    match reply {
        Ok(reply) if (200..300).contains(&reply.status) => Ok(()),
        Ok(reply) => Err(reply.status.to_string()),
        Err(error) => Err(error.reason),
    }
}

/// Read a device back from the API, so an identity Cloudflare no longer knows
/// is replaced instead of handshaking into nothing.
fn refresh<F>(spec: &WarpSpec, identity: &Identity, call: &F) -> Result<Identity, RegisterError>
where
    F: Fn(&str, &str, &[(&str, &str)], &[u8]) -> Result<Reply, RegisterError>,
{
    let path = format!("/reg/{}", identity.device_id);
    let bearer = format!("Bearer {}", identity.token);
    let headers = registration_headers(Some(&bearer));
    let headers = borrow_headers(&headers);
    let reply = call("GET", &path, &headers, b"")?;
    if refuses_identity(&reply) {
        return Err(RegisterError::refused(format!(
            "the API answered the saved identity with {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::retryable(format!(
            "the API answered the saved identity with {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = reply_root(&reply)?;
    let config = parse_config(&root)?;
    let mut fresh = identity.clone();
    fresh.wireguard.peer = config.peer;
    fresh.wireguard.endpoint = spec.endpoint.unwrap_or(config.endpoint);
    fresh.wireguard.reserved = config.reserved;
    if !config.addresses.is_empty() {
        fresh.wireguard.addresses.clone_from(&config.addresses);
        if let Some(masque) = &mut fresh.masque {
            masque.addresses = config.addresses;
        }
    }
    Ok(fresh)
}

fn refuses_identity(reply: &Reply) -> bool {
    matches!(reply.status, 401 | 410) || (reply.status == 404 && is_api_envelope(&reply.body))
}

/// Cloudflare's JSON error envelope, rather than a page of another server that
/// fronts the name: a 404 page says nothing about the identity.
fn is_api_envelope(body: &[u8]) -> bool {
    crate::json::parse(&String::from_utf8_lossy(body)).is_ok_and(|root| {
        matches!(root.get("success"), Some(crate::json::Json::Bool(false)))
            && matches!(root.get("errors"), Some(crate::json::Json::Arr(errors)) if !errors.is_empty())
    })
}

/// The API's own answers only: an error page of another server is not a refusal
/// of the identity.
fn reply_root(reply: &Reply) -> Result<crate::json::Json, RegisterError> {
    crate::json::parse(&String::from_utf8_lossy(&reply.body))
        .map_err(|_| RegisterError::retryable("the WARP reply is not JSON"))
}

fn refresh_saved(spec: &WarpSpec, identity: &Identity) -> Result<Identity, RegisterError> {
    let mut last = String::new();
    for base in spec.api_url() {
        let endpoint = match api_endpoint(spec, &base) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                last = reason;
                continue;
            }
        };
        match refresh(spec, identity, &|method, path, headers, body| {
            let url = endpoint.url(path);
            crate::foxy_account::h2_ask(&endpoint, method, &url, headers, body)
                .map_err(RegisterError::retryable)
        }) {
            Ok(fresh) => return Ok(fresh),
            Err(error) if error.fatal => return Err(error),
            Err(error) => last = error.reason,
        }
    }
    Err(RegisterError::retryable(last))
}

fn reprovision_enabled() -> bool {
    reprovision_enabled_for(std::env::var("AETHER_REPROVISION").ok().as_deref())
}

fn reprovision_enabled_for(value: Option<&str>) -> bool {
    !value.is_some_and(|value| {
        ["0", "off", "false"]
            .iter()
            .any(|off| value.trim().eq_ignore_ascii_case(off))
    })
}

fn should_reprovision(register: bool, refused: bool, enabled: bool) -> bool {
    register && refused && enabled
}

fn quarantine(path: &Path) {
    let mut target = path.to_path_buf();
    let name = target.file_name().map_or_else(
        || "warp-identity.json".to_owned(),
        |name| name.to_string_lossy().to_string(),
    );
    let mut ordinal = 0;
    loop {
        target.set_file_name(if ordinal == 0 {
            format!("{name}.corrupt")
        } else {
            format!("{name}.corrupt.{ordinal}")
        });
        if !target.exists() {
            break;
        }
        ordinal += 1;
    }
    if let Err(error) = std::fs::rename(path, &target) {
        eprintln!(
            "warp: the damaged identity at {} could not be moved aside: {error}",
            path.display()
        );
    }
}

fn borrow_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

#[derive(Debug)]
struct Registered {
    device_id: String,
    token: String,
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

fn parse_registration(reply: &Reply) -> Result<Registered, RegisterError> {
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::retryable(format!(
            "the WARP service answered {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = reply_root(reply)?;
    let config = parse_config(&root)?;
    let device_id = root
        .get("id")
        .and_then(crate::json::Json::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no device id"))?
        .to_owned();
    let token = root
        .get("token")
        .and_then(crate::json::Json::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no token"))?
        .to_owned();
    Ok(Registered {
        device_id,
        token,
        peer: config.peer,
        endpoint: config.endpoint,
        addresses: config.addresses,
        reserved: config.reserved,
    })
}

/// The `config` object both a registration and a read-back carry.
fn parse_config(root: &crate::json::Json) -> Result<DeviceConfig, RegisterError> {
    let config = root
        .get("config")
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no `config`"))?;
    let peer = config
        .get("peers")
        .and_then(crate::json::Json::as_arr)
        .and_then(|peers| peers.first())
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no peer"))?;
    let peer_key = peer
        .get("public_key")
        .and_then(crate::json::Json::as_str)
        .and_then(decode_key)
        .ok_or_else(|| RegisterError::retryable("the WARP reply's peer key is not 32 bytes"))?;
    let reserved = config
        .get("client_id")
        .and_then(crate::json::Json::as_str)
        .and_then(decode_bytes)
        .and_then(|bytes| <[u8; 3]>::try_from(bytes.as_slice()).ok())
        .unwrap_or([0u8; 3]);
    let endpoint = peer
        .get("endpoint")
        .ok_or_else(|| RegisterError::retryable("the WARP reply has no endpoint"))?;
    let v4 = endpoint
        .get("v4")
        .and_then(crate::json::Json::as_str)
        .unwrap_or_default();
    let host = v4.rsplit_once(':').map_or(v4, |(host, _)| host);
    let ip = host
        .parse()
        .or_else(|_| {
            endpoint
                .get("host")
                .and_then(crate::json::Json::as_str)
                .unwrap_or_default()
                .parse()
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(162, 159, 192, 1)));
    let ports: Vec<u16> = endpoint
        .get("ports")
        .and_then(crate::json::Json::as_arr)
        .map(|ports| {
            ports
                .iter()
                .filter_map(crate::json::Json::as_u32)
                .filter_map(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .collect()
        })
        .unwrap_or_default();
    let port = if ports.is_empty() || ports.contains(&WIREGUARD_PORT) {
        WIREGUARD_PORT
    } else {
        ports[0]
    };
    Ok(DeviceConfig {
        peer: peer_key,
        endpoint: SocketAddr::new(ip, port),
        addresses: reply_addresses(config),
        reserved,
    })
}

struct DeviceConfig {
    peer: [u8; 32],
    endpoint: SocketAddr,
    addresses: Vec<IpAddr>,
    reserved: [u8; 3],
}

fn reply_addresses(config: &crate::json::Json) -> Vec<IpAddr> {
    let interface = config
        .get("interface")
        .and_then(|value| value.get("addresses"));
    ["v4", "v6"]
        .iter()
        .filter_map(|family| {
            interface?
                .get(family)
                .and_then(crate::json::Json::as_str)
                .and_then(|text| text.trim().split('/').next())
                .and_then(|text| text.parse().ok())
        })
        .collect()
}

fn parse_masque_server(reply: &Reply) -> Result<Vec<u8>, RegisterError> {
    if !(200..300).contains(&reply.status) {
        return Err(RegisterError::fatal(format!(
            "the WARP key enrollment answered {}: {}",
            reply.status,
            reply_snippet(&reply.body)
        )));
    }
    let root = crate::json::parse(&String::from_utf8_lossy(&reply.body))
        .map_err(|_| RegisterError::fatal("the WARP enrollment reply is not JSON"))?;
    let key = root
        .get("config")
        .and_then(|config| config.get("peers"))
        .and_then(crate::json::Json::as_arr)
        .and_then(|peers| peers.first())
        .and_then(|peer| peer.get("public_key"))
        .and_then(crate::json::Json::as_str)
        .ok_or_else(|| RegisterError::fatal("the WARP enrollment reply has no server key"))?;
    let der = if key.contains("-----BEGIN") {
        decode_pem(key)
    } else {
        decode_bytes(key)
    }
    .ok_or_else(|| RegisterError::fatal("the WARP enrollment server key is not base64 or PEM"))?;
    if !is_p256_spki(&der) {
        return Err(RegisterError::fatal(
            "the WARP enrollment reply's key is not a P-256 SPKI",
        ));
    }
    Ok(der)
}

/// The reply's head, one line, for a runner's console: a WARP refusal that only
/// names a status cannot be acted on.
fn reply_snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(&body[..body.len().min(160)]);
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.is_empty() {
        "empty".to_owned()
    } else {
        line
    }
}

/// The P-256 algorithm identifier inside a `SubjectPublicKeyInfo`.
fn is_p256_spki(der: &[u8]) -> bool {
    const P256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    der.windows(P256.len()).any(|window| window == P256)
}

/// A save the service cannot read back is not a corrupt identity: only a failed
/// parse or field check may be replaced.
#[derive(Debug)]
enum LoadError {
    Read(String),
    Corrupt(String),
}

impl LoadError {
    fn corrupt(&self) -> bool {
        matches!(self, Self::Corrupt(_))
    }

    fn into_message(self) -> String {
        match self {
            Self::Read(message) | Self::Corrupt(message) => message,
        }
    }
}

impl Identity {
    fn from_json(value: &crate::json::Json) -> Result<Self, String> {
        let device_id = value
            .get("deviceId")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_default()
            .to_owned();
        let token = value
            .get("token")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_default()
            .to_owned();
        let wireguard = value
            .get("wireguard")
            .ok_or("warp identity has no `wireguard`")?;
        let private = wireguard
            .get("privateKey")
            .and_then(crate::json::Json::as_str)
            .and_then(decode_key)
            .ok_or("warp identity's wireguard `privateKey` is not 32 bytes")?;
        let peer = wireguard
            .get("publicKey")
            .and_then(crate::json::Json::as_str)
            .and_then(decode_key)
            .ok_or("warp identity's wireguard `publicKey` is not 32 bytes")?;
        let endpoint = wireguard
            .get("endpoint")
            .and_then(crate::json::Json::as_str)
            .and_then(parse_endpoint)
            .ok_or("warp identity's wireguard `endpoint` is not host:port")?;
        let addresses = json_addresses(wireguard.get("address"));
        if addresses.is_empty() {
            return Err("warp identity's wireguard `address` is empty".to_owned());
        }
        let reserved = wireguard
            .get("reserved")
            .and_then(crate::json::Json::as_arr)
            .and_then(|items| {
                if items.len() != 3 {
                    return None;
                }
                let mut reserved = [0u8; 3];
                for (slot, item) in reserved.iter_mut().zip(items) {
                    *slot = u8::try_from(item.as_u32()?).ok()?;
                }
                Some(reserved)
            })
            .unwrap_or([0u8; 3]);
        let masque = value.get("masque").map(|masque| {
            let private = masque
                .get("privateKey")
                .and_then(crate::json::Json::as_str)
                .and_then(decode_bytes)
                .ok_or("warp identity's masque `privateKey` is not base64")?;
            let server = masque
                .get("publicKey")
                .and_then(crate::json::Json::as_str)
                .and_then(decode_bytes)
                .ok_or("warp identity's masque `publicKey` is not base64")?;
            let mut addresses = json_addresses(masque.get("address"));
            if addresses.is_empty() {
                addresses.clone_from(&wireguard_addresses(value));
            }
            Ok::<_, String>(MasqueIdentity {
                private,
                server,
                addresses,
            })
        });
        let masque = masque.transpose()?;
        Ok(Self {
            device_id,
            token,
            wireguard: WireGuardIdentity {
                private,
                peer,
                endpoint,
                addresses,
                reserved,
            },
            masque,
        })
    }

    fn to_json(&self) -> crate::json::Json {
        let wireguard = obj_pairs(vec![
            ("privateKey", string(&b64(&self.wireguard.private))),
            ("publicKey", string(&b64(&self.wireguard.peer))),
            ("endpoint", string(&self.wireguard.endpoint.to_string())),
            ("address", address_json(&self.wireguard.addresses)),
            (
                "reserved",
                crate::json::Json::Arr(
                    self.wireguard
                        .reserved
                        .iter()
                        .map(|byte| crate::json::Json::Num(f64::from(*byte)))
                        .collect(),
                ),
            ),
        ]);
        let mut pairs = vec![
            ("deviceId", string(&self.device_id)),
            ("token", string(&self.token)),
            ("wireguard", wireguard),
        ];
        if let Some(masque) = &self.masque {
            pairs.push((
                "masque",
                obj_pairs(vec![
                    ("privateKey", string(&b64(&masque.private))),
                    ("publicKey", string(&b64(&masque.server))),
                    ("address", address_json(&masque.addresses)),
                ]),
            ));
        }
        obj_pairs(pairs)
    }

    fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            LoadError::Read(format!("warp: cannot read `{}`: {error}", path.display()))
        })?;
        let value = crate::json::parse(&text).map_err(|error| {
            LoadError::Corrupt(format!("warp: `{}` is not JSON: {error}", path.display()))
        })?;
        Self::from_json(&value)
            .map_err(|error| LoadError::Corrupt(format!("warp: `{}`: {error}", path.display())))
    }

    /// Write beside the target and rename over it, so a reader never sees half
    /// an identity and a failure leaves the old keys in place; the temporary is
    /// 0600 on Unix, and on Windows it inherits the directory ACL.
    fn save(&self, path: &Path) -> Result<(), String> {
        let mut text = String::new();
        crate::json::write(&self.to_json(), &mut text);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("warp: cannot create `{}`: {error}", parent.display()))?;
        }
        let mut temp = path.to_path_buf();
        let name = temp.file_name().map_or_else(
            || "warp-identity.json".to_owned(),
            |name| name.to_string_lossy().to_string(),
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        temp.set_file_name(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
        let mut created = false;
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|error| format!("warp: cannot write `{}`: {error}", temp.display()))?;
            created = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| format!("warp: cannot lock `{}`: {error}", temp.display()))?;
            }
            file.write_all(text.as_bytes())
                .map_err(|error| format!("warp: cannot write `{}`: {error}", temp.display()))?;
            file.sync_all()
                .map_err(|error| format!("warp: cannot sync `{}`: {error}", temp.display()))?;
            drop(file);
            std::fs::rename(&temp, path)
                .map_err(|error| format!("warp: cannot save `{}`: {error}", path.display()))?;
            #[cfg(unix)]
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                if let Ok(parent) = std::fs::File::open(parent) {
                    let _ = parent.sync_all();
                }
            }
            Ok(())
        })();
        if result.is_err() && created {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

fn wireguard_addresses(value: &crate::json::Json) -> Vec<IpAddr> {
    value
        .get("wireguard")
        .map(|wireguard| json_addresses(wireguard.get("address")))
        .unwrap_or_default()
}

fn json_addresses(value: Option<&crate::json::Json>) -> Vec<IpAddr> {
    value
        .and_then(crate::json::Json::as_arr)
        .map(|items| {
            items
                .iter()
                .filter_map(crate::json::Json::as_str)
                .filter_map(|text| text.trim().split('/').next())
                .filter_map(|text| text.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn address_json(addresses: &[IpAddr]) -> crate::json::Json {
    crate::json::Json::Arr(
        addresses
            .iter()
            .map(|address| string(&address.to_string()))
            .collect(),
    )
}

#[allow(clippy::too_many_lines)]
fn resolve_edges(identity: &mut Identity, spec: &mut WarpSpec) -> Result<(), String> {
    let mut wireguard = spec.wg_peer.or(spec.endpoint);
    let mut masque = if spec.mode == Mode::Mim {
        spec.mim.outer.or(spec.peer)
    } else {
        spec.peer
    };
    if let Some(edge) = wireguard {
        identity.wireguard.endpoint = edge;
        println!("[+] using forced peer {edge} (probe skipped)");
    }
    if let Some(edge) = masque {
        set_masque_edge(spec, edge);
        println!("[+] using forced peer {edge} (probe skipped)");
    }
    let want_wireguard = matches!(spec.mode, Mode::Auto | Mode::WireGuard);
    let want_masque = spec.mode != Mode::WireGuard && identity.masque.is_some();
    let cache_path = spec.last_edge_path();
    let mut last = LastEdge::load(&cache_path);
    let mut cooldowns = Cooldowns::new(spec.cooldown);
    let mut scan = spec.scan;
    let now = Instant::now();
    if spec.quick_reconnect {
        if wireguard.is_none() && want_wireguard {
            if let Some((edge, profile)) = last.get("wireguard") {
                let mut cached = spec.clone();
                if let Some(profile) = profile {
                    cached.noize.select_wireguard(profile);
                }
                if check_wireguard(identity, &cached, edge) {
                    if let Some(profile) = profile {
                        spec.noize.select_wireguard(profile);
                    }
                    wireguard = Some(edge);
                    println!("[+] selected WireGuard endpoint {edge}");
                } else {
                    cooldowns.hold(edge, now);
                    scan.get_or_insert(ScanMode::Balanced);
                    eprintln!("[-] last WireGuard edge {edge} did not answer; scanning");
                }
            }
        }
        if masque.is_none() && want_masque {
            if let Some((edge, _)) = last.get("masque") {
                if check_masque(identity, spec, edge) {
                    masque = Some(edge);
                    println!("[+] selected MASQUE gateway {edge}");
                } else {
                    cooldowns.hold(edge, now);
                    scan.get_or_insert(ScanMode::Balanced);
                    eprintln!("[-] last MASQUE edge {edge} did not answer; scanning");
                }
            }
        }
    }
    cooldowns.purge(now);
    let excluded = cooldowns.excluded(now);
    if let Some(mode) = scan {
        eprintln!("warp: scanning edges in {} mode", mode.label());
        let timeout = spec.stale.map_or_else(
            || warp_scan::scan_timeout(mode),
            |stale| stale.min(warp_scan::scan_timeout(mode)),
        );
        let (found_wireguard, found_masque) = std::thread::scope(|scope| {
            let wireguard = (wireguard.is_none() && want_wireguard).then(|| {
                let identity = identity.clone();
                let spec = spec.clone();
                let excluded = excluded.clone();
                scope.spawn(move || scan_wireguard(&identity, &spec, mode, timeout, &excluded))
            });
            let masque = (masque.is_none() && want_masque).then(|| {
                let identity = identity.clone();
                let spec = spec.clone();
                let excluded = excluded.clone();
                scope.spawn(move || scan_masque(&identity, &spec, mode, &excluded))
            });
            (
                wireguard.and_then(|handle| handle.join().ok().flatten()),
                masque.and_then(|handle| handle.join().ok().flatten()),
            )
        });
        if let Some((edge, profile)) = found_wireguard {
            wireguard = Some(edge);
            spec.noize.select_wireguard(&profile);
            println!("[+] selected WireGuard endpoint {edge}");
        }
        if let Some(edge) = found_masque {
            masque = Some(edge);
            println!("[+] selected MASQUE gateway {edge}");
        }
        if want_wireguard && wireguard.is_none() && spec.mode == Mode::WireGuard {
            return Err("warp: the WireGuard sweep found no edge that carries traffic".to_owned());
        }
        if want_masque && masque.is_none() && spec.mode == Mode::Masque {
            return Err("warp: the MASQUE sweep found no edge that carries traffic".to_owned());
        }
        if want_wireguard && wireguard.is_none() {
            eprintln!("warp: the WireGuard sweep found no edge; keeping the API endpoint");
        }
        if want_masque && masque.is_none() {
            eprintln!("warp: the MASQUE sweep found no edge; keeping the API edge");
        }
    }
    if let Some(edge) = wireguard {
        identity.wireguard.endpoint = edge;
    }
    if let Some(edge) = masque {
        set_masque_edge(spec, edge);
    }
    if (spec.scan.is_some() || spec.quick_reconnect) && (wireguard.is_some() || masque.is_some()) {
        if let Some(edge) = wireguard {
            last.record("wireguard", edge, Some(spec.noize.wireguard_name()));
        }
        if let Some(edge) = masque {
            last.record("masque", edge, None);
        }
        if let Err(error) = last.save(&cache_path) {
            eprintln!("{error}");
        }
    }
    Ok(())
}

/// Place the two `WireGuard` hops on distinct edges, scanning each with the key
/// that must own it so a verified edge carries the hop it was found for.
fn resolve_classic_edges(
    outer: &mut Identity,
    inner: &mut Identity,
    spec: &mut WarpSpec,
) -> Result<(), String> {
    let mut outer_edge = spec.gool.wiw_outer.or(spec.wg_peer).or(spec.endpoint);
    let mut inner_edge = spec.gool.wiw_inner.or(spec.gool.peer);
    if let Some(edge) = outer_edge {
        println!("[+] using forced outer peer {edge} (probe skipped)");
    }
    if let Some(edge) = inner_edge {
        println!("[+] using forced inner peer {edge} (probe skipped)");
    }
    let cache_path = spec.last_edge_path();
    let mut last = LastEdge::load(&cache_path);
    let mut cooldowns = Cooldowns::new(spec.cooldown);
    let mut scan = spec.scan;
    let now = Instant::now();
    if spec.quick_reconnect {
        if outer_edge.is_none() {
            if let Some((edge, _)) = last.get("classic-outer") {
                if check_wireguard(outer, spec, edge) {
                    outer_edge = Some(edge);
                    println!("[+] selected outer WireGuard endpoint {edge}");
                } else {
                    cooldowns.hold(edge, now);
                    scan.get_or_insert(ScanMode::Balanced);
                    eprintln!("[-] last outer WireGuard edge {edge} did not answer; scanning");
                }
            }
        }
        if inner_edge.is_none() {
            if let Some((edge, _)) = last.get("classic-inner") {
                if check_wireguard(inner, spec, edge) {
                    inner_edge = Some(edge);
                    println!("[+] selected inner WireGuard endpoint {edge}");
                } else {
                    cooldowns.hold(edge, now);
                    scan.get_or_insert(ScanMode::Balanced);
                    eprintln!("[-] last inner WireGuard edge {edge} did not answer; scanning");
                }
            }
        }
    }
    cooldowns.purge(now);
    let excluded = cooldowns.excluded(now);
    if let Some(mode) = scan {
        eprintln!("warp: scanning edges in {} mode", mode.label());
        let timeout = spec.stale.map_or_else(
            || warp_scan::scan_timeout(mode),
            |stale| stale.min(warp_scan::scan_timeout(mode)),
        );
        if outer_edge.is_none() {
            let avoid: HashSet<IpAddr> = inner_edge.map(|edge| edge.ip()).into_iter().collect();
            outer_edge = scan_wireguard_edges(outer, spec, mode, timeout, &excluded, &avoid, 16)
                .into_iter()
                .next();
            if let Some(edge) = outer_edge {
                println!("[+] selected outer WireGuard endpoint {edge}");
            }
        }
        if inner_edge.is_none() {
            let outer_ip = outer_edge.unwrap_or(outer.wireguard.endpoint).ip();
            let avoid = HashSet::from([outer_ip]);
            inner_edge = scan_wireguard_edges(inner, spec, mode, timeout, &excluded, &avoid, 16)
                .into_iter()
                .next();
            if let Some(edge) = inner_edge {
                println!("[+] selected inner WireGuard endpoint {edge}");
            }
        }
        if outer_edge.is_none() {
            eprintln!("warp: the outer WireGuard sweep found no edge; keeping the API endpoint");
        }
        if inner_edge.is_none() {
            eprintln!("warp: the inner WireGuard sweep found no edge; keeping the API endpoint");
        }
    }
    let outer_edge = outer_edge.unwrap_or(outer.wireguard.endpoint);
    let inner_edge = inner_edge.unwrap_or(inner.wireguard.endpoint);
    if outer_edge.ip() == inner_edge.ip() {
        return Err(format!(
            "warp gool-classic: the outer edge {outer_edge} and inner edge {inner_edge} share an address; name distinct `wiwOuter`/`wiwInner` peers or enable `scan`"
        ));
    }
    outer.wireguard.endpoint = outer_edge;
    inner.wireguard.endpoint = inner_edge;
    if spec.scan.is_some() || spec.quick_reconnect {
        last.record("classic-outer", outer_edge, None);
        last.record("classic-inner", inner_edge, None);
        if let Err(error) = last.save(&cache_path) {
            eprintln!("{error}");
        }
    }
    Ok(())
}

fn set_masque_edge(spec: &mut WarpSpec, edge: SocketAddr) {
    spec.masque_address = edge.ip().to_string();
    spec.masque_port = edge.port();
}

fn scan_wireguard(
    identity: &Identity,
    spec: &WarpSpec,
    mode: ScanMode,
    timeout: Duration,
    excluded: &HashSet<SocketAddr>,
) -> Option<(SocketAddr, String)> {
    let candidates = spec.noize.wireguard_candidates();
    let many = candidates.len() > 1;
    for profile in candidates {
        let mut candidate = spec.clone();
        candidate.noize.select_wireguard(&profile);
        if let Some(edge) = scan_wireguard_edges(
            identity,
            &candidate,
            mode,
            timeout,
            excluded,
            &HashSet::new(),
            1,
        )
        .into_iter()
        .next()
        {
            return Some((edge, profile));
        }
        if many {
            eprintln!("[-] WireGuard profile `{profile}` found no edge; trying the next");
        }
    }
    None
}

fn scan_wireguard_edges(
    identity: &Identity,
    spec: &WarpSpec,
    mode: ScanMode,
    timeout: Duration,
    excluded: &HashSet<SocketAddr>,
    avoid: &HashSet<IpAddr>,
    limit: usize,
) -> Vec<SocketAddr> {
    let ironclad = mode == ScanMode::Ironclad;
    let candidates = warp_scan::wg_candidates(mode)
        .into_iter()
        .filter(|edge| !avoid.contains(&edge.ip()))
        .collect();
    let noise = spec.noize.wireguard();
    warp_scan::hunt(candidates, mode, excluded, |edge| {
        let local = identity
            .wireguard
            .addresses
            .iter()
            .find_map(|address| match address {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            })?;
        let rtt = crate::wg::verify_endpoint(
            identity.wireguard.private,
            identity.wireguard.peer,
            identity.wireguard.reserved,
            local,
            edge,
            timeout,
            noise,
        )?;
        if ironclad && !http_check_wireguard(identity, spec, edge) {
            eprintln!("[-] edge {edge} opened a tunnel but carried no HTTP answer");
            return None;
        }
        Some(rtt)
    })
    .into_iter()
    .take(limit)
    .map(|(edge, _)| edge)
    .collect()
}

fn scan_masque(
    identity: &Identity,
    spec: &WarpSpec,
    mode: ScanMode,
    excluded: &HashSet<SocketAddr>,
) -> Option<SocketAddr> {
    let ironclad = mode == ScanMode::Ironclad;
    warp_scan::masque_hunt(mode, excluded, |edge| {
        let mut edge_spec = spec.clone();
        set_masque_edge(&mut edge_spec, edge);
        let out = build_masque(identity, &edge_spec).ok()?;
        let started = Instant::now();
        if !out.probe(PROBE_HOST, PROBE_PORT) {
            return None;
        }
        if ironclad && !http_check_masque(identity, spec, edge) {
            eprintln!("[-] gateway {edge} opened a tunnel but carried no HTTP answer");
            return None;
        }
        Some(started.elapsed())
    })
    .first()
    .map(|(edge, _)| *edge)
}

fn wireguard_answers(identity: &Identity, spec: &WarpSpec, edge: SocketAddr) -> bool {
    let timeout = spec.stale.map_or_else(
        || warp_scan::scan_timeout(ScanMode::Balanced),
        |stale| stale.min(warp_scan::scan_timeout(ScanMode::Balanced)),
    );
    let Some(local) = identity
        .wireguard
        .addresses
        .iter()
        .find_map(|address| match address {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        })
    else {
        return false;
    };
    crate::wg::verify_endpoint(
        identity.wireguard.private,
        identity.wireguard.peer,
        identity.wireguard.reserved,
        local,
        edge,
        timeout,
        spec.noize.wireguard(),
    )
    .is_some()
}

fn check_wireguard(identity: &Identity, spec: &WarpSpec, edge: SocketAddr) -> bool {
    wireguard_answers(identity, spec, edge)
        && (spec.scan != Some(ScanMode::Ironclad) || http_check_wireguard(identity, spec, edge))
}

fn check_masque(identity: &Identity, spec: &WarpSpec, edge: SocketAddr) -> bool {
    let mut edge_spec = spec.clone();
    set_masque_edge(&mut edge_spec, edge);
    let answered =
        build_masque(identity, &edge_spec).is_ok_and(|out| out.probe(PROBE_HOST, PROBE_PORT));
    answered && (spec.scan != Some(ScanMode::Ironclad) || http_check_masque(identity, spec, edge))
}

fn http_check_wireguard(identity: &Identity, spec: &WarpSpec, edge: SocketAddr) -> bool {
    let mut identity = identity.clone();
    identity.wireguard.endpoint = edge;
    let Ok(out) = build_wireguard(&identity, spec) else {
        return false;
    };
    http_check(
        |client, asked| out.serve_tcp(client, asked, b""),
        spec.ironclad_port,
    )
}

fn http_check_masque(identity: &Identity, spec: &WarpSpec, edge: SocketAddr) -> bool {
    let mut edge_spec = spec.clone();
    set_masque_edge(&mut edge_spec, edge);
    let Ok(out) = build_masque(identity, &edge_spec) else {
        return false;
    };
    http_check(
        |client, asked| out.serve_tcp(client, asked, b""),
        edge_spec.ironclad_port,
    )
}

fn http_check(
    serve: impl FnOnce(crate::conn::Connection, &crate::proxy::Destination),
    port: u16,
) -> bool {
    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let Ok(address) = listener.local_addr() else {
        return false;
    };
    let Ok(mut client) = TcpStream::connect(address) else {
        return false;
    };
    let Ok((tunnel, _)) = listener.accept() else {
        return false;
    };
    let _ = client.set_read_timeout(Some(HTTP_PROBE_TIMEOUT));
    let _ = client.set_write_timeout(Some(HTTP_PROBE_TIMEOUT));
    serve(
        crate::conn::Connection::from(tunnel),
        &crate::proxy::Destination::Name(HTTP_PROBE_HOST.to_owned(), port),
    );
    let request = format!(
        "GET {HTTP_PROBE_PATH} HTTP/1.1\r\nHost: {HTTP_PROBE_HOST}\r\nConnection: close\r\nUser-Agent: ferrox-ironclad\r\n\r\n"
    );
    if client.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    let mut buffer = [0u8; 128];
    loop {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.windows(2).any(|window| window == b"\r\n") || response.len() >= 128 {
                    break;
                }
            }
        }
    }
    let line = response.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    http_status_code(&String::from_utf8_lossy(line)) == Some(204)
}

fn http_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.trim().parse().ok()
}

/// The `WireGuard` half as the existing `wireguard` outbound reads it.
fn wireguard_settings(identity: &Identity, spec: &WarpSpec) -> crate::json::Json {
    let wireguard = &identity.wireguard;
    let peer = obj_pairs(vec![
        ("publicKey", string(&b64(&wireguard.peer))),
        ("endpoint", string(&wireguard.endpoint.to_string())),
        (
            "allowedIPs",
            crate::json::Json::Arr(vec![string("0.0.0.0/0"), string("::/0")]),
        ),
        (
            "keepAlive",
            crate::json::Json::Num(f64::from(spec.keepalive)),
        ),
    ]);
    obj_pairs(vec![
        ("secretKey", string(&b64(&wireguard.private))),
        ("address", address_json(&wireguard.addresses)),
        ("peers", crate::json::Json::Arr(vec![peer])),
        ("reserved", reserved_json(wireguard.reserved)),
        ("isClient", crate::json::Json::Bool(true)),
        ("mtu", crate::json::Json::Num(f64::from(spec.mtu))),
        ("noKernelTun", crate::json::Json::Bool(true)),
        ("remoteDNS", address_json(&spec.dns)),
    ])
}

/// The inner hop's settings with its peer moved to the forwarder and its MTU
/// bounded by what the outer carrier can hold after this hop's own header.
fn wireguard_settings_with_endpoint(
    identity: &Identity,
    spec: &WarpSpec,
    endpoint: SocketAddr,
    mtu: u16,
) -> crate::json::Json {
    let mut settings = wireguard_settings(identity, spec);
    let crate::json::Json::Obj(pairs) = &mut settings else {
        return settings;
    };
    let Some((_, crate::json::Json::Arr(peers))) = pairs.iter_mut().find(|(key, _)| key == "peers")
    else {
        return settings;
    };
    let Some(crate::json::Json::Obj(peer)) = peers.first_mut() else {
        return settings;
    };
    let Some((_, slot)) = peer.iter_mut().find(|(key, _)| key == "endpoint") else {
        return settings;
    };
    *slot = string(&endpoint.to_string());
    if let Some((_, slot)) = pairs.iter_mut().find(|(key, _)| key == "mtu") {
        *slot = crate::json::Json::Num(f64::from(mtu));
    }
    settings
}

/// The inner hop's MTU once the outer `WireGuard` header and the outer IPv4
/// or IPv6 UDP packet are subtracted from the outer MTU.
fn classic_inner_mtu(outer_mtu: u16, remote: SocketAddr) -> Result<u16, String> {
    let carrier = if remote.is_ipv4() { 28 } else { 48 };
    let overhead = u16::try_from(WG_HEADER_SIZE + WG_TAG_SIZE + carrier)
        .map_err(|_| "warp gool-classic: the nested overhead does not fit a u16".to_owned())?;
    outer_mtu
        .checked_sub(overhead)
        .filter(|mtu| *mtu > 0)
        .map(|mtu| mtu.min(GOOL_INNER_MTU))
        .ok_or_else(|| {
            format!(
                "warp gool-classic: outer MTU {outer_mtu} leaves no room for the inner hop's {overhead}-byte overhead"
            )
        })
}

/// The MASQUE half as the existing `masque` outbound reads it: the enrolled
/// key pair, the edge's pinned key, and the WARP host and SNI.
fn masque_outbound(identity: &Identity, spec: &WarpSpec) -> Result<crate::json::Json, String> {
    let masque = identity
        .masque
        .as_ref()
        .ok_or("warp: this identity has no MASQUE key")?;
    let warp = obj_pairs(vec![
        ("privateKey", string(&b64(&masque.private))),
        ("publicKey", string(&b64(&masque.server))),
        ("address", address_json(&masque.addresses)),
    ]);
    let masque_settings = obj_pairs(vec![
        ("warp", warp),
        ("host", string(&spec.masque_host)),
        ("path", string(&spec.masque_path)),
        ("noize", string(spec.noize.masque_profile())),
        ("quicV2", crate::json::Json::Bool(spec.quic_v2)),
    ]);
    let tls = obj_pairs(vec![
        ("serverName", string(&spec.masque_server_name)),
        ("allowInsecure", crate::json::Json::Bool(true)),
    ]);
    let stream = obj_pairs(vec![
        ("network", string("masque")),
        ("security", string("tls")),
        ("tlsSettings", tls),
        ("masqueSettings", masque_settings),
    ]);
    let settings = obj_pairs(vec![
        ("address", string(&spec.masque_address)),
        ("port", crate::json::Json::Num(f64::from(spec.masque_port))),
        ("remoteDNS", address_json(&spec.dns)),
        ("mtu", crate::json::Json::Num(f64::from(spec.mtu))),
    ]);
    Ok(obj_pairs(vec![
        ("protocol", string("masque")),
        ("settings", settings),
        ("streamSettings", stream),
    ]))
}

fn reserved_json(reserved: [u8; 3]) -> crate::json::Json {
    crate::json::Json::Arr(
        reserved
            .iter()
            .map(|byte| crate::json::Json::Num(f64::from(*byte)))
            .collect(),
    )
}

/// Which half carried the first answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    WireGuard,
    Masque,
    Gool,
    GoolClassic,
    Mim,
}

/// The outbound: both built halves, the mode that bounds which may run, and
/// the race's answer once it has one.
#[derive(Debug)]
pub(crate) struct WarpOut {
    mode: Mode,
    wireguard: Option<Arc<crate::wg::WireGuardOut>>,
    masque: Option<Arc<crate::masque::MasqueOut>>,
    gool: Option<Arc<GoolOut>>,
    gool_classic: Option<Arc<GoolClassicOut>>,
    mim: Option<Arc<MimOut>>,
    chosen: Mutex<Option<Lane>>,
    probe_host: String,
    probe_port: u16,
}

fn configured_identity(spec: &WarpSpec, test: bool) -> Result<Option<Identity>, String> {
    if test
        && spec.inline.is_none()
        && !spec
            .identity_file
            .as_ref()
            .is_some_and(|path| path.is_file())
    {
        return Ok(None);
    }
    if test
        && matches!(spec.mode, Mode::Gool | Mode::GoolClassic)
        && spec.gool.inline.is_none()
        && !spec
            .gool
            .identity_file
            .as_ref()
            .is_some_and(|path| path.is_file())
        && !spec
            .key_paths()
            .is_some_and(|paths| spec.gool_path(&paths).is_ok_and(|path| path.is_file()))
    {
        return Ok(None);
    }
    if test
        && spec.mode == Mode::Mim
        && spec.mim.inline.is_none()
        && !spec.mim_path().is_ok_and(|path| path.is_file())
    {
        return Ok(None);
    }
    Ok(Some(spec.identity_in(test)?))
}

fn resolve_for_mode(
    spec: &mut WarpSpec,
    identity: &mut Identity,
    test: bool,
) -> Result<Option<Identity>, String> {
    if spec.mode == Mode::GoolClassic {
        let mut inner = spec.gool_identity_in(test)?;
        if !test {
            resolve_classic_edges(identity, &mut inner, spec)?;
        }
        Ok(Some(inner))
    } else if spec.mode == Mode::Mim {
        let inner = spec.mim_identity_in(test)?;
        if !test {
            resolve_edges(identity, spec)?;
        }
        Ok(Some(inner))
    } else {
        if !test {
            resolve_edges(identity, spec)?;
        }
        Ok(None)
    }
}

impl WarpOut {
    fn unbuilt(spec: &WarpSpec) -> Self {
        Self {
            mode: spec.mode,
            wireguard: None,
            masque: None,
            gool: None,
            gool_classic: None,
            mim: None,
            chosen: Mutex::new(None),
            probe_host: spec.probe_host.clone(),
            probe_port: spec.probe_port,
        }
    }

    pub(crate) fn new(outbound: &crate::json::Json, test: bool) -> Result<Self, String> {
        let settings = outbound
            .get("settings")
            .ok_or("warp outbound has no settings")?;
        let mut spec = WarpSpec::from(settings)?;
        let Some(mut identity) = configured_identity(&spec, test)? else {
            return Ok(Self::unbuilt(&spec));
        };
        let inner_identity = resolve_for_mode(&mut spec, &mut identity, test)?;
        if test && spec.mode == Mode::Gool {
            validate_gool(&identity, &spec)?;
            return Ok(Self::unbuilt(&spec));
        }
        let wireguard = if matches!(
            spec.mode,
            Mode::Masque | Mode::Gool | Mode::GoolClassic | Mode::Mim
        ) {
            None
        } else {
            match build_wireguard(&identity, &spec) {
                Ok(wireguard) => Some(Arc::new(wireguard)),
                Err(reason) if spec.mode == Mode::WireGuard => {
                    return Err(format!("warp wireguard half: {reason}"));
                }
                Err(reason) => {
                    eprintln!("warp: the wireguard half did not build: {reason}");
                    None
                }
            }
        };
        let masque = if matches!(
            spec.mode,
            Mode::WireGuard | Mode::Gool | Mode::GoolClassic | Mode::Mim
        ) {
            None
        } else if identity.masque.is_none() {
            if spec.mode == Mode::Masque {
                return Err("warp masque half: the identity has no MASQUE key".to_owned());
            }
            None
        } else {
            match build_masque(&identity, &spec) {
                Ok(masque) => Some(Arc::new(masque)),
                Err(reason) if spec.mode == Mode::Masque => {
                    return Err(format!("warp masque half: {reason}"));
                }
                Err(reason) => {
                    eprintln!("warp: the masque half did not build: {reason}");
                    None
                }
            }
        };
        let gool = if spec.mode == Mode::Gool {
            Some(Arc::new(build_gool(&identity, &spec, test)?))
        } else {
            None
        };
        let gool_classic = if spec.mode == Mode::GoolClassic {
            let inner = inner_identity
                .as_ref()
                .ok_or("warp gool-classic: the inner identity was not built")?;
            Some(Arc::new(build_gool_classic(&identity, inner, &spec)?))
        } else {
            None
        };
        let mim = if spec.mode == Mode::Mim {
            let inner = inner_identity
                .as_ref()
                .ok_or("warp mim: the inner identity was not built")?;
            Some(Arc::new(build_mim(&identity, inner, &spec)?))
        } else {
            None
        };
        if wireguard.is_none()
            && masque.is_none()
            && gool.is_none()
            && gool_classic.is_none()
            && mim.is_none()
        {
            return Err("warp: neither half could be built".to_owned());
        }
        Ok(Self {
            mode: spec.mode,
            wireguard,
            masque,
            gool,
            gool_classic,
            mim,
            chosen: Mutex::new(None),
            probe_host: spec.probe_host,
            probe_port: spec.probe_port,
        })
    }

    /// The configured mode, or the race's winner in auto. A fixed mode never
    /// races, and an auto with one built half takes it without a probe.
    fn lane(&self) -> Lane {
        match self.mode {
            Mode::WireGuard => return Lane::WireGuard,
            Mode::Masque => return Lane::Masque,
            Mode::Gool => return Lane::Gool,
            Mode::GoolClassic => return Lane::GoolClassic,
            Mode::Mim => return Lane::Mim,
            Mode::Auto => {}
        }
        // The lock spans the race so a second flow waits for the answer instead of probing again.
        let mut chosen = match self.chosen.lock() {
            Ok(chosen) => chosen,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(lane) = *chosen {
            return lane;
        }
        let (lane, answered) = match (&self.wireguard, &self.masque) {
            (Some(_) | None, None) => (Lane::WireGuard, true),
            (None, Some(_)) => (Lane::Masque, true),
            (Some(wireguard), Some(masque)) => {
                let wg = Arc::clone(wireguard);
                let mq = Arc::clone(masque);
                let (host, port) = (self.probe_host.clone(), self.probe_port);
                let masque_host = host.clone();
                race_probes(
                    move || wg.probe(&host, port),
                    move || mq.probe(&masque_host, port),
                    RACE_DEADLINE,
                )
            }
        };
        // Only a half that answered is a winner; a deadline fallback races again.
        if answered {
            *chosen = Some(lane);
        }
        lane
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        match self.mode {
            Mode::WireGuard => self.wireguard.as_ref().and_then(|half| half.edge()),
            Mode::Masque => self.masque.as_ref().and_then(|half| half.edge()),
            Mode::Gool => self.gool.as_ref().and_then(|gool| gool.edge()),
            Mode::GoolClassic => self
                .gool_classic
                .as_ref()
                .and_then(|classic| classic.edge()),
            Mode::Mim => self.mim.as_ref().and_then(|mim| mim.edge()),
            Mode::Auto => match self.chosen.lock().ok().and_then(|chosen| *chosen) {
                Some(Lane::WireGuard) => self.wireguard.as_ref().and_then(|half| half.edge()),
                Some(Lane::Masque) => self.masque.as_ref().and_then(|half| half.edge()),
                Some(Lane::Gool) => self.gool.as_ref().and_then(|gool| gool.edge()),
                Some(Lane::GoolClassic) => self
                    .gool_classic
                    .as_ref()
                    .and_then(|classic| classic.edge()),
                Some(Lane::Mim) => self.mim.as_ref().and_then(|mim| mim.edge()),
                None => self
                    .wireguard
                    .as_ref()
                    .and_then(|half| half.edge())
                    .or_else(|| self.masque.as_ref().and_then(|half| half.edge()))
                    .or_else(|| self.gool_classic.as_ref().and_then(|half| half.edge())),
            },
        }
    }

    pub(crate) fn serve_tcp(
        &self,
        client: crate::conn::Connection,
        asked: &crate::proxy::Destination,
        prefix: &[u8],
    ) {
        match self.lane() {
            Lane::WireGuard => {
                if let Some(wireguard) = &self.wireguard {
                    wireguard.serve_tcp(client, asked, prefix);
                }
            }
            Lane::Masque => {
                if let Some(masque) = &self.masque {
                    masque.serve_tcp(client, asked, prefix);
                }
            }
            Lane::Gool => {
                if let Some(gool) = &self.gool {
                    gool.inner.serve_tcp(client, asked, prefix);
                }
            }
            Lane::GoolClassic => {
                if let Some(classic) = &self.gool_classic {
                    classic.inner.serve_tcp(client, asked, prefix);
                }
            }
            Lane::Mim => {
                if let Some(mim) = &self.mim {
                    mim.inner.serve_tcp(client, asked, prefix);
                }
            }
        }
    }

    pub(crate) fn serve_udp(
        &self,
        relay: &std::net::UdpSocket,
        associate: Option<&crate::conn::Connection>,
    ) {
        match self.lane() {
            Lane::WireGuard => {
                if let Some(wireguard) = &self.wireguard {
                    wireguard.serve_udp(relay, associate);
                }
            }
            Lane::Masque => {
                if let Some(masque) = &self.masque {
                    masque.serve_udp(relay, associate);
                }
            }
            Lane::Gool => {
                if let Some(gool) = &self.gool {
                    gool.inner.serve_udp(relay, associate);
                }
            }
            Lane::GoolClassic => {
                if let Some(classic) = &self.gool_classic {
                    classic.inner.serve_udp(relay, associate);
                }
            }
            Lane::Mim => {
                if let Some(mim) = &self.mim {
                    mim.inner.serve_udp(relay, associate);
                }
            }
        }
    }
}

/// The first half to answer the probe wins. A failed answer is not the race's
/// end: the other half may still carry. If neither answers by the deadline,
/// `WireGuard` is the fallback a fixed config would have chosen, reported as
/// unanswered so the caller keeps racing on later flows.
fn race_probes<W, M>(wireguard: W, masque: M, budget: Duration) -> (Lane, bool)
where
    W: FnOnce() -> bool + Send + 'static,
    M: FnOnce() -> bool + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let wg_sender = sender.clone();
    std::thread::spawn(move || {
        let _ = wg_sender.send((Lane::WireGuard, wireguard()));
    });
    std::thread::spawn(move || {
        let _ = sender.send((Lane::Masque, masque()));
    });
    let deadline = Instant::now() + budget;
    let mut failed = 0;
    while failed < 2 {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match receiver.recv_timeout(left) {
            Ok((lane, true)) => return (lane, true),
            Ok((_, false)) => failed += 1,
            Err(_) => break,
        }
    }
    (Lane::WireGuard, false)
}

fn build_wireguard(
    identity: &Identity,
    spec: &WarpSpec,
) -> Result<crate::wg::WireGuardOut, String> {
    let settings = wireguard_settings(identity, spec);
    let config = crate::wireguard::DeviceConfig::from_json(&settings)?;
    crate::wg::WireGuardOut::with_noise(config, spec.noize.wireguard())
}

fn build_masque(identity: &Identity, spec: &WarpSpec) -> Result<crate::masque::MasqueOut, String> {
    let outbound = masque_outbound(identity, spec)?;
    crate::masque::MasqueOut::new(&outbound)
}

/// The test dial validates both halves without binding the forwarder `GoolOut::new` opens.
fn validate_gool(identity: &Identity, spec: &WarpSpec) -> Result<(), String> {
    if identity.masque.is_none() {
        return Err("warp gool: the identity has no MASQUE key".to_owned());
    }
    let inner = spec.gool_identity_in(true)?;
    build_masque(identity, spec)?;
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let settings =
        wireguard_settings_with_endpoint(&inner, spec, local, spec.mtu.min(GOOL_INNER_MTU));
    let config = crate::wireguard::DeviceConfig::from_json(&settings)?;
    crate::wg::WireGuardOut::with_noise(config, spec.noize.wireguard())?;
    Ok(())
}

/// `WireGuard` carried inside a MASQUE conversation.
#[derive(Debug)]
pub(crate) struct GoolOut {
    outer: Arc<crate::masque::MasqueOut>,
    inner: Arc<crate::wg::WireGuardOut>,
    _forwarder: crate::wg_stack::UdpForwarder,
}

impl GoolOut {
    fn new(
        outer: crate::masque::MasqueOut,
        inner_identity: &Identity,
        spec: &WarpSpec,
        remote: SocketAddr,
    ) -> Result<Self, String> {
        let outer = Arc::new(outer);
        let forwarder = outer.udp_forwarder(remote)?;
        let mtu = spec.mtu.min(GOOL_INNER_MTU);
        let settings = wireguard_settings_with_endpoint(inner_identity, spec, forwarder.local, mtu);
        let config = crate::wireguard::DeviceConfig::from_json(&settings)?;
        let inner = crate::wg::WireGuardOut::with_noise(config, spec.noize.wireguard())?;
        Ok(Self {
            outer,
            inner: Arc::new(inner),
            _forwarder: forwarder,
        })
    }

    fn edge(&self) -> Option<SocketAddr> {
        self.outer.edge()
    }
}

fn build_gool(identity: &Identity, spec: &WarpSpec, test: bool) -> Result<GoolOut, String> {
    if identity.masque.is_none() {
        return Err(
            "warp gool: the outer identity has no MASQUE key to carry WireGuard".to_owned(),
        );
    }
    let inner_identity = spec.gool_identity_in(test)?;
    let remote = spec.gool.peer.unwrap_or(inner_identity.wireguard.endpoint);
    let outer = build_masque(identity, spec)?;
    GoolOut::new(outer, &inner_identity, spec, remote)
}

/// A MASQUE conversation carried inside another MASQUE conversation.
#[derive(Debug)]
pub(crate) struct MimOut {
    outer: Arc<crate::masque::MasqueOut>,
    inner: Arc<crate::masque::MasqueOut>,
    _forwarder: crate::wg_stack::UdpForwarder,
}

impl MimOut {
    fn new(
        outer: crate::masque::MasqueOut,
        inner_identity: &Identity,
        spec: &WarpSpec,
        remote: SocketAddr,
    ) -> Result<Self, String> {
        let datagram = mim_inner_datagram(spec.mtu, remote)?;
        let mtu = mim_inner_mtu(datagram);
        let outer = Arc::new(outer);
        let forwarder = outer.udp_forwarder(remote)?;
        let outbound = mim_outbound(inner_identity, spec, forwarder.local, mtu, datagram)?;
        let inner = crate::masque::MasqueOut::new(&outbound)?;
        Ok(Self {
            outer,
            inner: Arc::new(inner),
            _forwarder: forwarder,
        })
    }

    fn edge(&self) -> Option<SocketAddr> {
        self.outer.edge()
    }
}

fn build_mim(
    identity: &Identity,
    inner_identity: &Identity,
    spec: &WarpSpec,
) -> Result<MimOut, String> {
    if identity.masque.is_none() {
        return Err("warp mim: the outer identity has no MASQUE key".to_owned());
    }
    let outer = build_masque(identity, spec)?;
    let outer_edge = outer.edge();
    let remote = spec
        .mim
        .inner
        .or_else(|| {
            let outer_ip = outer_edge.map(|edge| edge.ip());
            let mode = spec.scan.unwrap_or(ScanMode::Balanced);
            warp_scan::masque_candidates(mode)
                .into_iter()
                .find(|edge| Some(edge.ip()) != outer_ip)
        })
        .ok_or("warp mim: no second MASQUE edge is known for the inner hop")?;
    MimOut::new(outer, inner_identity, spec, remote)
}

/// The inner hop's datagram budget: the outer MTU less the IP and UDP headers
/// that carry it, bounded to what a QUIC peer accepts.
fn mim_inner_datagram(outer_mtu: u16, remote: SocketAddr) -> Result<usize, String> {
    let headers = if remote.is_ipv4() { 28 } else { 48 };
    let budget = usize::from(outer_mtu).saturating_sub(headers);
    if budget < MIM_MIN_DATAGRAM {
        return Err(format!(
            "warp mim: outer MTU {outer_mtu} leaves less than the inner hop's {MIM_MIN_DATAGRAM}-byte datagram budget"
        ));
    }
    Ok(budget.min(crate::quic::MAX_DATAGRAM))
}

/// The inner stack's MTU once the inner datagram pays the MASQUE overhead.
fn mim_inner_mtu(datagram: usize) -> usize {
    datagram
        .saturating_sub(MASQUE_DATAGRAM_OVERHEAD)
        .clamp(MIM_MIN_MTU, 1500)
}

/// The inner MASQUE outbound: the same WARP dialect as the outer one, dialled
/// at the forwarder inside the outer tunnel.
fn mim_outbound(
    identity: &Identity,
    spec: &WarpSpec,
    local: SocketAddr,
    mtu: usize,
    max_datagram: usize,
) -> Result<crate::json::Json, String> {
    let masque = identity
        .masque
        .as_ref()
        .ok_or("warp mim: the inner identity has no MASQUE key")?;
    let warp = obj_pairs(vec![
        ("privateKey", string(&b64(&masque.private))),
        ("publicKey", string(&b64(&masque.server))),
        ("address", address_json(&masque.addresses)),
    ]);
    let masque_settings = obj_pairs(vec![
        ("warp", warp),
        ("host", string(&spec.masque_host)),
        ("path", string(&spec.masque_path)),
        ("noize", string(spec.noize.masque_profile())),
    ]);
    let tls = obj_pairs(vec![
        ("serverName", string(&spec.masque_server_name)),
        ("allowInsecure", crate::json::Json::Bool(true)),
    ]);
    let stream = obj_pairs(vec![
        ("network", string("masque")),
        ("security", string("tls")),
        ("tlsSettings", tls),
        ("masqueSettings", masque_settings),
    ]);
    let mtu_size = u16::try_from(mtu).unwrap_or(u16::MAX);
    let datagram_size = u16::try_from(max_datagram).unwrap_or(u16::MAX);
    let settings = obj_pairs(vec![
        ("address", string(&local.ip().to_string())),
        ("port", crate::json::Json::Num(f64::from(local.port()))),
        ("remoteDNS", address_json(&spec.dns)),
        ("mtu", crate::json::Json::Num(f64::from(mtu_size))),
        (
            "maxDatagram",
            crate::json::Json::Num(f64::from(datagram_size)),
        ),
    ]);
    Ok(obj_pairs(vec![
        ("protocol", string("masque")),
        ("settings", settings),
        ("streamSettings", stream),
    ]))
}

/// `WireGuard` carried inside another `WireGuard` conversation.
#[derive(Debug)]
pub(crate) struct GoolClassicOut {
    outer: Arc<crate::wg::WireGuardOut>,
    inner: Arc<crate::wg::WireGuardOut>,
    _forwarder: crate::wg_stack::UdpForwarder,
}

impl GoolClassicOut {
    fn new(
        outer: crate::wg::WireGuardOut,
        inner_identity: &Identity,
        spec: &WarpSpec,
        remote: SocketAddr,
    ) -> Result<Self, String> {
        let outer = Arc::new(outer);
        let forwarder = outer.udp_forwarder(remote)?;
        let mtu = classic_inner_mtu(spec.mtu, remote)?;
        let settings = wireguard_settings_with_endpoint(inner_identity, spec, forwarder.local, mtu);
        let config = crate::wireguard::DeviceConfig::from_json(&settings)?;
        let inner = crate::wg::WireGuardOut::with_noise(config, spec.noize.wireguard())?;
        Ok(Self {
            outer,
            inner: Arc::new(inner),
            _forwarder: forwarder,
        })
    }

    fn edge(&self) -> Option<SocketAddr> {
        self.outer.edge()
    }
}

fn build_gool_classic(
    outer_identity: &Identity,
    inner_identity: &Identity,
    spec: &WarpSpec,
) -> Result<GoolClassicOut, String> {
    let remote = spec
        .gool
        .wiw_inner
        .or(spec.gool.peer)
        .unwrap_or(inner_identity.wireguard.endpoint);
    let outer = build_wireguard(outer_identity, spec)?;
    GoolClassicOut::new(outer, inner_identity, spec, remote)
}

/// The `--register` kinds: one protocol, both hops of a two-hop one, or all five.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Masque,
    WireGuard,
    Gool,
    GoolClassic,
    Mim,
    All,
}

impl KeyKind {
    fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "masque" => Ok(Self::Masque),
            "wg" | "wireguard" | "warp" => Ok(Self::WireGuard),
            "gool" | "wg-over-masque" => Ok(Self::Gool),
            "gool-classic" | "wiw" | "warp-in-warp" => Ok(Self::GoolClassic),
            "mim" | "masque-in-masque" => Ok(Self::Mim),
            "all" => Ok(Self::All),
            other => Err(format!(
                "warp-register: --register takes masque, wg, gool, gool-classic, mim or all, not `{other}`"
            )),
        }
    }

    fn slots(self) -> &'static [Slot] {
        match self {
            Self::Masque => &[Slot::Masque],
            Self::WireGuard => &[Slot::WireGuard],
            Self::Gool => &[Slot::Masque, Slot::Gool],
            Self::GoolClassic => &[Slot::WireGuard, Slot::WireGuardInner],
            Self::Mim => &[Slot::Masque, Slot::MasqueInner],
            Self::All => &[
                Slot::WireGuard,
                Slot::WireGuardInner,
                Slot::Masque,
                Slot::MasqueInner,
                Slot::Gool,
            ],
        }
    }
}

/// One identity file: a transport's first hop, its second, or the `WireGuard`
/// identity gool carries inside its MASQUE tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    WireGuard,
    WireGuardInner,
    Masque,
    MasqueInner,
    Gool,
}

impl Slot {
    fn label(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::WireGuardInner => "wireguard inner",
            Self::Masque => "masque",
            Self::MasqueInner => "masque inner",
            Self::Gool => "gool",
        }
    }

    /// Only a MASQUE identity carries the P-256 key the tunnel presents; the
    /// gool slot is `WireGuard` carried inside that tunnel, not a MASQUE device.
    fn enrolls_masque(self) -> bool {
        matches!(self, Self::Masque | Self::MasqueInner)
    }

    fn path(self, paths: &KeyPaths) -> PathBuf {
        match self {
            Self::WireGuard => paths.wireguard.clone(),
            Self::WireGuardInner => derive_sibling_path(&paths.wireguard, "secondary"),
            Self::Masque => paths.masque_path(),
            Self::MasqueInner => paths.masque_sibling("secondary"),
            Self::Gool => paths.masque_sibling("gool"),
        }
    }

    /// Where registration writes this slot: the allocated file, not the runtime fallback, so a base
    /// that already names the MASQUE half still gives `WireGuard` and MASQUE distinct files.
    fn allocation(self, paths: &KeyPaths) -> PathBuf {
        match self {
            Self::WireGuard => paths.wireguard.clone(),
            Self::WireGuardInner => derive_sibling_path(&paths.wireguard, "secondary"),
            Self::Masque => paths.masque.clone(),
            Self::MasqueInner => derive_sibling_path(&paths.masque, "secondary"),
            Self::Gool => derive_sibling_path(&paths.masque, "gool"),
        }
    }
}

/// Where each transport keeps its identity: the `WireGuard` file as named, the
/// MASQUE file beside it, and every second hop derived from its own first.
struct KeyPaths {
    wireguard: PathBuf,
    /// The file a multi-slot registration allocates for the MASQUE half.
    masque: PathBuf,
    /// The base when it already names the MASQUE half: runtime lookup prefers it, registration does not.
    named_masque: Option<PathBuf>,
}

impl KeyPaths {
    fn new(base: &Path, wireguard: Option<&Path>, masque: Option<&Path>) -> Self {
        Self {
            wireguard: wireguard.map_or_else(|| base.to_path_buf(), Path::to_path_buf),
            masque: masque.map_or_else(|| derive_sibling_path(base, "masque"), Path::to_path_buf),
            named_masque: (masque.is_none() && named_slot(base, "masque"))
                .then(|| base.to_path_buf()),
        }
    }

    /// The MASQUE identity to load: the named file, then the derived one, then the named path again
    /// so a runtime pointed at `account-masque.json` keeps using it.
    fn masque_path(&self) -> PathBuf {
        if let Some(named) = self.named_masque.as_ref().filter(|path| path.exists()) {
            return named.clone();
        }
        if self.masque.exists() {
            return self.masque.clone();
        }
        self.named_masque
            .clone()
            .unwrap_or_else(|| self.masque.clone())
    }

    fn masque_sibling(&self, suffix: &str) -> PathBuf {
        let effective = self.masque_path();
        let current = derive_sibling_path(&effective, suffix);
        if current.exists() {
            return current;
        }
        let allocated = derive_sibling_path(&self.masque, suffix);
        if allocated.exists() {
            return allocated;
        }
        if let Some(named) = self.named_masque.as_ref() {
            let old = derive_sibling_path(named, suffix);
            if old.exists() {
                return old;
            }
        }
        current
    }
}

/// Whether a path already names a slot, so a runtime pointed at the MASQUE half does not derive a second `-masque`.
fn named_slot(path: &Path, suffix: &str) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let stem = match name.rfind('.') {
        Some(dot) if dot > 0 => &name[..dot],
        _ => &name,
    };
    stem.ends_with(&format!("-{suffix}"))
}

fn derive_sibling_path(base: &Path, suffix: &str) -> PathBuf {
    let name = base
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let derived = match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{}-{}{}", &name[..dot], suffix, &name[dot..]),
        _ => format!("{name}-{suffix}"),
    };
    base.with_file_name(derived)
}

fn planned_slots(kind: KeyKind, paths: &KeyPaths) -> Result<Vec<(Slot, PathBuf)>, String> {
    let mut planned: Vec<(Slot, PathBuf)> = Vec::new();
    for &slot in kind.slots() {
        let path = slot.allocation(paths);
        if planned.iter().any(|(_, other)| *other == path) {
            return Err(format!(
                "warp-register: the {} identity would share {}; give each slot its own file",
                slot.label(),
                path.display()
            ));
        }
        planned.push((slot, path));
    }
    Ok(planned)
}

struct PlannedSlot {
    slot: Slot,
    path: PathBuf,
    identity: Identity,
    replace: bool,
    saved: bool,
}

/// Load or make every identity the kind names. A slot with no file is saved as
/// soon as it is made so a later failure does not orphan it; a replacement is
/// held until every slot is ready, so a failed registration leaves the old keys.
fn provision_kind(
    spec: &WarpSpec,
    kind: KeyKind,
    paths: &KeyPaths,
) -> Result<Vec<PlannedSlot>, String> {
    provision_kind_with(spec, kind, paths, &register, &refresh_saved)
}

fn provision_kind_with(
    spec: &WarpSpec,
    kind: KeyKind,
    paths: &KeyPaths,
    register_identity: &dyn Fn(&WarpSpec, bool) -> Result<Identity, String>,
    refresh_identity: &dyn Fn(&WarpSpec, &Identity) -> Result<Identity, RegisterError>,
) -> Result<Vec<PlannedSlot>, String> {
    let planned = planned_slots(kind, paths)?;
    let mut ready = Vec::new();
    for (slot, path) in planned {
        let (identity, replace, saved) = if path.is_file() {
            match Identity::load(&path) {
                Ok(saved) => match refresh_identity(spec, &saved) {
                    Ok(fresh) => (fresh, false, false),
                    Err(error) if error.refused && reprovision_enabled() => {
                        eprintln!(
                            "warp-register: the saved {} identity was refused: {}; registering a fresh one",
                            slot.label(),
                            error.reason
                        );
                        (register_identity(spec, slot.enrolls_masque())?, true, false)
                    }
                    Err(error) => {
                        eprintln!(
                            "warp-register: keeping the saved {} identity unchecked: {}",
                            slot.label(),
                            error.reason
                        );
                        (saved, false, false)
                    }
                },
                Err(error) if error.corrupt() && reprovision_enabled() => {
                    eprintln!(
                        "warp-register: {}; registering a fresh {} identity",
                        error.into_message(),
                        slot.label()
                    );
                    (register_identity(spec, slot.enrolls_masque())?, true, false)
                }
                Err(error) => return Err(error.into_message()),
            }
        } else {
            let identity = register_identity(spec, slot.enrolls_masque())?;
            identity.save(&path)?;
            (identity, false, true)
        };
        ready.push(PlannedSlot {
            slot,
            path,
            identity,
            replace,
            saved,
        });
    }
    Ok(ready)
}

/// The forced edges one-tap registration pins in the outbound it prints.
pub(crate) struct ForcedPeers<'a> {
    wiw_outer: Option<&'a str>,
    wiw_inner: Option<&'a str>,
    mim_outer: Option<&'a str>,
    mim_inner: Option<&'a str>,
    noize: Option<&'a str>,
    no_profile_retry: bool,
    no_quic_v2: bool,
}

struct ForcedEdges {
    wiw_outer: Option<SocketAddr>,
    wiw_inner: Option<SocketAddr>,
    mim_outer: Option<SocketAddr>,
    mim_inner: Option<SocketAddr>,
}

fn forced_edges(peers: &ForcedPeers<'_>) -> Result<ForcedEdges, String> {
    let edge = |text: Option<&str>, flag: &str| -> Result<Option<SocketAddr>, String> {
        text.map(|text| {
            parse_endpoint(text)
                .ok_or_else(|| format!("warp: `{flag}` is not an address: `{text}`"))
        })
        .transpose()
    };
    Ok(ForcedEdges {
        wiw_outer: edge(peers.wiw_outer, "--wiw-outer")?,
        wiw_inner: edge(peers.wiw_inner, "--wiw-inner")?,
        mim_outer: edge(peers.mim_outer, "--mim-outer")?,
        mim_inner: edge(peers.mim_inner, "--mim-inner")?,
    })
}

/// One-tap registration: create a device, enroll its MASQUE key, enable it,
/// save the identity where only the user can read it, and return the outbound
/// config that references the saved file.
#[allow(clippy::too_many_lines)]
pub(crate) fn one_tap(
    path: &str,
    mode: &str,
    api: Option<&str>,
    api_address: Option<&str>,
    peers: &ForcedPeers<'_>,
) -> Result<String, String> {
    let mode = Mode::parse(Some(mode))?;
    let path = PathBuf::from(path);
    let resumed = path.is_file();
    if resumed {
        // The outer device was already created; a failed inner enrollment must be able to finish on the next run instead of minting a second device.
        let saved = Identity::load(&path).map_err(LoadError::into_message)?;
        if matches!(mode, Mode::Masque | Mode::Gool | Mode::Mim) && saved.masque.is_none() {
            return Err(format!(
                "warp: `{}` has no MASQUE key for mode `{mode:?}`; remove it to register a new device",
                path.display()
            ));
        }
    }
    let ForcedEdges {
        wiw_outer,
        wiw_inner,
        mim_outer,
        mim_inner,
    } = forced_edges(peers)?;
    let spec = WarpSpec {
        mode,
        register: true,
        identity_file: Some(path.clone()),
        wireguard_identity_file: None,
        masque_identity_file: None,
        inline: None,
        api: api.map(str::to_owned),
        api_address: api_address.map(str::to_owned),
        endpoint: None,
        mtu: DEFAULT_MTU,
        keepalive: DEFAULT_KEEPALIVE,
        probe_host: PROBE_HOST.to_owned(),
        probe_port: PROBE_PORT,
        dns: TUNNEL_DNS
            .iter()
            .filter_map(|text| text.parse().ok())
            .collect(),
        masque_address: CONNECT_HOST.to_owned(),
        masque_port: QUIC_PORT,
        masque_server_name: CONNECT_SNI.to_owned(),
        masque_host: CONNECT_HOST.to_owned(),
        masque_path: "/".to_owned(),
        scan: (mode == Mode::GoolClassic && (wiw_outer.is_none() || wiw_inner.is_none()))
            .then_some(ScanMode::Balanced),
        peer: None,
        wg_peer: None,
        ironclad_port: IRONCLAD_PORT,
        quick_reconnect: false,
        last_edge: None,
        stale: None,
        cooldown: Duration::from_secs(COOLDOWN_SECS),
        noize: crate::noize::NoizeSettings::from_cli(peers.noize, peers.no_profile_retry),
        quic_v2: !peers.no_quic_v2,
        gool: GoolSettings {
            wiw_outer,
            wiw_inner,
            ..GoolSettings::default()
        },
        mim: MimSettings {
            outer: mim_outer,
            inner: mim_inner,
            ..MimSettings::default()
        },
    };
    if !resumed {
        let identity = register(&spec, !matches!(mode, Mode::WireGuard | Mode::GoolClassic))?;
        identity.save(&path)?;
    }
    // The outer registration is the half that must not be repeated, so an inner failure keeps it for the next run.
    if matches!(mode, Mode::Gool | Mode::GoolClassic) {
        spec.gool_identity()?;
    }
    if mode == Mode::Mim {
        spec.mim_identity()?;
    }
    let mut settings = vec![
        ("mode", string(mode.label())),
        ("identityFile", string(&path.to_string_lossy())),
    ];
    if let Some(edge) = wiw_outer {
        settings.push(("wiwOuter", string(&edge.to_string())));
    }
    if let Some(edge) = wiw_inner {
        settings.push(("wiwInner", string(&edge.to_string())));
    }
    if let Some(edge) = mim_outer {
        settings.push(("mimOuter", string(&edge.to_string())));
    }
    if let Some(edge) = mim_inner {
        settings.push(("mimInner", string(&edge.to_string())));
    }
    if spec.scan.is_some() {
        settings.push(("scan", string("balanced")));
    }
    if let Some(profile) = peers.noize {
        settings.push(("noize", string(profile)));
    }
    if peers.no_profile_retry {
        settings.push(("noProfileRetry", crate::json::Json::Bool(true)));
    }
    if peers.no_quic_v2 {
        settings.push(("quicV2", crate::json::Json::Bool(false)));
    }
    Ok(config_text(settings))
}

fn config_text(settings: Vec<(&str, crate::json::Json)>) -> String {
    let outbound = obj_pairs(vec![
        ("protocol", string("warp")),
        ("settings", obj_pairs(settings)),
    ]);
    let config = obj_pairs(vec![("outbounds", crate::json::Json::Arr(vec![outbound]))]);
    let mut text = String::new();
    crate::json::write(&config, &mut text);
    text
}

fn string(text: &str) -> crate::json::Json {
    crate::json::Json::Str(text.to_owned())
}

fn obj_pairs(pairs: Vec<(&str, crate::json::Json)>) -> crate::json::Json {
    crate::json::Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn json_bytes(value: &crate::json::Json) -> Vec<u8> {
    let mut text = String::new();
    crate::json::write(value, &mut text);
    text.into_bytes()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let unpadded = text.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(unpadded))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(unpadded))
        .ok()
}

fn decode_key(text: &str) -> Option<[u8; 32]> {
    decode_bytes(text).and_then(|bytes| bytes.try_into().ok())
}

/// A PEM body is standard base64 between the marker lines.
fn decode_pem(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    decode_bytes(&body)
}

fn clamp(private: &mut [u8; 32]) {
    private[0] &= 0xF8;
    private[31] &= 0x7F;
    private[31] |= 0x40;
}

/// RFC 3339 with milliseconds in UTC, the shape the API's `tos` field reads.
fn tos_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or_default();
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        now.subsec_millis()
    )
}

/// The civil date of a count of days since 1970-01-01, Howard Hinnant's
/// `civil_from_days`, with the same integer arithmetic the reference uses.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

/// The `warp-register` command: with `--register` make the identities a kind
/// names and print where they are; without it, register once and print the
/// outbound that references the saved combined identity.
#[allow(clippy::too_many_lines)]
pub(crate) fn register_command(args: &mut std::iter::Skip<std::env::Args>, usage: fn() -> !) {
    let mut base = String::from("warp-identity.json");
    let mut mode = String::from("auto");
    let mut api = None;
    let mut api_address = None;
    let mut kind = None;
    let mut wireguard = None;
    let mut masque = None;
    let mut wiw_outer = None;
    let mut wiw_inner = None;
    let mut mim_outer = None;
    let mut mim_inner = None;
    let mut noize = None;
    let mut no_profile_retry = false;
    let mut no_quic_v2 = false;
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "-o" | "--out" | "--identity" | "--config" => base = value(),
            "--mode" => mode = value(),
            "--gool-classic" => mode = String::from("gool-classic"),
            "--wiw-outer" => wiw_outer = Some(value()),
            "--wiw-inner" => wiw_inner = Some(value()),
            "--mim-outer" => mim_outer = Some(value()),
            "--mim-inner" => mim_inner = Some(value()),
            "--noize" => noize = Some(value()),
            "--no-profile-retry" => no_profile_retry = true,
            "--no-quic-v2" => no_quic_v2 = true,
            "--api" => api = Some(value()),
            "--api-address" => api_address = Some(value()),
            "--wg-config" => wireguard = Some(value()),
            "--masque-config" => masque = Some(value()),
            "--register" => {
                let text = value();
                kind = Some(match KeyKind::parse(&text) {
                    Ok(kind) => kind,
                    Err(reason) => {
                        eprintln!("{reason}");
                        std::process::exit(2);
                    }
                });
            }
            _ => usage(),
        }
    }
    let result = match kind {
        None => {
            if wireguard.is_some() || masque.is_some() {
                usage();
            }
            one_tap(
                &base,
                &mode,
                api.as_deref(),
                api_address.as_deref(),
                &ForcedPeers {
                    wiw_outer: wiw_outer.as_deref(),
                    wiw_inner: wiw_inner.as_deref(),
                    mim_outer: mim_outer.as_deref(),
                    mim_inner: mim_inner.as_deref(),
                    noize: noize.as_deref(),
                    no_profile_retry,
                    no_quic_v2,
                },
            )
        }
        Some(kind) => {
            let mode = match Mode::parse(Some(&mode)) {
                Ok(mode) => mode,
                Err(reason) => {
                    eprintln!("warp-register: {reason}");
                    std::process::exit(1);
                }
            };
            let mut spec = WarpSpec::for_command(mode, api, api_address);
            spec.identity_file = Some(PathBuf::from(&base));
            spec.wireguard_identity_file =
                wireguard.as_deref().map(Path::new).map(Path::to_path_buf);
            spec.masque_identity_file = masque.as_deref().map(Path::new).map(Path::to_path_buf);
            let paths = spec.key_paths().expect("the base identity is named");
            match provision_kind(&spec, kind, &paths).and_then(|planned| {
                for planned in &planned {
                    if !planned.saved {
                        if planned.replace {
                            quarantine(&planned.path);
                        }
                        planned.identity.save(&planned.path)?;
                    }
                    println!(
                        "[+] {} identity ready: device={} at {}",
                        planned.slot.label(),
                        planned.identity.device_id,
                        planned.path.display()
                    );
                }
                Ok(())
            }) {
                Ok(()) => Ok(String::new()),
                Err(reason) => Err(reason),
            }
        }
    };
    match result {
        Ok(text) if text.is_empty() => {}
        Ok(text) => println!("{text}"),
        Err(reason) => {
            eprintln!("warp-register: {reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> WarpSpec {
        WarpSpec {
            mode: Mode::Auto,
            register: false,
            identity_file: None,
            wireguard_identity_file: None,
            masque_identity_file: None,
            inline: None,
            api: None,
            api_address: None,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: Vec::new(),
            masque_address: CONNECT_HOST.to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
            scan: None,
            peer: None,
            wg_peer: None,
            ironclad_port: IRONCLAD_PORT,
            quick_reconnect: false,
            last_edge: None,
            stale: None,
            cooldown: Duration::from_secs(COOLDOWN_SECS),
            noize: crate::noize::NoizeSettings::default(),
            quic_v2: true,
            gool: GoolSettings::default(),
            mim: MimSettings::default(),
        }
    }

    fn sample_identity() -> Identity {
        Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
                reserved: [1, 2, 3],
            },
            masque: None,
        }
    }

    fn sample_reply(peer_key: &str) -> Reply {
        reply_with_ports(peer_key, &[500, 2408])
    }

    fn reply_with_ports(peer_key: &str, ports: &[u16]) -> Reply {
        let peer = obj_pairs(vec![
            ("public_key", string(peer_key)),
            (
                "endpoint",
                obj_pairs(vec![
                    ("v4", string("192.0.2.1:0")),
                    (
                        "ports",
                        crate::json::Json::Arr(
                            ports
                                .iter()
                                .map(|port| crate::json::Json::Num(f64::from(*port)))
                                .collect(),
                        ),
                    ),
                ]),
            ),
        ]);
        let interface = obj_pairs(vec![(
            "addresses",
            obj_pairs(vec![
                ("v4", string("172.16.0.2")),
                ("v6", string("2606:4700:110:8a1b::2")),
            ]),
        )]);
        let config = obj_pairs(vec![
            ("client_id", string(&b64(&[9, 8, 7]))),
            ("peers", crate::json::Json::Arr(vec![peer])),
            ("interface", interface),
        ]);
        let root = obj_pairs(vec![
            ("id", string("a-device")),
            ("token", string("a-token")),
            ("config", config),
        ]);
        Reply {
            status: 200,
            headers: Vec::new(),
            body: json_bytes(&root),
        }
    }

    #[test]
    fn a_zero_port_reply_keeps_a_dialable_endpoint() {
        let named = reply_with_ports(&b64(&[0x42; 32]), &[0, 443]);
        assert_eq!(
            parse_registration(&named)
                .expect("a registration")
                .endpoint
                .port(),
            443
        );
        let empty = reply_with_ports(&b64(&[0x42; 32]), &[0]);
        assert_eq!(
            parse_registration(&empty)
                .expect("a registration")
                .endpoint
                .port(),
            WIREGUARD_PORT
        );
    }

    #[test]
    fn a_registration_is_register_enroll_enable() {
        let key = rcgen::KeyPair::generate().expect("a MASQUE key");
        let server = key.public_key_pem();
        let calls = Mutex::new(Vec::new());
        let spec = WarpSpec {
            mode: Mode::Auto,
            register: true,
            identity_file: None,
            wireguard_identity_file: None,
            masque_identity_file: None,
            inline: None,
            api: None,
            api_address: None,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: Vec::new(),
            masque_address: CONNECT_HOST.to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
            scan: None,
            peer: None,
            wg_peer: None,
            ironclad_port: IRONCLAD_PORT,
            quick_reconnect: false,
            last_edge: None,
            stale: None,
            cooldown: Duration::from_secs(COOLDOWN_SECS),
            noize: crate::noize::NoizeSettings::default(),
            quic_v2: true,
            gool: GoolSettings::default(),
            mim: MimSettings::default(),
        };
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let masque_reply = sample_reply(&server);
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            calls.lock().expect("the call log").push((
                method.to_owned(),
                path.to_owned(),
                body.to_vec(),
            ));
            let reply = if method == "POST" {
                wireguard_reply.clone()
            } else {
                masque_reply.clone()
            };
            Ok::<_, RegisterError>(reply)
        };
        let identity = register_with(&spec, true, &call).expect("a registration");
        let recorded = calls.lock().expect("the call log");
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].0, "POST");
        assert_eq!(recorded[0].1, "/reg");
        assert!(String::from_utf8_lossy(&recorded[0].2).contains(r#""key_type":"curve25519""#));
        assert_eq!(recorded[1].0, "PATCH");
        assert_eq!(recorded[1].1, "/reg/a-device");
        assert!(String::from_utf8_lossy(&recorded[1].2).contains(r#""tunnel_type":"masque""#));
        assert_eq!(recorded[2].2, ENABLE_BODY);
        assert_eq!(identity.wireguard.reserved, [9, 8, 7]);
        assert_eq!(
            identity.wireguard.endpoint,
            "192.0.2.1:2408".parse().expect("an endpoint")
        );
        assert_eq!(identity.wireguard.addresses.len(), 2);
        assert!(identity.masque.is_some());
    }

    #[test]
    fn a_registered_identity_builds_both_tunnels() {
        let key = rcgen::KeyPair::generate().expect("a MASQUE key");
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec![
                    "172.16.0.2".parse().expect("a v4 address"),
                    "2606:4700:110:8a1b::2".parse().expect("a v6 address"),
                ],
                reserved: [1, 2, 3],
            },
            masque: Some(MasqueIdentity {
                private: key.serialize_der(),
                server: decode_pem(&key.public_key_pem()).expect("the server key"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
            }),
        };
        let spec = WarpSpec {
            mode: Mode::Auto,
            register: false,
            identity_file: None,
            wireguard_identity_file: None,
            masque_identity_file: None,
            inline: Some(identity.clone()),
            api: None,
            api_address: None,
            endpoint: None,
            mtu: DEFAULT_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            probe_host: PROBE_HOST.to_owned(),
            probe_port: PROBE_PORT,
            dns: TUNNEL_DNS
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
            masque_address: "127.0.0.1".to_owned(),
            masque_port: QUIC_PORT,
            masque_server_name: CONNECT_SNI.to_owned(),
            masque_host: CONNECT_HOST.to_owned(),
            masque_path: "/".to_owned(),
            scan: None,
            peer: None,
            wg_peer: None,
            ironclad_port: IRONCLAD_PORT,
            quick_reconnect: false,
            last_edge: None,
            stale: None,
            cooldown: Duration::from_secs(COOLDOWN_SECS),
            noize: crate::noize::NoizeSettings::default(),
            quic_v2: true,
            gool: GoolSettings::default(),
            mim: MimSettings::default(),
        };
        let settings = wireguard_settings(&identity, &spec);
        let config = crate::wireguard::DeviceConfig::from_json(&settings).expect("the WG half");
        assert_eq!(config.reserved, [1, 2, 3]);
        assert_eq!(config.addresses.len(), 2);
        assert_eq!(config.mtu, usize::from(DEFAULT_MTU));
        assert_eq!(config.peers[0].endpoint, Some(identity.wireguard.endpoint));
        let outbound = masque_outbound(&identity, &spec).expect("the MASQUE half");
        assert_eq!(
            outbound
                .get("streamSettings")
                .and_then(|settings| settings.get("masqueSettings"))
                .and_then(|settings| settings.get("quicV2"))
                .and_then(crate::json::Json::as_bool),
            Some(true),
            "the WARP MASQUE half carries the opener"
        );
        crate::masque::MasqueOut::new(&outbound).expect("the MASQUE carrier");
        assert_eq!(
            wireguard_settings(&identity, &spec)
                .get("mtu")
                .and_then(crate::json::Json::as_u32),
            Some(u32::from(DEFAULT_MTU))
        );
    }

    #[test]
    fn the_auto_mode_races_both_tunnels() {
        assert_eq!(Mode::parse(None).expect("default"), Mode::Auto);
        assert_eq!(Mode::parse(Some("wg")).expect("wg"), Mode::WireGuard);
        assert_eq!(Mode::parse(Some("masque")).expect("masque"), Mode::Masque);
        assert!(Mode::parse(Some("other")).is_err());
    }

    #[test]
    fn the_first_answering_half_wins_the_race() {
        // MASQUE cannot answer until released, so WireGuard's answer is first by construction.
        let (release, wait) = mpsc::channel::<()>();
        let (lane, answered) = race_probes(
            || true,
            move || {
                let _ = wait.recv();
                true
            },
            Duration::from_secs(5),
        );
        assert_eq!(lane, Lane::WireGuard);
        assert!(answered);
        drop(release);
    }

    #[test]
    fn a_failed_probe_does_not_end_the_race() {
        // A false answer must not end the race: the other half may still carry.
        let (lane, answered) = race_probes(
            || false,
            || {
                std::thread::sleep(Duration::from_millis(50));
                true
            },
            Duration::from_secs(5),
        );
        assert_eq!(lane, Lane::Masque);
        assert!(answered);
    }

    #[test]
    fn two_failed_probes_fall_back_to_wireguard() {
        assert_eq!(
            race_probes(|| false, || false, Duration::from_secs(5)),
            (Lane::WireGuard, false)
        );
    }

    #[test]
    fn a_silent_pair_falls_back_at_the_deadline() {
        let start = Instant::now();
        let (lane, answered) = race_probes(
            || {
                std::thread::sleep(Duration::from_secs(30));
                true
            },
            || {
                std::thread::sleep(Duration::from_secs(30));
                true
            },
            Duration::from_millis(50),
        );
        assert_eq!(lane, Lane::WireGuard);
        assert!(!answered);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the deadline bound the wait"
        );
    }

    #[test]
    fn an_identity_survives_a_save_and_load() {
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let dir = std::env::temp_dir().join(format!("ferrox-warp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        identity.save(&path).expect("saves");
        let loaded = Identity::load(&path).expect("loads");
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.wireguard.private, identity.wireguard.private);
        assert_eq!(loaded.wireguard.peer, identity.wireguard.peer);
        assert_eq!(loaded.wireguard.endpoint, identity.wireguard.endpoint);
        assert_eq!(loaded.wireguard.reserved, [1, 2, 3]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the identity is owner-only");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_api_address_moves_the_dial_not_the_name() {
        let spec = WarpSpec::for_command(Mode::Auto, None, Some("198.51.100.7:8443".to_owned()));
        let endpoint =
            api_endpoint(&spec, "https://api.cloudflareclient.com/v0a4471").expect("an endpoint");
        assert_eq!(endpoint.host, "api.cloudflareclient.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(
            endpoint.address,
            Some("198.51.100.7:8443".parse().expect("an address"))
        );
        let plain = api_endpoint(
            &WarpSpec::for_command(Mode::Auto, None, None),
            "https://api.cloudflareclient.com/v0a4471",
        )
        .expect("an endpoint");
        assert_eq!(plain.address, None);
        for (text, want) in [
            ("2606:4700::1", "[2606:4700::1]:443"),
            ("[2606:4700::1]", "[2606:4700::1]:443"),
            ("[2606:4700::1]:8443", "[2606:4700::1]:8443"),
        ] {
            let spec = WarpSpec::for_command(Mode::Auto, None, Some(text.to_owned()));
            let endpoint = api_endpoint(&spec, "https://api.cloudflareclient.com/v0a4471")
                .expect("an endpoint");
            assert_eq!(
                endpoint.address,
                Some(want.parse().expect("an address")),
                "{text}"
            );
        }
    }

    #[test]
    fn host_and_port_split_every_shape_the_flag_takes() {
        let cases = [
            ("198.51.100.7", ("198.51.100.7", 443)),
            ("198.51.100.7:80", ("198.51.100.7", 80)),
            ("2606:4700::1", ("2606:4700::1", 443)),
            ("[2606:4700::1]:8443", ("2606:4700::1", 8443)),
            ("[2606:4700::1]", ("2606:4700::1", 443)),
            ("api.example.com", ("api.example.com", 443)),
            ("api.example.com:8080", ("api.example.com", 8080)),
        ];
        for (text, (host, port)) in cases {
            assert_eq!(
                split_host_port(text, 443),
                Some((host.to_owned(), port)),
                "{text}"
            );
        }
        assert_eq!(split_host_port("", 443), None);
        assert_eq!(split_host_port("[2606:4700::1", 443), None);
        assert_eq!(split_host_port("api.example.com:port", 443), None);
    }

    #[test]
    fn every_slot_derives_beside_its_own_first_hop() {
        assert_eq!(KeyKind::All.slots().len(), 5);
        assert_eq!(KeyKind::Gool.slots().len(), 2);
        let base = Path::new("/tmp/warp-identity.json");
        let paths = KeyPaths::new(base, None, None);
        assert_eq!(Slot::WireGuard.path(&paths), base);
        assert_eq!(
            Slot::WireGuardInner.path(&paths),
            Path::new("/tmp/warp-identity-secondary.json")
        );
        assert_eq!(
            Slot::Masque.path(&paths),
            Path::new("/tmp/warp-identity-masque.json")
        );
        assert_eq!(
            Slot::MasqueInner.path(&paths),
            Path::new("/tmp/warp-identity-masque-secondary.json")
        );
        assert_eq!(
            Slot::Gool.path(&paths),
            Path::new("/tmp/warp-identity-masque-gool.json")
        );
        let overridden = KeyPaths::new(
            base,
            Some(Path::new("/etc/wg.json")),
            Some(Path::new("/etc/masque.json")),
        );
        assert_eq!(
            Slot::WireGuardInner.path(&overridden),
            Path::new("/etc/wg-secondary.json")
        );
        assert_eq!(
            Slot::Gool.path(&overridden),
            Path::new("/etc/masque-gool.json")
        );
    }

    /// A runtime pointed straight at the MASQUE half keeps that file: deriving beside it would
    /// look for `account-masque-masque.json`, which no earlier run ever wrote.
    #[test]
    fn a_masque_path_is_not_suffixed_again() {
        let base = Path::new("/tmp/account-masque.json");
        let paths = KeyPaths::new(base, Some(Path::new("/tmp/account-wg.json")), None);
        assert_eq!(Slot::Masque.path(&paths), base);
        assert_eq!(
            Slot::WireGuard.path(&paths),
            Path::new("/tmp/account-wg.json")
        );
        assert!(!named_slot(
            Path::new("/tmp/account-masquerade.json"),
            "masque"
        ));
    }

    /// A base that already names the MASQUE half still has to register both slots: runtime reuses
    /// the base, but allocation derives the old distinct file or `planned_slots` sees a collision.
    #[test]
    fn a_named_masque_base_allocates_a_distinct_registration_file() {
        let base = Path::new("/tmp/account-masque.json");
        let paths = KeyPaths::new(base, None, None);
        assert_eq!(Slot::WireGuard.allocation(&paths), base);
        assert_eq!(
            Slot::Masque.allocation(&paths),
            Path::new("/tmp/account-masque-masque.json")
        );
        assert_eq!(
            Slot::MasqueInner.allocation(&paths),
            Path::new("/tmp/account-masque-masque-secondary.json")
        );
        assert!(planned_slots(KeyKind::All, &paths).is_ok());
    }

    /// `auto` can serve a WireGuard-only device, so resuming one must not demand a MASQUE key that
    /// only the explicit MASQUE lanes need.
    #[test]
    fn auto_resume_accepts_a_wireguard_only_identity() {
        let path = std::env::temp_dir().join(format!(
            "ferrox-warp-auto-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        sample_identity().save(&path).expect("saves the identity");
        let out = one_tap(
            &path.to_string_lossy(),
            "auto",
            None,
            None,
            &ForcedPeers {
                wiw_outer: None,
                wiw_inner: None,
                mim_outer: None,
                mim_inner: None,
                noize: None,
                no_profile_retry: false,
                no_quic_v2: false,
            },
        );
        std::fs::remove_file(&path).ok();
        assert!(out.is_ok(), "{out:?}");
    }

    /// The old rule derived beside a base that already named the MASQUE half; an identity enrolled
    /// then must still be the one a later run loads, both for the outer hop and its inner hops.
    #[test]
    fn a_legacy_named_masque_slot_keeps_its_inner_identities() {
        let dir = std::env::temp_dir().join(format!(
            "ferrox-warp-legacy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let base = dir.join("account-masque.json");
        let legacy = dir.join("account-masque-masque.json");
        let legacy_inner = dir.join("account-masque-masque-secondary.json");
        let legacy_gool = dir.join("account-masque-masque-gool.json");
        for path in [&legacy, &legacy_inner, &legacy_gool] {
            std::fs::write(path, b"{}").expect("a legacy identity file");
        }
        let paths = KeyPaths::new(&base, None, None);
        assert_eq!(Slot::Masque.path(&paths), legacy);
        assert_eq!(Slot::MasqueInner.path(&paths), legacy_inner);
        assert_eq!(Slot::Gool.path(&paths), legacy_gool);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_slots_cannot_share_one_identity_file() {
        let base = Path::new("/tmp/warp-identity.json");
        let paths = KeyPaths::new(base, Some(base), Some(base));
        let error = planned_slots(KeyKind::All, &paths).expect_err("the slots collide");
        assert!(error.contains("share"), "{error}");
        let distinct = KeyPaths::new(
            base,
            Some(Path::new("/tmp/wg.json")),
            Some(Path::new("/tmp/masque.json")),
        );
        assert_eq!(
            planned_slots(KeyKind::All, &distinct)
                .expect("distinct slots")
                .len(),
            5
        );
    }

    #[test]
    fn a_wireguard_slot_registers_without_enrolling_masque() {
        let calls = Mutex::new(Vec::new());
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            calls.lock().expect("the call log").push((
                method.to_owned(),
                path.to_owned(),
                body.to_vec(),
            ));
            Ok::<_, RegisterError>(wireguard_reply.clone())
        };
        let identity = register_with(&spec, false, &call).expect("a registration");
        let recorded = calls.lock().expect("the call log");
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].0, "POST");
        assert_eq!(recorded[1].0, "PATCH");
        assert_eq!(recorded[1].1, "/reg/a-device");
        assert_eq!(recorded[1].2, ENABLE_BODY);
        assert!(identity.masque.is_none());
    }

    #[test]
    fn a_refused_enable_is_fatal_and_saves_nothing() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let call = |method: &str, _path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            if method == "PATCH" && body == ENABLE_BODY {
                return Ok::<_, RegisterError>(Reply {
                    status: 403,
                    headers: Vec::new(),
                    body: b"{\"error\":\"refused\"}".to_vec(),
                });
            }
            Ok::<_, RegisterError>(wireguard_reply.clone())
        };
        let error = register_with(&spec, false, &call).expect_err("the enable is refused");
        assert!(error.fatal);
        assert!(error.reason.contains("403"), "{}", error.reason);
    }

    #[test]
    fn a_failed_enrollment_does_not_mint_a_second_device() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let wireguard_reply = sample_reply(&b64(&[0x42; 32]));
        let posts = Mutex::new(0usize);
        let deletes = Mutex::new(0usize);
        let call = |method: &str, _path: &str, _headers: &[(&str, &str)], _body: &[u8]| {
            if method == "POST" {
                *posts.lock().expect("the post count") += 1;
                return Ok::<_, RegisterError>(wireguard_reply.clone());
            }
            if method == "DELETE" {
                *deletes.lock().expect("the delete count") += 1;
                return Ok(wireguard_reply.clone());
            }
            Err::<Reply, _>(RegisterError::retryable("the enrollment leg is down"))
        };
        let error = register_with(&spec, true, &call).expect_err("the enrollment fails");
        assert!(error.fatal, "{}", error.reason);
        assert!(
            error.reason.contains("enrollment failed"),
            "{}",
            error.reason
        );
        assert_eq!(*posts.lock().expect("the post count"), 1);
        assert_eq!(*deletes.lock().expect("the delete count"), 1);
    }

    #[test]
    fn a_read_back_updates_the_saved_identity() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("a v4 address")],
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let fresh_reply = sample_reply(&b64(&[0x55; 32]));
        let call = |method: &str, path: &str, _headers: &[(&str, &str)], body: &[u8]| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/reg/a-device");
            assert_eq!(body, []);
            Ok::<_, RegisterError>(fresh_reply.clone())
        };
        let fresh = refresh(&spec, &saved, &call).expect("a read-back");
        assert_eq!(fresh.wireguard.peer, [0x55; 32]);
        assert_eq!(fresh.wireguard.reserved, [9, 8, 7]);
        assert_eq!(fresh.wireguard.addresses.len(), 2);
    }

    #[test]
    fn a_refused_read_back_is_told_apart_from_an_outage() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        for (status, body, refused) in [
            (401, &b"{\"error\":\"x\"}"[..], true),
            (404, &b"{\"error\":\"x\"}"[..], false),
            (
                404,
                &b"{\"success\":false,\"errors\":[{\"code\":1000}]}"[..],
                true,
            ),
            (404, &b"{\"success\":true,\"errors\":[]}"[..], false),
            (410, &b"{\"error\":\"x\"}"[..], true),
            (503, &b"{\"error\":\"x\"}"[..], false),
        ] {
            let call = move |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
                Ok::<_, RegisterError>(Reply {
                    status,
                    headers: Vec::new(),
                    body: body.to_vec(),
                })
            };
            let error = refresh(&spec, &saved, &call).expect_err("not a usable read-back");
            assert_eq!(error.refused, refused, "{status}");
        }
    }

    #[test]
    fn three_spellings_turn_reprovisioning_off() {
        for off in ["0", "off", "false", " OFF ", "False", "0\t"] {
            assert!(!reprovision_enabled_for(Some(off)), "{off}");
        }
        assert!(reprovision_enabled_for(None));
        assert!(reprovision_enabled_for(Some("1")));
        assert!(reprovision_enabled_for(Some("true")));
    }

    #[test]
    fn an_unreadable_identity_is_not_a_corrupt_one() {
        let dir = std::env::temp_dir().join(format!("ferrox-warp-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        std::fs::create_dir(&path).expect("a directory where the file should be");
        let error = Identity::load(&path).expect_err("a read failure");
        assert!(!error.corrupt(), "{error:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_broken_identity_is_corrupt() {
        let dir = std::env::temp_dir().join(format!("ferrox-warp-broken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("identity.json");
        std::fs::write(&path, b"not json").expect("a broken identity");
        let error = Identity::load(&path).expect_err("a parse failure");
        assert!(error.corrupt(), "{error:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_refused_identity_is_replaced_only_when_registration_is_allowed() {
        assert!(should_reprovision(true, true, true));
        assert!(!should_reprovision(false, true, true));
        assert!(!should_reprovision(true, false, true));
        assert!(!should_reprovision(true, true, false));
    }

    #[test]
    fn a_404_page_from_a_front_is_not_a_refusal() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let saved = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [1, 2, 3],
            },
            masque: None,
        };
        let page = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 404,
                headers: Vec::new(),
                body: b"<html>not the API</html>".to_vec(),
            })
        };
        let error = refresh(&spec, &saved, &page).expect_err("a 404 page");
        assert!(!error.refused, "{}", error.reason);
        let envelope = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 404,
                headers: Vec::new(),
                body: b"{\"success\":false,\"errors\":[{\"code\":1000}]}".to_vec(),
            })
        };
        let error = refresh(&spec, &saved, &envelope).expect_err("a refusal");
        assert!(error.refused, "{}", error.reason);
    }

    #[test]
    fn a_shaped_registration_reply_is_not_retried_on_another_host() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let shaped = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 200,
                headers: Vec::new(),
                body: b"{\"id\":\"a-device\",\"token\":\"a-token\"}".to_vec(),
            })
        };
        let error = register_with(&spec, false, &shaped).expect_err("no config");
        assert!(error.fatal, "{}", error.reason);
        let page = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Ok::<_, RegisterError>(Reply {
                status: 200,
                headers: Vec::new(),
                body: b"<html>not the API</html>".to_vec(),
            })
        };
        let error = register_with(&spec, false, &page).expect_err("not the API");
        assert!(error.fatal, "{}", error.reason);
    }

    /// A POST that may have created the device stops host fallback even when its response was lost.
    #[test]
    fn a_lost_registration_response_stops_host_fallback() {
        let spec = WarpSpec::for_command(Mode::Auto, None, None);
        let lost = |_: &str, _: &str, _: &[(&str, &str)], _: &[u8]| {
            Err::<Reply, _>(RegisterError::fatal("the response was lost"))
        };
        let error = register_with(&spec, false, &lost).expect_err("the response is lost");
        assert!(error.fatal, "{}", error.reason);
        assert!(error.reason.contains("lost"), "{}", error.reason);
    }

    #[test]
    fn the_quic_v2_opener_is_on_unless_a_setting_or_the_environment_turns_it_off() {
        let settings = |text: &str| crate::json::parse(text).expect("settings");
        assert!(quic_v2_enabled(&settings("{}"), None));
        assert!(quic_v2_enabled(&settings("{}"), Some("1")));
        assert!(quic_v2_enabled(&settings("{}"), Some("anything")));
        for off in ["0", "off", "false", "no", " OFF "] {
            assert!(!quic_v2_enabled(&settings("{}"), Some(off)), "{off}");
        }
        assert!(!quic_v2_enabled(
            &settings(r#"{"quicV2":false}"#),
            Some("1")
        ));
        assert!(quic_v2_enabled(&settings(r#"{"quicV2":true}"#), Some("0")));
    }

    #[test]
    fn six_register_kinds_parse() {
        let kinds = ["masque", "wg", "gool", "gool-classic", "mim", "all"];
        assert_eq!(kinds.len(), 6);
        for kind in kinds {
            assert!(KeyKind::parse(kind).is_ok(), "{kind}");
        }
        for alias in [
            "wireguard",
            "warp",
            "wg-over-masque",
            "wiw",
            "warp-in-warp",
            "masque-in-masque",
        ] {
            assert!(KeyKind::parse(alias).is_ok(), "{alias}");
        }
        assert!(KeyKind::parse("other").is_err());
    }

    #[test]
    fn a_gool_mode_parses_the_inner_hop() {
        let spec = WarpSpec::from(
            &crate::json::parse(
                r#"{"mode":"gool","register":true,"mtu":1500,"goolPeer":"192.0.2.9:2408","goolIdentityFile":"inner.json"}"#,
            )
            .expect("settings"),
        )
        .expect("a gool spec");
        assert_eq!(spec.mode, Mode::Gool);
        assert_eq!(spec.mode.label(), "gool");
        assert_eq!(spec.mtu, 1500);
        assert_eq!(
            spec.gool.peer,
            Some("192.0.2.9:2408".parse().expect("the inner peer"))
        );
        assert_eq!(
            spec.gool.identity_file.as_deref(),
            Some(Path::new("inner.json"))
        );
        assert_eq!(
            Mode::parse(Some("wg-over-masque")).expect("the alias"),
            Mode::Gool
        );
    }

    #[test]
    fn a_gool_classic_mode_parses_both_hops() {
        let spec = WarpSpec::from(
            &crate::json::parse(
                r#"{"mode":"gool-classic","register":true,"wiwOuter":"192.0.2.1:2408","wiwInner":"192.0.2.2:2408","goolIdentityFile":"inner.json"}"#,
            )
            .expect("settings"),
        )
        .expect("a gool-classic spec");
        assert_eq!(spec.mode, Mode::GoolClassic);
        assert_eq!(spec.mode.label(), "gool-classic");
        assert_eq!(
            spec.gool.wiw_outer,
            Some("192.0.2.1:2408".parse().expect("the outer peer"))
        );
        assert_eq!(
            spec.gool.wiw_inner,
            Some("192.0.2.2:2408".parse().expect("the inner peer"))
        );
        assert_eq!(
            Mode::parse(Some("wiw")).expect("the alias"),
            Mode::GoolClassic
        );
    }

    #[test]
    fn the_gool_classic_inner_identity_derives_beside_the_outer_one() {
        let spec = WarpSpec {
            mode: Mode::GoolClassic,
            identity_file: Some(PathBuf::from("/tmp/warp-identity.json")),
            ..sample_spec()
        };
        let paths = spec.key_paths().expect("the outer identity");
        assert_eq!(
            spec.gool_path(&paths).expect("the inner path"),
            PathBuf::from("/tmp/warp-identity-secondary.json")
        );
        let gool = WarpSpec {
            mode: Mode::Gool,
            ..spec
        };
        assert_eq!(
            gool.gool_path(&paths).expect("the inner path"),
            PathBuf::from("/tmp/warp-identity-masque-gool.json")
        );
    }

    #[test]
    fn the_gool_path_follows_the_masque_override_the_planner_writes() {
        let base = Path::new("/tmp/warp-identity.json");
        let masque = Path::new("/tmp/outer.json");
        let paths = KeyPaths::new(base, None, Some(masque));
        let spec = WarpSpec {
            mode: Mode::Gool,
            identity_file: Some(base.to_path_buf()),
            masque_identity_file: Some(masque.to_path_buf()),
            ..sample_spec()
        };
        assert_eq!(
            spec.gool_path(&paths).expect("the inner path"),
            Slot::Gool.path(&paths)
        );
        assert_eq!(
            spec.gool_path(&paths).expect("the inner path"),
            PathBuf::from("/tmp/outer-gool.json")
        );
    }

    #[test]
    fn a_gool_identity_file_stands_without_an_outer_identity_file() {
        let inner = std::env::temp_dir().join(format!(
            "ferrox-gool-explicit-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let spec = WarpSpec {
            mode: Mode::Gool,
            inline: Some(sample_identity()),
            gool: GoolSettings {
                identity_file: Some(inner.clone()),
                ..GoolSettings::default()
            },
            ..sample_spec()
        };
        let error = spec.gool_identity().expect_err("the named file is absent");
        assert!(
            error.contains(&inner.display().to_string()),
            "the explicit inner path is read without an outer file: {error}"
        );
        assert!(
            !error.contains("`goolIdentityFile`"),
            "the outer file is not demanded when the inner one is named: {error}"
        );
    }

    #[test]
    fn a_second_gool_registration_finds_the_file_the_first_one_wrote() {
        let dir = std::env::temp_dir().join(format!(
            "ferrox-gool-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let base = dir.join("warp-identity.json");
        let masque = dir.join("outer.json");
        let paths = KeyPaths::new(&base, None, Some(&masque));
        let spec = WarpSpec {
            mode: Mode::Gool,
            identity_file: Some(base.clone()),
            masque_identity_file: Some(masque.clone()),
            ..sample_spec()
        };
        let registrations = std::cell::Cell::new(0u32);
        let counting = |_: &WarpSpec, _: bool| {
            registrations.set(registrations.get() + 1);
            Ok(sample_identity())
        };
        let fresh = |_: &WarpSpec, saved: &Identity| Ok(saved.clone());
        let first = provision_kind_with(&spec, KeyKind::Gool, &paths, &counting, &fresh)
            .expect("the first");
        assert_eq!(registrations.get(), 2, "both slots enrolled once");
        let gool = first
            .iter()
            .find(|planned| planned.slot == Slot::Gool)
            .expect("the gool slot");
        assert_eq!(spec.gool_path(&paths).expect("the inner path"), gool.path);
        assert_eq!(gool.path, Slot::Gool.path(&paths));
        let second = provision_kind_with(&spec, KeyKind::Gool, &paths, &counting, &fresh)
            .expect("the second");
        assert_eq!(registrations.get(), 2, "the second run enrolls nothing");
        assert!(second.iter().all(|planned| !planned.saved));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_two_gool_classic_hops_must_land_on_distinct_edges() {
        let mut outer = sample_identity();
        let mut inner = sample_identity();
        let mut spec = sample_spec();
        spec.mode = Mode::GoolClassic;
        spec.gool.wiw_outer = Some("192.0.2.1:2408".parse().expect("the outer peer"));
        spec.gool.wiw_inner = Some("192.0.2.1:2408".parse().expect("the inner peer"));
        assert_eq!(
            resolve_classic_edges(&mut outer, &mut inner, &mut spec),
            Err("warp gool-classic: the outer edge 192.0.2.1:2408 and inner edge 192.0.2.1:2408 share an address; name distinct `wiwOuter`/`wiwInner` peers or enable `scan`".to_owned())
        );

        spec.gool.wiw_inner = Some("192.0.2.2:2408".parse().expect("a second peer"));
        resolve_classic_edges(&mut outer, &mut inner, &mut spec).expect("distinct hops");
        assert_eq!(
            outer.wireguard.endpoint,
            "192.0.2.1:2408".parse().expect("outer")
        );
        assert_eq!(
            inner.wireguard.endpoint,
            "192.0.2.2:2408".parse().expect("inner")
        );
    }

    #[test]
    fn a_malformed_gool_peer_is_refused() {
        let reason = WarpSpec::from(
            &crate::json::parse(r#"{"mode":"gool","register":true,"goolPeer":"not-an-address"}"#)
                .expect("settings"),
        )
        .expect_err("a malformed peer");
        assert!(reason.contains("goolPeer"), "{reason}");
    }

    #[test]
    fn the_gool_inner_hop_points_at_the_forwarder_and_caps_the_mtu() {
        let identity = Identity {
            device_id: "gool".to_owned(),
            token: String::new(),
            wireguard: WireGuardIdentity {
                private: [0x11; 32],
                peer: [0x22; 32],
                endpoint: "192.0.2.9:2408".parse().expect("the inner endpoint"),
                addresses: vec!["10.0.0.2".parse().expect("the inner address")],
                reserved: [0; 3],
            },
            masque: None,
        };
        let spec = WarpSpec::for_command(Mode::Gool, None, None);
        let settings = wireguard_settings_with_endpoint(
            &identity,
            &spec,
            "127.0.0.1:5000".parse().expect("the forwarder"),
            GOOL_INNER_MTU,
        );
        let config = crate::wireguard::DeviceConfig::from_json(&settings).expect("the inner hop");
        assert_eq!(
            config.peers[0].endpoint,
            Some("127.0.0.1:5000".parse().expect("the forwarder"))
        );
        assert_eq!(config.mtu, usize::from(GOOL_INNER_MTU));
    }

    #[test]
    fn the_classic_inner_mtu_subtracts_the_header_and_the_outer_packet() {
        let v4: SocketAddr = "192.0.2.9:2408".parse().expect("an IPv4 edge");
        let v6: SocketAddr = "[2001:db8::1]:2408".parse().expect("an IPv6 edge");
        assert_eq!(classic_inner_mtu(1280, v4), Ok(GOOL_INNER_MTU));
        assert_eq!(
            classic_inner_mtu(1280, v6),
            Ok(1280 - WG_HEADER_SIZE as u16 - WG_TAG_SIZE as u16 - 48)
        );
        assert_eq!(classic_inner_mtu(1400, v4), Ok(GOOL_INNER_MTU));
        assert_eq!(
            classic_inner_mtu(u16::try_from(28 + WG_HEADER_SIZE + WG_TAG_SIZE - 1).expect("small"),
                v4),
            Err("warp gool-classic: outer MTU 59 leaves no room for the inner hop's 60-byte overhead".to_owned())
        );
    }

    #[test]
    fn the_mim_inner_budget_subtracts_the_headers_and_the_masque_overhead() {
        let v4: SocketAddr = "192.0.2.9:443".parse().expect("an IPv4 edge");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("an IPv6 edge");
        assert_eq!(mim_inner_datagram(1280, v4), Ok(1252));
        assert_eq!(mim_inner_datagram(1280, v6), Ok(1232));
        assert_eq!(mim_inner_datagram(1400, v4), Ok(1350));
        assert_eq!(
            mim_inner_datagram(1200, v4),
            Err("warp mim: outer MTU 1200 leaves less than the inner hop's 1200-byte datagram budget".to_owned())
        );
        assert_eq!(mim_inner_mtu(1252), 1182);
        assert_eq!(mim_inner_mtu(1200), 1130);
        assert_eq!(mim_inner_mtu(600), MIM_MIN_MTU);
    }

    #[test]
    fn the_mim_inner_identity_derives_beside_the_masque_one() {
        let mut spec = sample_spec();
        spec.mode = Mode::Mim;
        spec.identity_file = Some(PathBuf::from("/tmp/warp-identity.json"));
        assert_eq!(
            spec.mim_path().expect("the inner path"),
            PathBuf::from("/tmp/warp-identity-masque-secondary.json")
        );
    }

    #[test]
    fn the_mim_inner_outbound_targets_the_forwarder_inside_the_outer_tunnel() {
        let identity = Identity {
            device_id: "mim".to_owned(),
            token: String::new(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [0; 3],
            },
            masque: Some(MasqueIdentity {
                private: vec![1; 32],
                server: vec![2; 33],
                addresses: vec!["10.14.0.2".parse().expect("an address")],
            }),
        };
        let spec = WarpSpec::for_command(Mode::Mim, None, None);
        let local: SocketAddr = "127.0.0.1:5000".parse().expect("the forwarder");
        let outbound = mim_outbound(&identity, &spec, local, 1182, 1252).expect("the inner hop");
        let mut text = String::new();
        crate::json::write(&outbound, &mut text);
        assert!(text.contains(r#""address":"127.0.0.1""#));
        assert!(text.contains(r#""port":5000"#));
        assert!(text.contains(r#""mtu":1182"#));
        assert!(text.contains(r#""maxDatagram":1252"#));
    }

    #[test]
    fn the_mim_inner_outbound_parses_back_into_its_budget() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let identity = Identity {
            device_id: "mim".to_owned(),
            token: String::new(),
            wireguard: WireGuardIdentity {
                private: [7u8; 32],
                peer: [8u8; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: Vec::new(),
                reserved: [0; 3],
            },
            masque: Some(MasqueIdentity {
                private: key.serialize_der(),
                server: decode_pem(&key.public_key_pem()).expect("the server key"),
                addresses: vec!["10.14.0.2".parse().expect("an address")],
            }),
        };
        let spec = WarpSpec::for_command(Mode::Mim, None, None);
        let local: SocketAddr = "127.0.0.1:5000".parse().expect("the forwarder");
        let outbound = mim_outbound(&identity, &spec, local, 1182, 1252).expect("the inner hop");
        let budgets = crate::masque::parsed_budgets(&outbound).expect("the emitted outbound");
        assert_eq!(budgets, (1182, 1252));
    }

    #[test]
    fn a_second_quarantine_keeps_the_first_damaged_identity() {
        let dir =
            std::env::temp_dir().join(format!("ferrox-warp-quarantine-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("warp-identity.json");
        std::fs::write(&path, b"first").expect("a damaged identity");
        quarantine(&path);
        assert!(!path.exists(), "the bad file is moved aside");
        std::fs::write(&path, b"second").expect("a second damaged identity");
        quarantine(&path);
        assert_eq!(
            std::fs::read(dir.join("warp-identity.json.corrupt")).expect("the first file"),
            b"first"
        );
        assert_eq!(
            std::fs::read(dir.join("warp-identity.json.corrupt.1")).expect("the second file"),
            b"second"
        );
        std::fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    }

    fn freedom_outbound(redirect: Option<&str>) -> crate::proxy::Outbound {
        let settings = match redirect {
            Some(redirect) => format!(r#"{{"redirect":"{redirect}"}}"#),
            None => "{}".to_owned(),
        };
        let root = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"protocol":"freedom","settings":{settings}}}]}}"#
        ))
        .expect("a freedom outbound");
        crate::proxy::Outbound::Freedom(Arc::new(
            crate::proxy::find_freedom_outbound(&root)
                .expect("the outbound reads")
                .expect("a freedom outbound"),
        ))
    }

    /// One MASQUE edge with a `WireGuard` peer behind it, driven until the inner handshake carries
    /// nine bytes back. The runner owns the deadline so a Windows loopback reset can be retried
    /// with a fresh lane instead of hanging the test on a single shot.
    fn wireguard_rides_inside_masque_attempt(
        client_private: [u8; 32],
        allowed_public: [u8; 32],
        timeout: Duration,
    ) -> std::io::Result<()> {
        use std::net::{TcpListener, TcpStream};

        use ferrox_core::foxy::account::hex_encode;
        use ferrox_core::wireguard::device::public_key;

        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("echo address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let mut seen = 0;
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
                seen += n;
                if seen >= 9 {
                    return;
                }
            }
        });

        let server_private = [0x22; 32];
        let server_public = public_key(&server_private);
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex_encode(&server_private),
            hex_encode(&allowed_public)
        );
        let wireguard_inbound = crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#))
            .expect("a wireguard inbound");
        let wireguard_port =
            crate::wg::serve_inbound(&wireguard_inbound, &freedom_outbound(None), "127.0.0.1:0")
                .expect("the wireguard server serves");

        let masque_inbound = crate::json::parse(
            r#"{"settings":{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]},"streamSettings":{"network":"masque","security":"none"}}"#,
        )
        .expect("a masque inbound");
        let redirect = format!("127.0.0.1:{wireguard_port}");
        let masque_port = crate::masque::serve_inbound(
            &masque_inbound,
            &freedom_outbound(Some(&redirect)),
            "127.0.0.1:0",
        )
        .expect("the masque server serves");

        let outer_outbound = crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{masque_port}}},"streamSettings":{{"network":"masque","security":"none","masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound");
        let outer = crate::masque::MasqueOut::new(&outer_outbound).expect("the outer tunnel");

        let inner_identity = Identity {
            device_id: "gool".to_owned(),
            token: String::new(),
            wireguard: WireGuardIdentity {
                private: client_private,
                peer: server_public,
                endpoint: "192.0.2.9:2408".parse().expect("the inner endpoint"),
                addresses: vec!["10.0.0.2".parse().expect("the inner address")],
                reserved: [0; 3],
            },
            masque: None,
        };
        let spec = WarpSpec::for_command(Mode::Gool, None, None);
        let remote: SocketAddr = "192.0.2.9:2408".parse().expect("the inner peer");
        let gool = GoolOut::new(outer, &inner_identity, &spec, remote).expect("gool builds");

        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun =
            TcpStream::connect(listener.local_addr().expect("pair address")).expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(timeout))?;
        gool.inner.serve_tcp(
            crate::conn::Connection::from(tun),
            &crate::proxy::Destination::Address(echo_address),
            b"head",
        );
        app.write_all(b"hello")?;
        let mut answer = [0u8; 9];
        app.read_exact(&mut answer)?;
        assert_eq!(&answer, b"headhello");
        Ok(())
    }

    fn tls_masque_inbound(settings: &str) -> crate::json::Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let lines = |pem: &str| {
            pem.trim_end()
                .lines()
                .map(|line| format!("\"{line}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let certificate = lines(&minted.cert.pem());
        let key = lines(&minted.signing_key.serialize_pem());
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{certificate}],"key":[{key}]}}]}}}}}}"#
        ))
        .expect("a masque inbound")
    }

    fn tls_masque_outbound(port: u16) -> crate::json::Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port}}},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    #[test]
    fn masque_rides_inside_masque() {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};

        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("echo address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let mut seen = 0;
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
                seen += n;
                if seen >= 9 {
                    return;
                }
            }
        });

        let inner_inbound = tls_masque_inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.15.0.1/24"]}"#,
        );
        let inner_port =
            crate::masque::serve_inbound(&inner_inbound, &freedom_outbound(None), "127.0.0.1:0")
                .expect("the inner masque server serves");
        let outer_inbound = tls_masque_inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        );
        let redirect = format!("127.0.0.1:{inner_port}");
        let outer_port = crate::masque::serve_inbound(
            &outer_inbound,
            &freedom_outbound(Some(&redirect)),
            "127.0.0.1:0",
        )
        .expect("the outer masque server serves");

        let outer = crate::masque::MasqueOut::new(&tls_masque_outbound(outer_port))
            .expect("the outer tunnel");
        let outer = Arc::new(outer);
        let remote: SocketAddr = format!("127.0.0.1:{inner_port}")
            .parse()
            .expect("the inner peer");
        let forwarder = outer.udp_forwarder(remote).expect("the forwarder");
        let inner = crate::masque::MasqueOut::new(&tls_masque_outbound(forwarder.local.port()))
            .expect("the inner tunnel");
        let mim = MimOut {
            outer,
            inner: Arc::new(inner),
            _forwarder: forwarder,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun =
            TcpStream::connect(listener.local_addr().expect("pair address")).expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(120)))
            .expect("timeout");
        mim.inner.serve_tcp(
            crate::conn::Connection::from(tun),
            &crate::proxy::Destination::Address(echo_address),
            b"head",
        );
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 9];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"headhello");
    }

    #[test]
    fn wireguard_rides_inside_masque() {
        use ferrox_core::wireguard::device::public_key;
        if !crate::conn::in_a_quiet_process("warp::tests::wireguard_rides_inside_masque") {
            return;
        }

        let client_private = [0x11; 32];
        let allowed = public_key(&client_private);
        let deadline = Duration::from_secs(60);
        let started = Instant::now();
        let mut last = None;
        while started.elapsed() < deadline {
            match wireguard_rides_inside_masque_attempt(
                client_private,
                allowed,
                Duration::from_secs(20),
            ) {
                Ok(()) => return,
                Err(error) => last = Some(error),
            }
        }
        panic!("the inner handshake did not complete over MASQUE within {deadline:?}: {last:?}");
    }

    /// The retry must not make the assertion vacuous: a peer the server does not know rides the
    /// lane's whole read deadline without an answer, so only a timeout counts as its rejection.
    #[test]
    fn a_broken_inner_handshake_never_completes_over_masque() {
        use ferrox_core::wireguard::device::public_key;

        let error = wireguard_rides_inside_masque_attempt(
            [0x33; 32],
            public_key(&[0x11; 32]),
            Duration::from_secs(5),
        )
        .expect_err("an unregistered inner peer completed the MASQUE tunnel");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "the unknown peer is dropped after the lane carried its handshake, not refused by a dead lane: {error}"
        );
    }

    /// One `WireGuard` edge with another `WireGuard` peer behind it, driven until the inner
    /// handshake carries nine bytes back; the runner retries it on a fresh lane.
    #[allow(clippy::too_many_lines)]
    fn wireguard_rides_inside_wireguard_attempt(overall: Instant) -> std::io::Result<()> {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        use ferrox_core::foxy::account::hex_encode;
        use ferrox_core::wireguard::device::public_key;

        struct EchoWorker {
            stop: Arc<AtomicBool>,
            handle: Option<std::thread::JoinHandle<()>>,
        }

        impl Drop for EchoWorker {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
        }

        let deadline = (Instant::now() + Duration::from_secs(20)).min(overall);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the attempt began after its deadline",
            ));
        }

        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        echo.set_nonblocking(true).expect("nonblocking echo");
        let echo_address = echo.local_addr().expect("echo address");
        crate::proxy::echo_trace("wiw: echo bound");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                match echo.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                        let mut buf = [0u8; 1024];
                        let mut seen = 0;
                        loop {
                            if worker_stop.load(Ordering::Relaxed) {
                                return;
                            }
                            match stream.read(&mut buf) {
                                Ok(0) => return,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                    seen += n;
                                    if seen >= 9 {
                                        return;
                                    }
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => return,
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        let _echo = EchoWorker {
            stop,
            handle: Some(worker),
        };

        let outer_client_private = [0x11; 32];
        let outer_server_private = [0x22; 32];
        let inner_client_private = [0x33; 32];
        let inner_server_private = [0x44; 32];
        let outer_client_public = public_key(&outer_client_private);
        let outer_server_public = public_key(&outer_server_private);
        let inner_client_public = public_key(&inner_client_private);
        let inner_server_public = public_key(&inner_server_private);

        let inner_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.1.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.1.0.2/32"]}}}}]}}"#,
            hex_encode(&inner_server_private),
            hex_encode(&inner_client_public)
        );
        let inner_inbound = crate::json::parse(&format!(r#"{{"settings":{inner_settings}}}"#))
            .expect("an inner wireguard inbound");
        let inner_port =
            crate::wg::serve_inbound(&inner_inbound, &freedom_outbound(None), "127.0.0.1:0")
                .expect("the inner wireguard server serves");
        crate::proxy::echo_trace("wiw: inner inbound");

        let outer_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex_encode(&outer_server_private),
            hex_encode(&outer_client_public)
        );
        let outer_inbound = crate::json::parse(&format!(r#"{{"settings":{outer_settings}}}"#))
            .expect("an outer wireguard inbound");
        let redirect = format!("127.0.0.1:{inner_port}");
        let outer_port = crate::wg::serve_inbound(
            &outer_inbound,
            &freedom_outbound(Some(&redirect)),
            "127.0.0.1:0",
        )
        .expect("the outer wireguard server serves");
        crate::proxy::echo_trace("wiw: outer inbound");

        let outer_client = crate::json::parse(&format!(
            r#"{{"secretKey":"{}","address":["10.0.0.2"],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{outer_port}"}}],"noKernelTun":true}}"#,
            hex_encode(&outer_client_private),
            hex_encode(&outer_server_public)
        ))
        .expect("an outer wireguard outbound");
        let config =
            crate::wireguard::DeviceConfig::from_json(&outer_client).expect("the outer config");
        let outer = crate::wg::WireGuardOut::new(config).expect("the outer tunnel");
        crate::proxy::echo_trace("wiw: outer tunnel");

        let inner_identity = Identity {
            device_id: "wiw".to_owned(),
            token: String::new(),
            wireguard: WireGuardIdentity {
                private: inner_client_private,
                peer: inner_server_public,
                endpoint: "192.0.2.9:2408".parse().expect("the inner endpoint"),
                addresses: vec!["10.1.0.2".parse().expect("the inner address")],
                reserved: [0; 3],
            },
            masque: None,
        };
        let spec = WarpSpec::for_command(Mode::GoolClassic, None, None);
        let remote: SocketAddr = format!("127.0.0.1:{inner_port}")
            .parse()
            .expect("the inner peer");
        let classic = GoolClassicOut::new(outer, &inner_identity, &spec, remote)
            .expect("the classic chain builds");
        crate::proxy::echo_trace("wiw: classic chain");

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the attempt deadline passed before the pair",
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        listener.set_nonblocking(true).expect("nonblocking pair");
        let tun =
            TcpStream::connect_timeout(&listener.local_addr().expect("pair address"), remaining)?;
        let (mut app, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "no pair before the attempt deadline",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        };
        app.set_nonblocking(false)?;
        crate::proxy::echo_trace("wiw: pair");
        classic.inner.serve_tcp(
            crate::conn::Connection::from(tun),
            &crate::proxy::Destination::Address(echo_address),
            b"head",
        );
        crate::proxy::echo_trace("wiw: serving");
        // Resend the trigger only after a read timeout, within the same budget, so a slow inner handshake does not fail the test.
        let mut answer = Vec::with_capacity(9);
        let mut found = [0u8; 9];
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no echo before the handshake budget",
            ));
        }
        app.set_write_timeout(Some(
            remaining
                .min(Duration::from_secs(5))
                .max(Duration::from_millis(1)),
        ))?;
        app.set_read_timeout(Some(
            remaining
                .min(Duration::from_millis(200))
                .max(Duration::from_millis(1)),
        ))?;
        app.write_all(b"hello")?;
        loop {
            match app.read(&mut found) {
                Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                Ok(n) => answer.extend_from_slice(&found[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "no echo before the handshake budget",
                        ));
                    }
                    app.set_write_timeout(Some(
                        remaining
                            .min(Duration::from_secs(5))
                            .max(Duration::from_millis(1)),
                    ))?;
                    app.set_read_timeout(Some(
                        remaining
                            .min(Duration::from_millis(200))
                            .max(Duration::from_millis(1)),
                    ))?;
                    app.write_all(b"hello")?;
                }
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no echo before the handshake budget",
                ));
            }
            if answer.len() >= 9 {
                break;
            }
        }
        crate::proxy::echo_trace("wiw: answer");
        assert_eq!(&answer[..9], b"headhello");
        Ok(())
    }

    #[test]
    fn wireguard_rides_inside_wireguard() {
        if !crate::conn::in_a_quiet_process("warp::tests::wireguard_rides_inside_wireguard") {
            return;
        }
        let budget = Duration::from_secs(60);
        let deadline = Instant::now() + budget;
        let mut last = None;
        while Instant::now() < deadline {
            crate::proxy::echo_trace("wiw: attempt");
            match wireguard_rides_inside_wireguard_attempt(deadline) {
                Ok(()) if Instant::now() < deadline => return,
                Ok(()) => {
                    last = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the inner handshake finished after the budget",
                    ));
                }
                Err(error) => last = Some(error),
            }
        }
        panic!("the inner handshake did not complete over WireGuard within {budget:?}: {last:?}");
    }

    #[cfg(unix)]
    #[test]
    fn saving_over_a_loose_identity_locks_it_to_the_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("ferrox-warp-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("warp-identity.json");
        std::fs::write(&path, b"loose").expect("a pre-existing identity");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("a world-readable identity");
        let identity = Identity {
            device_id: "a-device".to_owned(),
            token: "a-token".to_owned(),
            wireguard: WireGuardIdentity {
                private: [1; 32],
                peer: [2; 32],
                endpoint: "192.0.2.1:2408".parse().expect("an endpoint"),
                addresses: vec!["172.16.0.2".parse().expect("an address")],
                reserved: [0, 0, 0],
            },
            masque: Some(MasqueIdentity {
                private: vec![3; 32],
                server: vec![4; 32],
                addresses: vec!["172.16.0.2".parse().expect("an address")],
            }),
        };
        identity.save(&path).expect("the identity is saved");
        let mode = std::fs::metadata(&path)
            .expect("the saved identity")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the keys are not readable by anyone else");
        assert_eq!(Identity::load(&path).expect("the saved identity"), identity);
        std::fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    }

    #[test]
    fn scan_settings_take_the_reference_names_and_off() {
        assert_eq!(scan_mode("stealth"), Some(ScanMode::Verified));
        assert_eq!(scan_mode("guaranteed"), Some(ScanMode::Ironclad));
        assert_eq!(scan_mode("off"), None);
        assert_eq!(scan_mode("typo"), Some(ScanMode::Balanced));
    }

    #[test]
    fn an_http_status_line_is_read_not_guessed() {
        assert_eq!(http_status_code("HTTP/1.1 204 No Content"), Some(204));
        assert_eq!(http_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(http_status_code("204"), None);
        assert_eq!(http_status_code("GET / HTTP/1.1"), None);
    }

    #[test]
    fn the_last_edge_sits_beside_the_identity_unless_named() {
        let mut spec = sample_spec();
        spec.identity_file = Some(PathBuf::from("/tmp/warp-identity.json"));
        assert_eq!(
            spec.last_edge_path(),
            PathBuf::from("/tmp/warp-identity.lastconn.json")
        );
        spec.last_edge = Some(PathBuf::from("/tmp/chosen.json"));
        assert_eq!(spec.last_edge_path(), PathBuf::from("/tmp/chosen.json"));
    }

    #[test]
    fn a_forced_peer_skips_the_sweep_on_both_halves() {
        let mut identity = sample_identity();
        let mut spec = sample_spec();
        spec.wg_peer = Some("192.0.2.8:2408".parse().expect("a WG peer"));
        spec.peer = Some("192.0.2.9:443".parse().expect("a MASQUE peer"));
        resolve_edges(&mut identity, &mut spec).expect("forced peers resolve");
        assert_eq!(
            identity.wireguard.endpoint,
            "192.0.2.8:2408".parse().expect("the WG peer")
        );
        assert_eq!(spec.masque_address, "192.0.2.9");
        assert_eq!(spec.masque_port, 443);
    }
}

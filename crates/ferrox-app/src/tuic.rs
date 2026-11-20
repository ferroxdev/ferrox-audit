//! TUIC v5 over QUIC: authentication, CONNECT streams, and PACKET datagrams.

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{self, Destination};
use crate::quic::{self, Datagram, QuicStream};
use ferrox_core::tls::Anchors;
use ferrox_core::tuic as wire;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCID_LEN: usize = 16;
const HEARTBEAT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
const UDP_IDLE: Duration = Duration::from_secs(300);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);
const MAX_REASSEMBLIES: usize = 64;
const MAX_REASSEMBLIES_PER_ASSOC: usize = 8;
const MAX_PACKET_PAYLOAD: usize = 65_535;
const MAX_REASSEMBLY_BYTES: usize = MAX_REASSEMBLIES * MAX_PACKET_PAYLOAD;
/// The largest frame a PACKET may carry, header included: the payload limit, the ten-byte packet
/// header, and the first fragment's address (a type byte, a length byte, the name, and a port).
const MAX_UNI_COMMAND: usize = MAX_PACKET_PAYLOAD + 10 + wire::MAX_ADDRESS + 2 + 2;
const MAX_SESSIONS: usize = 1024;
const MAX_PENDING: usize = 64;
const MAX_CLIENT_REPLIES: usize = 64;
const MAX_PREAUTH_COMMANDS: usize = 16;
const MAX_PREAUTH_BYTES: usize = 64 * 1024;
const RETRY_TOKEN_TTL: Duration = Duration::from_secs(60);
const RETRY_TOKEN_TAG: usize = 32;
const MAX_ASSOCIATIONS_PER_SESSION: usize = 256;
const MAX_UDP_SOCKETS: usize = 2048;
const MAX_RESOLVING_PER_SESSION: usize = 32;
const MAX_RESOLVE_PAYLOADS: usize = 4;
const RESOLVE_QUEUE: usize = 256;
const RESOLVE_WORKERS: usize = 4;
const UDP_BUFFER: usize = 65_535;
const UDP_PACKETS_PER_SWEEP: usize = 256;
const UDP_PACKETS_PER_ASSOC: usize = 32;
const DGRAM_SEND_QUEUE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMode {
    Native,
    Quic,
}

fn quiche_cc(name: &str) -> &str {
    if name == "new_reno" {
        "reno"
    } else {
        name
    }
}

#[derive(Clone)]
struct User {
    uuid: [u8; 16],
    password: String,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("uuid", &self.uuid)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub(crate) struct TuicOut {
    address: String,
    port: u16,
    host: String,
    uuid: [u8; 16],
    password: String,
    mode: RelayMode,
    zero_rtt: bool,
    cc: Option<String>,
    roots: Option<Anchors>,
    cert_pins: Arc<[[u8; 32]]>,
    insecure: bool,
    heartbeat: Duration,
    lane: Mutex<Option<Arc<Lane>>>,
    session: Arc<Mutex<Option<Vec<u8>>>>,
}

impl std::fmt::Debug for TuicOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicOut")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("host", &self.host)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

struct Lane {
    conn: Arc<Mutex<quiche::Connection>>,
    sock: Arc<Datagram>,
    local: SocketAddr,
    next_bidi: Mutex<u64>,
    next_uni: AtomicU64,
    next_assoc: AtomicU16,
    stop: Arc<AtomicBool>,
    sinks: Mutex<Vec<Arc<UdpSink>>>,
    pending: Mutex<Vec<Pending>>,
    session: Arc<Mutex<Option<Vec<u8>>>>,
    heartbeat: thread::Thread,
    auth: Auth,
    authed: AtomicBool,
    early_since: Option<Instant>,
    establish_by: Option<Instant>,
}

fn lane_established(conn: &quiche::Connection, lane: &Lane) -> bool {
    if conn.is_closed() {
        return false;
    }
    if conn.is_established() {
        return true;
    }
    let Some(since) = lane.early_since else {
        return true;
    };
    Instant::now() < lane.establish_by.unwrap_or(since + quic::HANDSHAKE_TIMEOUT)
        && !(since.elapsed() >= quic::SILENT_HANDSHAKE && conn.stats().recv == 0)
}

struct Auth {
    uuid: [u8; 16],
    password: String,
    frame: OnceLock<Vec<u8>>,
    sent: AtomicUsize,
}

impl Lane {
    /// Finish the handshake once: the exporter token, then resumption. An early lane calls this
    /// from its driver after the flight lands; a cold lane calls it before it is returned, so a
    /// caller never writes into a connection whose trust is still unread.
    fn finish_handshake(&self) -> bool {
        if self.authed.load(Ordering::Relaxed) {
            return true;
        }
        let Ok(mut conn) = self.conn.lock() else {
            return false;
        };
        if !conn.is_established() {
            return !conn.is_closed();
        }
        if self.auth.frame.get().is_none() {
            let Some(token) =
                export_token(&mut conn, &self.auth.uuid, self.auth.password.as_bytes())
            else {
                let _ = conn.close(false, 0, b"authentication");
                quic::flush_egress(&mut conn, &self.sock);
                return false;
            };
            let mut auth = Vec::with_capacity(wire::AUTH_LEN);
            wire::encode_auth(&self.auth.uuid, &token, &mut auth);
            let _ = self.auth.frame.set(auth);
        }
        let Some(auth) = self.auth.frame.get() else {
            return false;
        };
        let mut at = self.auth.sent.load(Ordering::Relaxed);
        while at < auth.len() {
            match conn.stream_send(2, &auth[at..], false) {
                Ok(written) if written > 0 => {
                    at += written;
                    self.auth.sent.store(at, Ordering::Relaxed);
                }
                Ok(_) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                    quic::flush_egress(&mut conn, &self.sock);
                    return !conn.is_closed();
                }
                Err(_) => {
                    let _ = conn.close(false, 0, b"authentication");
                    quic::flush_egress(&mut conn, &self.sock);
                    return false;
                }
            }
        }
        match conn.stream_send(2, &[], true) {
            Ok(_) => {}
            Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                quic::flush_egress(&mut conn, &self.sock);
                return !conn.is_closed();
            }
            Err(_) => {
                let _ = conn.close(false, 0, b"authentication");
                quic::flush_egress(&mut conn, &self.sock);
                return false;
            }
        }
        quic::flush_egress(&mut conn, &self.sock);
        remember_session(&conn, &self.session);
        self.authed.store(true, Ordering::Relaxed);
        true
    }
}

struct UdpSink {
    association: u16,
    reply: UdpSocket,
    source: Mutex<Option<SocketAddr>>,
    last: Mutex<Instant>,
}

struct Pending {
    id: Option<u64>,
    data: Vec<u8>,
    at: usize,
    finish: bool,
}

enum Sent {
    Done,
    Blocked,
    Failed,
}

struct Resolving {
    generation: u64,
    payloads: Vec<Vec<u8>>,
}

struct ResolveJob {
    association: u16,
    host: String,
    port: u16,
    payload: Vec<u8>,
    generation: u64,
    options: Option<Arc<crate::sockopt::SocketOptions>>,
    reply: Sender<ResolveDone>,
}

struct ResolveDone {
    association: u16,
    host: String,
    port: u16,
    target: Option<SocketAddr>,
    payload: Vec<u8>,
    generation: u64,
}

struct ResolverPool {
    jobs: SyncSender<ResolveJob>,
    workers: usize,
}

impl ResolverPool {
    fn get() -> &'static ResolverPool {
        static POOL: OnceLock<ResolverPool> = OnceLock::new();
        POOL.get_or_init(|| {
            let (jobs, pending) = std::sync::mpsc::sync_channel::<ResolveJob>(RESOLVE_QUEUE);
            let pending = Arc::new(Mutex::new(pending));
            let mut workers = 0;
            for index in 0..RESOLVE_WORKERS {
                let pending = Arc::clone(&pending);
                let spawned = thread::Builder::new()
                    .name(format!("tuic-resolve-{index}"))
                    .spawn(move || loop {
                        let job = match pending.lock() {
                            Ok(pending) => match pending.recv() {
                                Ok(job) => job,
                                Err(_) => return,
                            },
                            Err(_) => return,
                        };
                        let target = proxy::resolve_outbound_with(
                            job.options.as_deref(),
                            &job.host,
                            job.port,
                        );
                        let _ = job.reply.send(ResolveDone {
                            association: job.association,
                            host: job.host,
                            port: job.port,
                            target,
                            payload: job.payload,
                            generation: job.generation,
                        });
                    });
                if spawned.is_ok() {
                    workers += 1;
                }
            }
            ResolverPool { jobs, workers }
        })
    }

    fn submit(&self, job: ResolveJob) -> bool {
        if self.workers == 0 {
            return false;
        }
        match self.jobs.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.heartbeat.unpark();
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn.close(true, 0, b"closed");
            quic::flush_egress(&mut conn, &self.sock);
        }
    }
}

impl TuicOut {
    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        proxy::resolve_outbound(&self.address, self.port)
    }

    fn lane(&self) -> Option<Arc<Lane>> {
        let mut held = self.lane.lock().ok()?;
        if let Some(lane) = held.as_ref() {
            let live = !lane.stop.load(Ordering::Relaxed)
                && lane
                    .conn
                    .lock()
                    .is_ok_and(|conn| lane_established(&conn, lane));
            if live {
                return Some(Arc::clone(lane));
            }
            lane.stop.store(true, Ordering::Relaxed);
            if let Ok(mut conn) = lane.conn.lock() {
                if !conn.is_closed() {
                    let _ = conn.close(true, 0, b"handshake deadline");
                    quic::flush_egress(&mut conn, &lane.sock);
                }
            }
        }
        let lane = self.connect_lane()?;
        *held = Some(Arc::clone(&lane));
        Some(lane)
    }

    fn connect_lane(&self) -> Option<Arc<Lane>> {
        let options = proxy::dial_options();
        let (socket, peer, local) =
            if let Some(tag) = options.as_deref().and_then(|o| o.dialer_proxy()) {
                let options = options.as_deref()?;
                let peer = options.resolve_addr(&self.address, self.port)?;
                let (sock, stop) = proxy::dial_udp_through_proxy(peer, tag, options)?;
                let local = sock.local_addr().ok()?;
                (quic::Datagram::proxied(sock, peer, stop), peer, local)
            } else {
                let (sock, peer, local) = quic::udp_to_server_with_source(
                    &self.address,
                    self.port,
                    options.as_deref(),
                    proxy::flow_source().ok()?,
                )?;
                (quic::Datagram::plain(sock).with_gro(false), peer, local)
            };
        let socket = socket.with_options(options);
        let mut config = self.client_config()?;
        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some(&self.host), &cid, local, peer, &mut config).ok()?;
        if self.zero_rtt {
            if let Ok(session) = self.session.lock() {
                if let Some(blob) = session.as_deref() {
                    let _ = conn.set_session(blob);
                }
            }
        }
        quic::flush_egress(&mut conn, &socket);
        let early = self.zero_rtt && conn.is_in_early_data();
        if !early {
            quic::drive_handshake(&mut conn, &socket, local)?;
        }
        let socket = Arc::new(socket);
        let conn = Arc::new(Mutex::new(conn));
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = heartbeat(&conn, &socket, self.heartbeat, Arc::clone(&stop));
        let lane = Arc::new(Lane {
            conn,
            sock: socket,
            local,
            next_bidi: Mutex::new(0),
            next_uni: AtomicU64::new(6),
            next_assoc: AtomicU16::new(0),
            stop,
            sinks: Mutex::new(Vec::new()),
            pending: Mutex::new(Vec::new()),
            session: Arc::clone(&self.session),
            heartbeat,
            auth: Auth {
                uuid: self.uuid,
                password: self.password.clone(),
                frame: OnceLock::new(),
                sent: AtomicUsize::new(0),
            },
            authed: AtomicBool::new(false),
            early_since: early.then(Instant::now),
            establish_by: early.then(|| Instant::now() + quic::HANDSHAKE_TIMEOUT),
        });
        if !early && !lane.finish_handshake() {
            return None;
        }
        thread::spawn({
            let lane = Arc::downgrade(&lane);
            move || drive_client(&lane)
        });
        Some(lane)
    }

    fn client_config(&self) -> Option<quiche::Config> {
        let roots = self.roots.as_deref().unwrap_or(&[]);
        let mut config = if !self.cert_pins.is_empty() {
            let mut config = pinned_config(Arc::clone(&self.cert_pins), self.host.clone())?;
            config.set_application_protos(&[wire::ALPN]).ok()?;
            if let Some(name) = self.cc.as_deref() {
                config.set_cc_algorithm_name(name).ok()?;
            }
            config
        } else if self.insecure {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
            config.verify_peer(false);
            config.set_application_protos(&[wire::ALPN]).ok()?;
            if let Some(name) = self.cc.as_deref() {
                config.set_cc_algorithm_name(name).ok()?;
            }
            config
        } else {
            if roots.is_empty() {
                return None;
            }
            quic::quiche_config_alpn(roots, self.cc.as_deref(), &[wire::ALPN])?
        };
        quic::tune_transport(&mut config);
        config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
        if self.zero_rtt {
            config.enable_early_data();
        }
        Some(config)
    }

    pub(crate) fn dial(&self, client: &Connection, target: &Destination) {
        let Some(lane) = self.lane() else {
            return;
        };
        let (host, port): (Cow<'_, str>, u16) = match target {
            Destination::Name(host, port) => (Cow::Borrowed(host.as_str()), *port),
            Destination::Address(address) => (Cow::Owned(address.ip().to_string()), address.port()),
        };
        let mut header = Vec::with_capacity(host.len() + 5);
        if wire::encode_connect(host.as_ref(), port, &mut header).is_err() {
            return;
        }
        let deadline = Instant::now() + crate::budgets::dial();
        let Ok(mut next) = lane.next_bidi.lock() else {
            return;
        };
        let id = loop {
            if Instant::now() >= deadline {
                return;
            }
            let credit = match lane.conn.lock() {
                Ok(conn) if !conn.is_closed() => conn.peer_streams_left_bidi(),
                _ => return,
            };
            if credit > 0 {
                break *next;
            }
            thread::sleep(Duration::from_millis(5));
        };
        *next = next.wrapping_add(4);
        drop(next);
        let mut stream = QuicStream::new(
            Arc::clone(&lane.conn),
            Arc::clone(&lane.sock),
            id,
            proxy::flow_outbound_meter().unwrap_or_default(),
        )
        .with_stop(Arc::clone(&lane.stop));
        if stream.write_all(&header).is_err() {
            stream.close();
            return;
        }
        proxy::relay_quic_stream(client, stream, None);
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn serve_udp(&self, relay: &UdpSocket, associate: Option<&Connection>) {
        let Some(lane) = self.lane() else {
            return;
        };
        if let Some(associate) = associate {
            let _ = associate.set_read_timeout(Some(POLL));
        }
        let Ok(reply) = relay.try_clone() else {
            return;
        };
        let Ok(mut sinks) = lane.sinks.lock() else {
            return;
        };
        let mut tries = 0usize;
        let association = loop {
            let candidate = lane.next_assoc.fetch_add(1, Ordering::Relaxed);
            if !sinks.iter().any(|sink| sink.association == candidate) {
                break candidate;
            }
            tries += 1;
            if tries > usize::from(u16::MAX) {
                return;
            }
        };
        let sink = Arc::new(UdpSink {
            association,
            reply,
            source: Mutex::new(None),
            last: Mutex::new(Instant::now()),
        });
        sinks.push(Arc::clone(&sink));
        drop(sinks);
        let cancelled = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let watcher = associate.and_then(|associate| {
            let control = associate.try_clone().ok()?;
            let _ = control.set_read_timeout(Some(POLL));
            let cancelled = Arc::clone(&cancelled);
            let finished = Arc::clone(&finished);
            thread::Builder::new()
                .spawn(move || {
                    while !finished.load(Ordering::Relaxed) {
                        if proxy::peer_left(&control) {
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                })
                .ok()
        });
        let watch_started = watcher.is_some();
        let mut buf = vec![0u8; UDP_BUFFER];
        let mut packet = 0u16;
        let mut frame = Vec::new();
        let _ = relay.set_read_timeout(Some(POLL));
        loop {
            if lane.stop.load(Ordering::Relaxed) {
                break;
            }
            if cancelled.load(Ordering::Relaxed)
                || (!watch_started && associate.is_some_and(proxy::peer_left))
            {
                break;
            }
            match relay.recv_from(&mut buf) {
                Ok((n, client)) => {
                    let Some((destination, payload)) = proxy::parse_socks_udp_dest(&buf[..n])
                    else {
                        continue;
                    };
                    if let Ok(mut slot) = sink.source.lock() {
                        match *slot {
                            None => *slot = Some(client),
                            Some(pinned) if pinned != client => continue,
                            Some(_) => {}
                        }
                    } else {
                        break;
                    }
                    let Some((address, port)) = destination_wire(&destination) else {
                        continue;
                    };
                    packet = next_packet(packet);
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    if conn.is_closed() {
                        break;
                    }
                    let Ok(mut pending) = lane.pending.lock() else {
                        break;
                    };
                    let max = conn.dgram_max_writable_len();
                    send_message(
                        &mut conn,
                        &lane.sock,
                        self.mode,
                        association,
                        packet,
                        address,
                        port,
                        payload,
                        max,
                        &mut pending,
                        &mut frame,
                    );
                    flush_pending(&mut conn, &lane.sock, &mut pending, &lane.next_uni);
                    touch(&sink.last);
                }
                Err(error) if is_wait(&error) => {
                    if idle(&sink.last) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if let Ok(mut sinks) = lane.sinks.lock() {
            sinks.retain(|held| !Arc::ptr_eq(held, &sink));
        }
        finished.store(true, Ordering::Relaxed);
        if let Some(watcher) = watcher {
            let _ = watcher.join();
        }
        if let Ok(mut conn) = lane.conn.lock() {
            if !conn.is_closed() {
                if let Ok(mut pending) = lane.pending.lock() {
                    queue_dissociate(&mut pending, association);
                    flush_pending(&mut conn, &lane.sock, &mut pending, &lane.next_uni);
                }
            }
        };
    }
}

fn destination_wire(destination: &Destination) -> Option<(wire::Address<'_>, u16)> {
    match destination {
        Destination::Name(host, port) => Some((wire::Address::of(host)?, *port)),
        Destination::Address(address) => {
            let port = address.port();
            match address.ip() {
                IpAddr::V4(ip) => Some((wire::Address::V4(ip.octets()), port)),
                IpAddr::V6(ip) => Some((wire::Address::V6(ip.octets()), port)),
            }
        }
    }
}

fn destination_of(address: wire::Address<'_>, port: u16) -> Destination {
    match address {
        wire::Address::V4(octets) => {
            Destination::Address(SocketAddr::new(IpAddr::V4(octets.into()), port))
        }
        wire::Address::V6(octets) => {
            Destination::Address(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        wire::Address::Name(bytes) => {
            Destination::Name(String::from_utf8_lossy(bytes).into_owned(), port)
        }
    }
}

fn next_packet(packet: u16) -> u16 {
    let next = packet.wrapping_add(1);
    if next == u16::MAX {
        0
    } else {
        next
    }
}

/// A pin is the handshake's own verifier, so a chain that does not match never reaches the
/// exporter key or the authentication frame. The callback receives the DER the edge sent, and
/// the same `verify_cert_pinned` rule the other TLS lanes use decides it.
fn pinned_config(pins: Arc<[[u8; 32]]>, name: String) -> Option<quiche::Config> {
    use boring::ssl::{SslAlert, SslMethod, SslVerifyError, SslVerifyMode};
    let mut builder = boring::ssl::SslContextBuilder::new(SslMethod::tls()).ok()?;
    builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let Some(chain) = ssl.peer_cert_chain() else {
            return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
        };
        let mut chain_der = Vec::with_capacity(chain.len());
        for cert in chain {
            let Ok(der) = cert.to_der() else {
                return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
            };
            chain_der.push(der);
        }
        if ferrox_core::tls::verify_cert_pinned(&chain_der, &pins, &name) {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(SslAlert::UNKNOWN_CA))
        }
    });
    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).ok()
}

fn remember_session(conn: &quiche::Connection, session: &Mutex<Option<Vec<u8>>>) -> bool {
    let Some(blob) = conn.session() else {
        return false;
    };
    if let Ok(mut held) = session.lock() {
        *held = Some(blob.to_vec());
    }
    true
}

fn heartbeat(
    conn: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<Datagram>,
    every: Duration,
    stop: Arc<AtomicBool>,
) -> thread::Thread {
    let conn = Arc::clone(conn);
    let sock = Arc::clone(sock);
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            thread::park_timeout(every.max(POLL));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut conn) = conn.lock() else {
                break;
            };
            if conn.is_closed() {
                break;
            }
            let _ = conn.dgram_send(&[wire::VERSION, wire::HEARTBEAT]);
            quic::flush_egress(&mut conn, &sock);
        }
    });
    handle.thread().clone()
}

fn export_token(
    conn: &mut quiche::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Option<[u8; wire::TOKEN_LEN]> {
    use foreign_types::ForeignTypeRef as _;
    let mut token = [0u8; wire::TOKEN_LEN];
    let ssl = <quiche::Connection as AsMut<boring::ssl::SslRef>>::as_mut(conn);
    let ok = unsafe {
        boring_sys::SSL_export_keying_material(
            ssl.as_ptr(),
            token.as_mut_ptr(),
            token.len(),
            uuid.as_ptr().cast(),
            uuid.len(),
            if password.is_empty() {
                std::ptr::null()
            } else {
                password.as_ptr()
            },
            password.len(),
            i32::from(!password.is_empty()),
        )
    };
    (ok == 1).then_some(token)
}

#[allow(clippy::too_many_arguments)]
fn send_message(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    mode: RelayMode,
    association: u16,
    packet: u16,
    address: wire::Address<'_>,
    port: u16,
    payload: &[u8],
    max: Option<usize>,
    pending: &mut Vec<Pending>,
    frame: &mut Vec<u8>,
) {
    let mut destination = [0u8; wire::MAX_ADDRESS + 4];
    let Some(destination_len) = wire::address_port_into(address, port, &mut destination) else {
        return;
    };
    let address = &destination[..destination_len];
    if mode == RelayMode::Quic {
        queue_stream(pending, association, packet, address, payload);
        return;
    }
    let Some(max) = max else {
        queue_stream(pending, association, packet, address, payload);
        return;
    };
    let Some(plan) = wire::fragment_plan(max, address.len(), payload.len()) else {
        queue_stream(pending, association, packet, address, payload);
        return;
    };
    let fragments = usize::from(plan.total);
    if conn.dgram_send_queue_len() + fragments > DGRAM_SEND_QUEUE {
        quic::flush_egress(conn, sock);
        if conn.dgram_send_queue_len() + fragments > DGRAM_SEND_QUEUE {
            queue_stream(pending, association, packet, address, payload);
            return;
        }
    }
    frame.clear();
    if frame.capacity() < max {
        frame.reserve(max - frame.capacity());
    }
    let mut left = payload;
    for index in 0..plan.total {
        let take = left.len().min(if index == 0 {
            plan.first
        } else {
            plan.continuation
        });
        wire::encode_fragment(
            association,
            packet,
            plan.total,
            index,
            address,
            &left[..take],
            frame,
        );
        if conn.dgram_send(&frame[..]).is_err() {
            quic::flush_egress(conn, sock);
            if conn.dgram_send(&frame[..]).is_err() {
                break;
            }
        }
        left = &left[take..];
    }
}

fn queue_stream(
    pending: &mut Vec<Pending>,
    association: u16,
    packet: u16,
    address: &[u8],
    payload: &[u8],
) {
    if pending.len() >= MAX_PENDING {
        return;
    }
    let mut data = Vec::with_capacity(12 + address.len() + payload.len());
    wire::encode_fragment(association, packet, 1, 0, address, payload, &mut data);
    pending.push(Pending {
        id: None,
        data,
        at: 0,
        finish: true,
    });
}

fn queue_dissociate(pending: &mut Vec<Pending>, association: u16) {
    if pending.len() >= MAX_PENDING {
        return;
    }
    let mut data = Vec::with_capacity(4);
    wire::encode_dissociate(association, &mut data);
    pending.push(Pending {
        id: None,
        data,
        at: 0,
        finish: true,
    });
}

fn flush_one(conn: &mut quiche::Connection, frame: &mut Pending, next_uni: &AtomicU64) -> Sent {
    if frame.id.is_none() {
        if conn.is_closed() {
            return Sent::Failed;
        }
        if conn.peer_streams_left_uni() == 0 {
            return Sent::Blocked;
        }
        let id = next_uni.load(Ordering::Relaxed);
        match conn.stream_send(id, &frame.data[frame.at..], false) {
            Ok(n) if n > 0 => {
                frame.id = Some(id);
                next_uni.store(id.wrapping_add(4), Ordering::Relaxed);
                frame.at += n;
            }
            Err(quiche::Error::Done) => {
                frame.id = Some(id);
                next_uni.store(id.wrapping_add(4), Ordering::Relaxed);
                return Sent::Blocked;
            }
            Err(quiche::Error::StreamLimit) => return Sent::Blocked,
            Ok(_) | Err(_) => return Sent::Failed,
        }
    }
    let Some(id) = frame.id else {
        return Sent::Blocked;
    };
    while frame.at < frame.data.len() {
        match conn.stream_send(id, &frame.data[frame.at..], false) {
            Ok(n) if n > 0 => frame.at += n,
            Ok(_) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                return Sent::Blocked;
            }
            Err(_) => return Sent::Failed,
        }
    }
    if frame.finish {
        match conn.stream_send(id, &[], true) {
            Ok(_) => Sent::Done,
            Err(quiche::Error::Done | quiche::Error::StreamLimit) => Sent::Blocked,
            Err(_) => Sent::Failed,
        }
    } else {
        Sent::Done
    }
}

fn flush_pending(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    pending: &mut Vec<Pending>,
    next_uni: &AtomicU64,
) {
    let mut index = 0;
    while index < pending.len() {
        match flush_one(conn, &mut pending[index], next_uni) {
            Sent::Done | Sent::Failed => {
                pending.swap_remove(index);
            }
            Sent::Blocked => index += 1,
        }
    }
    quic::flush_egress(conn, sock);
}

fn is_wait(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn service(conn: &mut quiche::Connection, lane: &Lane) -> bool {
    if conn
        .timeout_instant()
        .is_some_and(|at| at <= Instant::now())
    {
        conn.on_timeout();
    }
    flush_lane(lane, conn);
    !conn.is_closed()
}

fn reply_worker(weak: &std::sync::Weak<Lane>) -> std::sync::mpsc::SyncSender<Vec<u8>> {
    let (replies, backlog) = std::sync::mpsc::sync_channel::<Vec<u8>>(MAX_CLIENT_REPLIES);
    let worker = weak.clone();
    thread::spawn(move || {
        let mut reassembly = HashMap::new();
        let mut head = Vec::with_capacity(22);
        while let Ok(data) = backlog.recv() {
            let Some(owner) = worker.upgrade() else {
                break;
            };
            if owner.stop.load(Ordering::Relaxed) {
                break;
            }
            dispatch_client(&data, &owner, &mut reassembly, &mut head);
        }
    });
    replies
}

#[allow(clippy::too_many_lines)]
fn drive_client(weak: &std::sync::Weak<Lane>) {
    if weak.upgrade().is_none() {
        return;
    }
    let replies = reply_worker(weak);
    let mut buf = vec![0u8; 65535];
    let mut ids = Vec::new();
    let mut uni: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut batch = quic::Batch::new();
    while let Some(lane) = weak.upgrade() {
        if lane.stop.load(Ordering::Relaxed) {
            break;
        }
        if lane.sock.set_read_timeout(Some(POLL)).is_err() {
            break;
        }
        let alive = match quic::recv_batch(&lane.sock, &mut batch) {
            quic::Drain::Read => {
                let taken = batch.len();
                {
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    for at in 0..taken {
                        let Some((bytes, from)) = batch.at(at) else {
                            continue;
                        };
                        let _ = conn.recv(
                            bytes,
                            quiche::RecvInfo {
                                from,
                                to: lane.local,
                            },
                        );
                    }
                }
                lane.finish_handshake()
                    && match lane.conn.lock() {
                        Ok(mut conn) => {
                            client_turn(&mut conn, &lane, &mut buf, &replies, &mut uni, &mut ids)
                        }
                        Err(_) => false,
                    }
            }
            quic::Drain::Empty => {
                if !lane.finish_handshake() {
                    break;
                }
                let Ok(mut conn) = lane.conn.lock() else {
                    break;
                };
                service(&mut conn, &lane)
            }
            quic::Drain::Unbatchable => match lane.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    let _ = conn.recv(
                        &mut buf[..n],
                        quiche::RecvInfo {
                            from,
                            to: lane.local,
                        },
                    );
                    drop(conn);
                    lane.finish_handshake()
                        && match lane.conn.lock() {
                            Ok(mut conn) => client_turn(
                                &mut conn, &lane, &mut buf, &replies, &mut uni, &mut ids,
                            ),
                            Err(_) => false,
                        }
                }
                Err(error) if is_wait(&error) => {
                    if !lane.finish_handshake() {
                        break;
                    }
                    let Ok(mut conn) = lane.conn.lock() else {
                        break;
                    };
                    service(&mut conn, &lane)
                }
                Err(_) => break,
            },
            quic::Drain::Unreadable => break,
        };
        if !alive {
            break;
        }
    }
    if let Some(lane) = weak.upgrade() {
        lane.stop.store(true, Ordering::Relaxed);
        lane.heartbeat.unpark();
    }
}

/// The work one received batch owes: the datagrams it queued, the streams it made readable, and
/// the timers behind them. The lock, the readable sweep and the egress flush are each paid once
/// per batch instead of once per packet.
fn client_turn(
    conn: &mut quiche::Connection,
    lane: &Lane,
    buf: &mut [u8],
    replies: &std::sync::mpsc::SyncSender<Vec<u8>>,
    uni: &mut HashMap<u64, Vec<u8>>,
    ids: &mut Vec<u64>,
) -> bool {
    remember_session(conn, &lane.session);
    while let Ok(data) = conn.dgram_recv_buf() {
        let _ = replies.try_send(data);
    }
    ids.clear();
    ids.extend(conn.readable());
    for &id in ids.iter() {
        if id % 4 != 3 {
            continue;
        }
        let mut data = uni.remove(&id).unwrap_or_default();
        while let Ok((read, _)) = conn.stream_recv(id, buf) {
            if read == 0 {
                break;
            }
            if data.len() + read > MAX_UNI_COMMAND {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                break;
            }
            data.extend_from_slice(&buf[..read]);
        }
        if data.get(1) == Some(&wire::PACKET) {
            let mut at = 0usize;
            loop {
                match wire::parse_packet_prefix(&data[at..]) {
                    Ok((_, used)) => {
                        let _ = replies.try_send(data[at..at + used].to_vec());
                        at += used;
                    }
                    Err(wire::FrameError::Short) => break,
                    Err(_) => {
                        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                        data.clear();
                        at = 0;
                        break;
                    }
                }
            }
            if at > 0 {
                data.drain(..at);
            }
        }
        if !conn.stream_finished(id) && !data.is_empty() {
            uni.insert(id, data);
        }
    }
    service(conn, lane)
}

fn flush_lane(lane: &Lane, conn: &mut quiche::Connection) {
    if let Ok(mut pending) = lane.pending.lock() {
        flush_pending(conn, &lane.sock, &mut pending, &lane.next_uni);
    } else {
        quic::flush_egress(conn, &lane.sock);
    }
}

fn dispatch_client(
    data: &[u8],
    lane: &Lane,
    reassembly: &mut HashMap<(u16, u16), Parts>,
    head: &mut Vec<u8>,
) {
    let Ok(packet) = wire::parse_packet(data) else {
        return;
    };
    let Ok(sinks) = lane.sinks.lock() else {
        return;
    };
    for sink in sinks.iter() {
        if sink.association != packet.association {
            continue;
        }
        client_reply(
            &packet,
            reassembly,
            &sink.source,
            &sink.last,
            &sink.reply,
            head,
        );
    }
}

fn client_reply(
    packet: &wire::Packet<'_>,
    reassembly: &mut HashMap<(u16, u16), Parts>,
    source: &Mutex<Option<SocketAddr>>,
    last: &Mutex<Instant>,
    reply: &UdpSocket,
    head: &mut Vec<u8>,
) {
    let Some((destination, payload)) = take_packet(reassembly, packet) else {
        return;
    };
    let Some(source) = source.lock().ok().and_then(|slot| *slot) else {
        return;
    };
    let target = match destination {
        Destination::Address(target) => target,
        Destination::Name(host, port) => {
            let Some(target) = proxy::resolve_outbound(&host, port) else {
                return;
            };
            target
        }
    };
    let (head, payload) = proxy::socks_udp_parts(head, &target, &payload);
    if proxy::send_to_two(reply, head, payload, source).is_ok() {
        touch(last);
    }
}

fn touch(last: &Mutex<Instant>) {
    if let Ok(mut last) = last.lock() {
        *last = Instant::now();
    }
}

fn idle(last: &Mutex<Instant>) -> bool {
    last.lock().is_ok_and(|last| last.elapsed() >= UDP_IDLE)
}

fn take_packet<'a>(
    reassembly: &mut HashMap<(u16, u16), Parts>,
    packet: &wire::Packet<'a>,
) -> Option<(Destination, Cow<'a, [u8]>)> {
    let size = packet.payload.len();
    if packet.total == 1 {
        let (address, port) = packet.destination?;
        return Some((destination_of(address, port), Cow::Borrowed(packet.payload)));
    }
    if size > MAX_PACKET_PAYLOAD {
        return None;
    }
    let key = (packet.association, packet.packet);
    if reassembly
        .get(&key)
        .is_some_and(|entry| entry.at.elapsed() >= REASSEMBLY_TTL)
    {
        reassembly.remove(&key);
    }
    if !reassembly.contains_key(&key) {
        let mut per_assoc = 0usize;
        let mut retained = 0usize;
        for ((assoc, _), parts) in &*reassembly {
            per_assoc += usize::from(*assoc == packet.association);
            retained += parts.bytes;
        }
        if reassembly.len() >= MAX_REASSEMBLIES
            || per_assoc >= MAX_REASSEMBLIES_PER_ASSOC
            || retained.saturating_add(size) > MAX_REASSEMBLY_BYTES
        {
            return None;
        }
    }
    let bad = reassembly.get(&key).is_some_and(|entry| {
        entry.total != packet.total
            || entry.payload[usize::from(packet.index)].is_some()
            || entry.bytes.saturating_add(size) > MAX_PACKET_PAYLOAD
    });
    if bad {
        reassembly.remove(&key);
        return None;
    }
    let entry = reassembly.entry(key).or_insert_with(|| Parts {
        total: packet.total,
        address: None,
        payload: vec![None; usize::from(packet.total)],
        received: 0,
        bytes: 0,
        at: Instant::now(),
    });
    if let Some((address, port)) = packet.destination {
        entry.address = Some(destination_of(address, port));
    }
    entry.payload[usize::from(packet.index)] = Some(packet.payload.to_vec());
    entry.received += 1;
    entry.bytes += size;
    if entry.received != entry.total {
        return None;
    }
    let entry = reassembly.remove(&key)?;
    let destination = entry.address?;
    let mut payload = Vec::with_capacity(entry.bytes);
    for part in entry.payload {
        payload.extend_from_slice(part.as_deref()?);
    }
    Some((destination, Cow::Owned(payload)))
}

struct Parts {
    total: u8,
    address: Option<Destination>,
    payload: Vec<Option<Vec<u8>>>,
    received: u8,
    bytes: usize,
    at: Instant,
}

pub(crate) fn outbound(root: &Json) -> Result<Option<TuicOut>, String> {
    let Some(first) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|list| list.first())
    else {
        return Ok(None);
    };
    if first.get("protocol").and_then(Json::as_str) != Some("tuic") {
        return Ok(None);
    }
    let settings = first
        .get("settings")
        .ok_or("tuic outbound has no settings")?;
    let server = settings
        .get("servers")
        .and_then(Json::as_arr)
        .and_then(|servers| servers.first())
        .unwrap_or(settings);
    let field = |name: &str| server.get(name).or_else(|| settings.get(name));
    let address = field("address")
        .or_else(|| field("server"))
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("tuic outbound has no server address")?;
    let port = field("port")
        .or_else(|| field("server_port"))
        .and_then(Json::as_port)
        .ok_or("tuic outbound has no server port")?;
    let uuid = field("uuid")
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .ok_or("tuic outbound has no uuid")?;
    let password = field("password")
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("tuic outbound has no password")?;
    let tls = crate::config::outbound_tls(first, address)?;
    if field("udp_over_stream")
        .or_else(|| field("udpOverStream"))
        .is_some_and(|value| matches!(value, Json::Bool(true)))
    {
        return Err("tuic udp_over_stream is not carried".to_owned());
    }
    let mode = match field("udp_relay_mode")
        .or_else(|| field("udpRelayMode"))
        .and_then(Json::as_str)
    {
        Some("native") | None => RelayMode::Native,
        Some("quic") => RelayMode::Quic,
        Some(other) => return Err(format!("tuic udp_relay_mode `{other}` is not carried")),
    };
    let cc = field("congestion_control")
        .or_else(|| field("congestionControl"))
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .map(|name| quiche_cc(name).to_owned());
    if let Some(name) = cc.as_deref() {
        if !matches!(name, "cubic" | "reno" | "bbr") {
            return Err(format!("tuic congestion_control `{name}` is not carried"));
        }
    }
    let heartbeat = field("heartbeat")
        .or_else(|| field("heartbeat_interval"))
        .and_then(Json::as_u32)
        .filter(|seconds| *seconds > 0)
        .map_or(HEARTBEAT, |seconds| Duration::from_secs(u64::from(seconds)));
    Ok(Some(TuicOut {
        address: address.to_owned(),
        port,
        host: if tls.server_name.is_empty() {
            address.to_owned()
        } else {
            tls.server_name.clone()
        },
        uuid,
        password: password.to_owned(),
        mode,
        zero_rtt: bool_field(settings, "zero_rtt_handshake")
            || bool_field(settings, "zeroRttHandshake")
            || bool_field(server, "zero_rtt_handshake")
            || bool_field(server, "zeroRttHandshake"),
        cc,
        roots: Some(tls.roots.clone()),
        cert_pins: Arc::clone(&tls.cert_pins),
        insecure: tls.insecure,
        heartbeat,
        lane: Mutex::new(None),
        session: Arc::new(Mutex::new(None)),
    }))
}

fn bool_field(node: &Json, name: &str) -> bool {
    matches!(node.get(name), Some(Json::Bool(true)))
}

fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high = None;
    let mut digits = 0;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        digits += 1;
        if digits > 32 {
            return None;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(high) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (high << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    (digits == 32 && high.is_none()).then_some(out)
}

fn users(inbound: &Json) -> Vec<User> {
    let settings = inbound.get("settings");
    let mut users = Vec::new();
    if let Some(listed) = settings
        .and_then(|node| node.get("users").or_else(|| node.get("clients")))
        .and_then(Json::as_arr)
    {
        for user in listed {
            let Some(uuid) = user.get("uuid").and_then(Json::as_str).and_then(uuid_bytes) else {
                continue;
            };
            let Some(password) = user
                .get("password")
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            users.push(User {
                uuid,
                password: password.to_owned(),
            });
        }
    }
    if users.is_empty() {
        if let (Some(uuid), Some(password)) = (
            settings
                .and_then(|node| node.get("uuid"))
                .and_then(Json::as_str)
                .and_then(uuid_bytes),
            settings
                .and_then(|node| node.get("password"))
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty()),
        ) {
            users.push(User {
                uuid,
                password: password.to_owned(),
            });
        }
    }
    users
}

pub(crate) fn serve_inbound(
    address: &str,
    inbound: &Json,
    path: &str,
    freedom: bool,
    stop: Option<Arc<proxy::Stop>>,
) -> bool {
    let users = users(inbound);
    if users.is_empty() {
        eprintln!("tuic inbound in {path} names no user: serves nothing");
        return false;
    }
    let Some(stream) = inbound.get("streamSettings") else {
        eprintln!("tuic inbound in {path} carries no tls settings: serves nothing");
        return false;
    };
    if crate::config::stream_security(inbound) != "tls" {
        eprintln!("tuic inbound in {path} is not on tls: serves nothing");
        return false;
    }
    let Some(identity) = crate::config::tls_identity_from_settings(stream) else {
        eprintln!("unreadable tuic identity in {path}: serves nothing");
        return false;
    };
    let Ok(socket) = quic::bind_datagram_plain(address) else {
        eprintln!("tuic inbound in {path} cannot bind {address}: serves nothing");
        return false;
    };
    let Ok(local) = socket.local_addr() else {
        return false;
    };
    let Some(mut template) = quic::tls_config(&identity) else {
        eprintln!("tuic inbound in {path} cannot build its tls: serves nothing");
        return false;
    };
    if !quic::tune(&mut template, wire::ALPN) {
        return false;
    }
    let setting = |name: &str| {
        inbound
            .get("settings")
            .and_then(|node| node.get(name))
            .and_then(Json::as_u32)
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(u64::from(seconds)))
    };
    let heartbeat = setting("heartbeat").unwrap_or(HEARTBEAT);
    let auth_timeout = setting("auth_timeout").unwrap_or(AUTH_TIMEOUT);
    let udp_timeout = setting("udp_timeout").unwrap_or(UDP_IDLE);
    if let Some(name) = inbound
        .get("settings")
        .and_then(|node| {
            node.get("congestion_control")
                .or_else(|| node.get("congestionControl"))
        })
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
    {
        if !matches!(name, "cubic" | "new_reno" | "reno" | "bbr") {
            eprintln!("tuic congestion_control `{name}` is not carried");
            return false;
        }
        if template.set_cc_algorithm_name(quiche_cc(name)).is_err() {
            eprintln!("tuic congestion_control `{name}` is not carried");
            return false;
        }
    }
    template.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
    if inbound.get("settings").is_some_and(|node| {
        bool_field(node, "zero_rtt_handshake") || bool_field(node, "zeroRttHandshake")
    }) {
        template.enable_early_data();
    }
    let signal = stop.as_ref().map(|stop| stop.shared());
    let meter = proxy::inbound_meter(inbound);
    thread::spawn(move || {
        run(
            Arc::new(Datagram::plain(socket).with_gro(false)),
            local,
            users,
            template,
            freedom,
            heartbeat,
            auth_timeout,
            udp_timeout,
            meter,
            signal,
        );
        if let Some(stop) = stop {
            stop.mark_closed();
        }
    });
    true
}

#[allow(clippy::too_many_arguments)]
fn run(
    sock: Arc<Datagram>,
    local: SocketAddr,
    users: Vec<User>,
    template: quiche::Config,
    freedom: bool,
    heartbeat: Duration,
    auth_timeout: Duration,
    udp_timeout: Duration,
    meter: crate::stats::Meter,
    signal: Option<Arc<AtomicBool>>,
) {
    let stop = signal.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let mut retry_secret = [0u8; 32];
    if getrandom::fill(&mut retry_secret).is_err() {
        return;
    }
    let mut server = Server {
        sock,
        local,
        users,
        template,
        freedom,
        heartbeat,
        auth_timeout,
        udp_timeout,
        meter,
        stop: Arc::clone(&stop),
        live: Arc::new(AtomicUsize::new(0)),
        conns: HashMap::new(),
        sessions: 0,
        udp_sockets: Arc::new(AtomicUsize::new(0)),
        retry_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &retry_secret),
        touched: Vec::new(),
        dead: Vec::new(),
        seen: Vec::new(),
    };
    let mut buf = vec![0u8; UDP_BUFFER];
    let mut last_tick = Instant::now();
    if server.sock.set_read_timeout(Some(POLL)).is_err() {
        return;
    }
    let mut batch = quic::Batch::new();
    while !stop.load(Ordering::Relaxed) {
        match quic::recv_batch(&server.sock, &mut batch) {
            quic::Drain::Read => server.route_batch(&mut batch),
            quic::Drain::Empty => {}
            quic::Drain::Unbatchable => match server.sock.recv_from(&mut buf) {
                Ok((n, from)) => server.route(&mut buf[..n], from),
                Err(error)
                    if is_wait(&error) || error.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            },
            quic::Drain::Unreadable => break,
        }
        if last_tick.elapsed() >= POLL {
            server.tick();
            last_tick = Instant::now();
        }
    }
    server.close();
}

struct Server {
    sock: Arc<Datagram>,
    local: SocketAddr,
    users: Vec<User>,
    template: quiche::Config,
    freedom: bool,
    heartbeat: Duration,
    auth_timeout: Duration,
    udp_timeout: Duration,
    meter: crate::stats::Meter,
    /// The driver's stop, so every worker leaves and drops its socket before the listener reports closed.
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    conns: HashMap<Vec<u8>, Arc<Session>>,
    sessions: usize,
    udp_sockets: Arc<AtomicUsize>,
    retry_key: ring::hmac::Key,
    /// Sessions this worker owed a turn at the end of a batch, kept so each batch reuses one capacity.
    touched: Vec<Arc<Session>>,
    /// The same for the periodic sweep: the dead sessions it found and the ones it already visited.
    dead: Vec<Arc<Session>>,
    seen: Vec<Arc<Session>>,
}

/// A worker's claim on the listener's socket, returned even when the flow panics.
struct LiveWorker(Arc<AtomicUsize>);

impl Drop for LiveWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Session {
    conn: Arc<Mutex<quiche::Connection>>,
    born: Instant,
    auth_from: Mutex<Option<Instant>>,
    heartbeat: Mutex<Instant>,
    inner: Mutex<Inner>,
}

struct Inner {
    authed: bool,
    auth: Vec<u8>,
    auth_id: Option<u64>,
    seen: HashSet<u64>,
    uni: HashMap<u64, Vec<u8>>,
    udp: HashMap<u16, UdpAssoc>,
    /// The association the last sweep stopped on, so later ones are serviced next.
    udp_cursor: Option<u16>,
    reassembly: HashMap<(u16, u16), Parts>,
    next_uni: AtomicU64,
    pending: Vec<Pending>,
    resolving: HashMap<(u16, String, u16), Resolving>,
    next_generation: u64,
    resolve_done: Sender<ResolveDone>,
    resolved: Receiver<ResolveDone>,
    udp_sockets: Arc<AtomicUsize>,
    udp_buf: Vec<u8>,
    udp_frame: Vec<u8>,
    readable: Vec<u64>,
    expired: Vec<u16>,
}

struct UdpAssoc {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    stream: bool,
    last: Instant,
    generation: u64,
    packet: u16,
    /// The socket the next sweep reads first, so a full v4 queue cannot starve v6 forever.
    turn_v6: bool,
    sockets: Arc<AtomicUsize>,
}

impl UdpAssoc {
    fn new(stream: bool, sockets: Arc<AtomicUsize>, generation: u64) -> Self {
        Self {
            v4: None,
            v6: None,
            stream,
            last: Instant::now(),
            generation,
            packet: 0,
            turn_v6: false,
            sockets,
        }
    }
}

impl Drop for UdpAssoc {
    fn drop(&mut self) {
        let held = usize::from(self.v4.is_some()) + usize::from(self.v6.is_some());
        if held > 0 {
            self.sockets.fetch_sub(held, Ordering::Relaxed);
        }
    }
}

fn reserve_socket(sockets: &AtomicUsize) -> bool {
    let mut current = sockets.load(Ordering::Relaxed);
    loop {
        if current >= MAX_UDP_SOCKETS {
            return false;
        }
        match sockets.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

impl UdpAssoc {
    fn socket_for(&mut self, target: SocketAddr) -> Option<&UdpSocket> {
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let slot = if target.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };
        if slot.is_none() {
            if !reserve_socket(&self.sockets) {
                return None;
            }
            if let Ok(socket) = UdpSocket::bind(bind) {
                let _ = socket.set_nonblocking(true);
                *slot = Some(socket);
            } else {
                self.sockets.fetch_sub(1, Ordering::Relaxed);
                return None;
            }
        }
        slot.as_ref()
    }
}

impl Server {
    fn route(&mut self, bytes: &mut [u8], from: SocketAddr) {
        let Some(session) = self.session_for(bytes, from) else {
            return;
        };
        self.feed(&session, bytes, from);
        self.turn(&session);
    }

    /// One received burst: every datagram goes to quiche first, and the session whose packets it
    /// carried takes one turn over them instead of one per datagram.
    fn route_batch(&mut self, batch: &mut quic::Batch) {
        let taken = batch.len();
        let mut touched = std::mem::take(&mut self.touched);
        touched.clear();
        for at in 0..taken {
            let Some((bytes, from)) = batch.at(at) else {
                continue;
            };
            let Some(session) = self.session_for(bytes, from) else {
                continue;
            };
            self.feed(&session, bytes, from);
            if !touched.iter().any(|held| Arc::ptr_eq(held, &session)) {
                touched.push(session);
            }
        }
        for session in touched.drain(..) {
            self.turn(&session);
        }
        self.touched = touched;
    }

    fn session_for(&mut self, bytes: &mut [u8], from: SocketAddr) -> Option<Arc<Session>> {
        let header = quiche::Header::from_slice(bytes, SCID_LEN).ok()?;
        if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
            return None;
        }
        let initial = header.ty == quiche::Type::Initial;
        let found = self.conns.get(header.dcid.as_ref()).cloned();
        match found {
            Some(session) => Some(session),
            None if initial => {
                if let Some(token) = header.token.as_deref().filter(|token| !token.is_empty()) {
                    self.accept(from, &header, token)
                } else {
                    self.retry(&header, from);
                    None
                }
            }
            None => None,
        }
    }

    fn retry(&self, header: &quiche::Header, from: SocketAddr) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::fill(&mut scid).is_err() {
            return;
        }
        let token = retry_token(&self.retry_key, from, header.dcid.as_ref(), &scid);
        let mut out = [0u8; 512];
        let Ok(len) = quiche::retry(
            &header.scid,
            &header.dcid,
            &quiche::ConnectionId::from_ref(&scid),
            &token,
            header.version,
            &mut out,
        ) else {
            return;
        };
        let _ = self.sock.send_to(&out[..len], from);
    }

    fn accept(
        &mut self,
        from: SocketAddr,
        header: &quiche::Header,
        token: &[u8],
    ) -> Option<Arc<Session>> {
        if self.sessions >= MAX_SESSIONS {
            return None;
        }
        let (odcid, retry_scid) = retry_token_valid(&self.retry_key, from, token)?;
        if header.dcid.as_ref() != retry_scid.as_slice() {
            return None;
        }
        let odcid = quiche::ConnectionId::from_ref(&odcid);
        let retry_scid = quiche::ConnectionId::from_ref(&retry_scid);
        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let conn: quiche::Connection = quiche::accept_with_retry(
            &cid,
            quiche::RetryConnectionIds {
                original_destination_cid: &odcid,
                retry_source_cid: &retry_scid,
            },
            self.local,
            from,
            &mut self.template,
        )
        .ok()?;
        let conn = Arc::new(Mutex::new(conn));
        let now = Instant::now();
        let (resolve_done, resolved) = std::sync::mpsc::channel();
        let session = Arc::new(Session {
            conn: Arc::clone(&conn),
            born: now,
            auth_from: Mutex::new(None),
            heartbeat: Mutex::new(now),
            inner: Mutex::new(Inner {
                authed: false,
                auth: Vec::new(),
                auth_id: None,
                seen: HashSet::new(),
                uni: HashMap::new(),
                udp: HashMap::new(),
                udp_cursor: None,
                reassembly: HashMap::new(),
                next_uni: AtomicU64::new(3),
                pending: Vec::new(),
                resolving: HashMap::new(),
                next_generation: 0,
                resolve_done,
                resolved,
                udp_sockets: Arc::clone(&self.udp_sockets),
                udp_buf: Vec::new(),
                udp_frame: Vec::new(),
                readable: Vec::new(),
                expired: Vec::new(),
            }),
        });
        self.conns.insert(scid.to_vec(), Arc::clone(&session));
        self.conns
            .entry(retry_scid.as_ref().to_vec())
            .or_insert_with(|| Arc::clone(&session));
        self.sessions += 1;
        Some(session)
    }

    fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let mut seen: Vec<Arc<Session>> = Vec::new();
        for session in self.conns.values() {
            if seen.iter().any(|seen| Arc::ptr_eq(seen, session)) {
                continue;
            }
            seen.push(Arc::clone(session));
            if let Ok(mut conn) = session.conn.lock() {
                let _ = conn.close(true, 0, b"closed");
                quic::flush_egress(&mut conn, &self.sock);
            }
        }
        self.conns.clear();
        self.sessions = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.live.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let left = self.live.load(Ordering::SeqCst);
        if left != 0 {
            eprintln!("tuic: {left} stream handlers still running at shutdown");
        }
    }

    /// Hand one packet to its connection and register the source ids it named, so the rest of the
    /// batch routes by them.
    fn feed(&mut self, session: &Arc<Session>, bytes: &mut [u8], from: SocketAddr) {
        let Ok(mut conn) = session.conn.lock() else {
            return;
        };
        let _ = conn.recv(
            bytes,
            quiche::RecvInfo {
                from,
                to: self.local,
            },
        );
        for id in conn.source_ids() {
            if !self.conns.contains_key(id.as_ref()) {
                self.conns.insert(id.as_ref().to_vec(), Arc::clone(session));
            }
        }
    }

    /// What a session owes after its packets landed: the timers they advanced, the streams they
    /// made readable, and the egress behind both.
    fn turn(&mut self, session: &Arc<Session>) {
        let Ok(mut conn) = session.conn.lock() else {
            return;
        };
        if conn
            .timeout_instant()
            .is_some_and(|at| at <= Instant::now())
        {
            conn.on_timeout();
        }
        if !conn.is_established() || conn.is_closed() {
            quic::flush_egress(&mut conn, &self.sock);
            return;
        }
        let Ok(mut inner) = session.inner.lock() else {
            return;
        };
        if !inner.authed {
            if let Ok(mut from) = session.auth_from.lock() {
                from.get_or_insert_with(Instant::now);
            }
            if !authenticate(&mut conn, &mut inner, &self.users) {
                quic::flush_egress(&mut conn, &self.sock);
                return;
            }
        }
        let state = &mut *inner;
        state.seen.retain(|id| !conn.stream_closed(*id));
        state.readable.clear();
        state.readable.extend(conn.readable());
        for id in state.uni.keys() {
            if !state.readable.contains(id) {
                state.readable.push(*id);
            }
        }
        let mut ids = std::mem::take(&mut state.readable);
        for &id in &ids {
            match id % 4 {
                0 => {
                    if state.seen.insert(id) {
                        let stream = QuicStream::new(
                            Arc::clone(&session.conn),
                            Arc::clone(&self.sock),
                            id,
                            crate::stats::Meter::default(),
                        )
                        .with_stop(Arc::clone(&self.stop))
                        .with_meter(self.meter.clone());
                        let freedom = self.freedom;
                        self.live.fetch_add(1, Ordering::SeqCst);
                        let worker = LiveWorker(Arc::clone(&self.live));
                        let _ = thread::Builder::new()
                            .spawn(move || serve_tcp(stream, freedom, worker));
                    }
                }
                2 => read_uni(&mut conn, state, id, self.freedom),
                _ => {}
            }
        }
        ids.clear();
        state.readable = ids;
        while let Ok(data) = conn.dgram_recv_buf() {
            if self.freedom {
                if let Ok(packet) = wire::parse_packet(&data) {
                    accept_packet(&mut inner, &packet, false);
                }
            }
        }
        let now = Instant::now();
        drain_resolved(&mut inner, now);
        poll_udp(&mut conn, &self.sock, &mut inner, now);
        inner
            .reassembly
            .retain(|_, parts| now.duration_since(parts.at) < REASSEMBLY_TTL);
        expire_udp(&mut inner, now, self.udp_timeout);
        flush_inner(&mut conn, &self.sock, &mut inner);
        self.beat(session, &mut conn, now);
        quic::flush_egress(&mut conn, &self.sock);
    }

    fn beat(&self, session: &Session, conn: &mut quiche::Connection, now: Instant) {
        let due = session
            .heartbeat
            .lock()
            .is_ok_and(|last| now.duration_since(*last) >= self.heartbeat);
        if due {
            let _ = conn.dgram_send(&[wire::VERSION, wire::HEARTBEAT]);
            if let Ok(mut last) = session.heartbeat.lock() {
                *last = now;
            }
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let mut dead = std::mem::take(&mut self.dead);
        let mut seen = std::mem::take(&mut self.seen);
        dead.clear();
        seen.clear();
        for session in self.conns.values() {
            if seen.iter().any(|seen| Arc::ptr_eq(seen, session)) {
                continue;
            }
            seen.push(Arc::clone(session));
            let Ok(mut conn) = session.conn.lock() else {
                continue;
            };
            let authed = session.inner.lock().is_ok_and(|inner| inner.authed);
            let auth_at = session
                .auth_from
                .lock()
                .ok()
                .and_then(|from| *from)
                .unwrap_or(session.born);
            if conn.is_closed() || (!authed && now.duration_since(auth_at) >= self.auth_timeout) {
                if !conn.is_closed() {
                    let _ = conn.close(true, 0, b"timeout");
                    quic::flush_egress(&mut conn, &self.sock);
                }
                dead.push(Arc::clone(session));
                continue;
            }
            if !conn.is_established() {
                if let Some(at) = conn.timeout_instant() {
                    if at <= now {
                        conn.on_timeout();
                    }
                }
                quic::flush_egress(&mut conn, &self.sock);
                continue;
            }
            self.beat(session, &mut conn, now);
            if let Some(at) = conn.timeout_instant() {
                if at <= now {
                    conn.on_timeout();
                }
            }
            let Ok(mut inner) = session.inner.lock() else {
                continue;
            };
            inner.seen.retain(|id| !conn.stream_closed(*id));
            drain_resolved(&mut inner, now);
            poll_udp(&mut conn, &self.sock, &mut inner, now);
            expire_udp(&mut inner, now, self.udp_timeout);
            inner
                .reassembly
                .retain(|_, parts| now.duration_since(parts.at) < REASSEMBLY_TTL);
            flush_inner(&mut conn, &self.sock, &mut inner);
            quic::flush_egress(&mut conn, &self.sock);
        }
        if !dead.is_empty() {
            self.conns
                .retain(|_, session| !dead.iter().any(|dead| Arc::ptr_eq(dead, session)));
            self.sessions = self.sessions.saturating_sub(dead.len());
        }
        dead.clear();
        seen.clear();
        self.dead = dead;
        self.seen = seen;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn retry_token(key: &ring::hmac::Key, from: SocketAddr, odcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let now = unix_now();
    let mut token = Vec::with_capacity(1 + 8 + 17 + 1 + odcid.len() + SCID_LEN + RETRY_TOKEN_TAG);
    token.push(1);
    token.extend_from_slice(&now.to_le_bytes());
    match from.ip() {
        IpAddr::V4(ip) => {
            token.push(4);
            token.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            token.push(6);
            token.extend_from_slice(&ip.octets());
        }
    }
    token.push(odcid.len() as u8);
    token.extend_from_slice(odcid);
    token.extend_from_slice(scid);
    let tag = ring::hmac::sign(key, &token);
    token.extend_from_slice(tag.as_ref());
    token
}

fn retry_token_valid(
    key: &ring::hmac::Key,
    from: SocketAddr,
    token: &[u8],
) -> Option<(Vec<u8>, [u8; SCID_LEN])> {
    let (body, tag) = token.split_at_checked(token.len().checked_sub(RETRY_TOKEN_TAG)?)?;
    if ring::hmac::verify(key, body, tag).is_err() {
        return None;
    }
    let mut at = 0;
    if *body.first()? != 1 {
        return None;
    }
    at += 1;
    let issued = u64::from_le_bytes(body.get(at..at + 8)?.try_into().ok()?);
    at += 8;
    let now = unix_now();
    if issued > now.saturating_add(5) || now.saturating_sub(issued) > RETRY_TOKEN_TTL.as_secs() {
        return None;
    }
    let ip = match body.get(at).copied()? {
        4 => {
            at += 1;
            IpAddr::from(<[u8; 4]>::try_from(body.get(at..at + 4)?).ok()?)
        }
        6 => {
            at += 1;
            IpAddr::from(<[u8; 16]>::try_from(body.get(at..at + 16)?).ok()?)
        }
        _ => return None,
    };
    at += if ip.is_ipv4() { 4 } else { 16 };
    if ip != from.ip() {
        return None;
    }
    let len = *body.get(at)? as usize;
    at += 1;
    if len == 0 || len > quiche::MAX_CONN_ID_LEN {
        return None;
    }
    let odcid = body.get(at..at + len)?.to_vec();
    at += len;
    let scid = <[u8; SCID_LEN]>::try_from(body.get(at..at + SCID_LEN)?).ok()?;
    at += SCID_LEN;
    if at != body.len() {
        return None;
    }
    Some((odcid, scid))
}

fn authenticate(conn: &mut quiche::Connection, inner: &mut Inner, users: &[User]) -> bool {
    let mut room = [0u8; 512];
    if inner.auth.len() < wire::AUTH_LEN {
        if let Some(id) = inner.auth_id {
            if !read_command(conn, id, &mut inner.auth, &mut room) {
                return false;
            }
        } else {
            let ids: Vec<u64> = conn.readable().filter(|id| id % 4 == 2).collect();
            for id in ids {
                let mut data = inner.uni.remove(&id).unwrap_or_default();
                read_prefix(conn, id, &mut data, &mut room);
                if data.len() < 2 {
                    if !data.is_empty() {
                        inner.uni.insert(id, data);
                    }
                    continue;
                }
                if data[0] != wire::VERSION {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                if data[1] == wire::AUTHENTICATE {
                    if !read_command(conn, id, &mut data, &mut room) {
                        return false;
                    }
                    inner.auth_id = Some(id);
                    inner.auth = data;
                    break;
                }
                if !matches!(
                    data[1],
                    wire::CONNECT | wire::PACKET | wire::DISSOCIATE | wire::HEARTBEAT
                ) {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                let held: usize = inner.uni.values().map(Vec::len).sum();
                if inner.uni.len() >= MAX_PREAUTH_COMMANDS
                    || held.saturating_add(data.len()) > MAX_PREAUTH_BYTES
                {
                    let _ = conn.close(true, 0, b"command");
                    return false;
                }
                inner.uni.insert(id, data);
            }
        }
    }
    if inner.auth.len() < wire::AUTH_LEN {
        return false;
    }
    if inner.auth[0] != wire::VERSION || inner.auth[1] != wire::AUTHENTICATE {
        let _ = conn.close(false, 0, b"auth");
        return false;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&inner.auth[2..18]);
    let user = users.iter().find(|user| user.uuid == uuid);
    let password: &[u8] = match user {
        Some(user) => user.password.as_bytes(),
        None => &[],
    };
    let Some(token) = export_token(conn, &uuid, password) else {
        let _ = conn.close(false, 0, b"auth");
        return false;
    };
    if user.is_none() || !constant_eq(&inner.auth[18..50], &token) {
        let _ = conn.close(false, 0, b"auth");
        return false;
    }
    inner.authed = true;
    inner.auth.clear();
    if inner.auth_id.is_some_and(|id| conn.stream_finished(id)) {
        inner.auth_id = None;
    }
    true
}

fn read_prefix(conn: &mut quiche::Connection, id: u64, data: &mut Vec<u8>, room: &mut [u8]) {
    while data.len() < 2 {
        let need = 2 - data.len();
        match conn.stream_recv(id, &mut room[..need]) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => data.extend_from_slice(&room[..n]),
        }
    }
}

fn read_command(
    conn: &mut quiche::Connection,
    id: u64,
    data: &mut Vec<u8>,
    room: &mut [u8],
) -> bool {
    while data.len() < MAX_UNI_COMMAND {
        match conn.stream_recv(id, room) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) if data.len() + n <= MAX_UNI_COMMAND => {
                data.extend_from_slice(&room[..n]);
                if data.len() >= wire::AUTH_LEN
                    && data.first() == Some(&wire::VERSION)
                    && data.get(1) == Some(&wire::AUTHENTICATE)
                {
                    break;
                }
            }
            Ok(_) => {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                let _ = conn.close(true, 0, b"command");
                return false;
            }
        }
    }
    true
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn serve_tcp(mut stream: QuicStream, freedom: bool, worker: LiveWorker) {
    if !freedom {
        stream.close();
        drop(stream);
        return;
    }
    let deadline = Instant::now() + CONNECT_HEADER_TIMEOUT;
    let mut head = [0u8; 2];
    if read_exact(&mut stream, &mut head, deadline).is_err()
        || head != [wire::VERSION, wire::CONNECT]
    {
        stream.close();
        drop(stream);
        return;
    }
    let Some((host, port)) = read_stream_address(&mut stream, deadline) else {
        stream.close();
        drop(stream);
        return;
    };
    let Some(upstream) =
        proxy::resolve_outbound(&host, port).and_then(|target| proxy::dial_or_report(&target))
    else {
        stream.close();
        drop(stream);
        return;
    };
    proxy::relay_quic_stream(&upstream, stream, Some(Box::new(move || drop(worker))));
}

fn read_exact(stream: &mut QuicStream, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        match stream.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => at += n,
            Err(error) if is_wait(&error) => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_stream_address(stream: &mut QuicStream, deadline: Instant) -> Option<(String, u16)> {
    let mut kind = [0u8; 1];
    read_exact(stream, &mut kind, deadline).ok()?;
    let host = match kind[0] {
        0 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len, deadline).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name, deadline).ok()?;
            String::from_utf8(name).ok()?
        }
        1 => {
            let mut octets = [0u8; 4];
            read_exact(stream, &mut octets, deadline).ok()?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        2 => {
            let mut octets = [0u8; 16];
            read_exact(stream, &mut octets, deadline).ok()?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    read_exact(stream, &mut port, deadline).ok()?;
    Some((host, u16::from_be_bytes(port)))
}

thread_local! {
    static UNI_ROOM: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn read_uni(conn: &mut quiche::Connection, inner: &mut Inner, id: u64, freedom: bool) {
    let mut room = UNI_ROOM.with(|held| std::mem::take(&mut *held.borrow_mut()));
    room.resize(UDP_BUFFER, 0);
    read_uni_with(conn, inner, id, freedom, &mut room);
    UNI_ROOM.with(|held| *held.borrow_mut() = room);
}

fn read_uni_with(
    conn: &mut quiche::Connection,
    inner: &mut Inner,
    id: u64,
    freedom: bool,
    room: &mut [u8],
) {
    if inner.auth_id == Some(id) {
        let mut room = [0u8; 512];
        while let Ok((n, _)) = conn.stream_recv(id, &mut room) {
            if n == 0 {
                break;
            }
        }
        inner.uni.remove(&id);
        if conn.stream_finished(id) {
            inner.auth_id = None;
        }
        return;
    }
    let mut data = inner.uni.remove(&id).unwrap_or_default();
    while let Ok((n, _)) = conn.stream_recv(id, &mut *room) {
        if n == 0 {
            break;
        }
        if data.len() + n > MAX_UNI_COMMAND {
            let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
            return;
        }
        data.extend_from_slice(&room[..n]);
    }
    if freedom && data.get(1) == Some(&wire::PACKET) {
        let mut at = 0usize;
        loop {
            match wire::parse_packet_prefix(&data[at..]) {
                Ok((packet, used)) => {
                    accept_packet(inner, &packet, true);
                    at += used;
                }
                Err(wire::FrameError::Short) => break,
                Err(_) => {
                    let _ = conn.close(true, 0, b"command");
                    return;
                }
            }
        }
        if at > 0 {
            data.drain(..at);
        }
    }
    if !conn.stream_finished(id) {
        if !data.is_empty() {
            inner.uni.insert(id, data);
        }
        return;
    }
    if data.len() < 2 || data[0] != wire::VERSION {
        return;
    }
    match data[1] {
        wire::DISSOCIATE if data.len() == 4 => {
            let association = u16::from_be_bytes([data[2], data[3]]);
            inner.udp.remove(&association);
            inner.reassembly.retain(|key, _| key.0 != association);
            inner.resolving.retain(|key, _| key.0 != association);
        }
        wire::HEARTBEAT if data.len() == 2 => {}
        _ => {
            let _ = conn.close(true, 0, b"command");
        }
    }
}

fn accept_packet(inner: &mut Inner, packet: &wire::Packet<'_>, stream: bool) {
    let Some(generation) = select_assoc(inner, packet.association, stream) else {
        return;
    };
    let Some((destination, payload)) = take_packet(&mut inner.reassembly, packet) else {
        return;
    };
    match destination {
        Destination::Address(target) => {
            deliver_udp(inner, packet.association, target, &payload, Instant::now());
        }
        Destination::Name(host, port) => {
            let job = ResolveJob {
                association: packet.association,
                host,
                port,
                payload: payload.into_owned(),
                generation,
                options: proxy::dial_options(),
                reply: inner.resolve_done.clone(),
            };
            queue_resolve(inner, job);
        }
    }
}

fn queue_resolve(inner: &mut Inner, job: ResolveJob) {
    let key = (job.association, job.host.clone(), job.port);
    if let Some(pending) = inner.resolving.get_mut(&key) {
        if pending.payloads.len() < MAX_RESOLVE_PAYLOADS {
            pending.payloads.push(job.payload);
        }
        return;
    }
    if inner.resolving.len() >= MAX_RESOLVING_PER_SESSION {
        return;
    }
    inner.resolving.insert(
        key.clone(),
        Resolving {
            generation: job.generation,
            payloads: Vec::new(),
        },
    );
    if !ResolverPool::get().submit(job) {
        inner.resolving.remove(&key);
    }
}

fn drain_resolved(inner: &mut Inner, now: Instant) {
    while let Ok(done) = inner.resolved.try_recv() {
        let key = (done.association, done.host.clone(), done.port);
        let Some(held) = inner.resolving.get(&key) else {
            continue;
        };
        if held.generation != done.generation {
            continue;
        }
        if inner
            .udp
            .get(&done.association)
            .is_none_or(|assoc| assoc.generation != done.generation)
        {
            inner.resolving.remove(&key);
            continue;
        }
        let Some(pending) = inner.resolving.remove(&key) else {
            continue;
        };
        if let Some(target) = done.target {
            deliver_udp(inner, done.association, target, &done.payload, now);
            for payload in pending.payloads {
                deliver_udp(inner, done.association, target, &payload, now);
            }
        }
    }
}

/// Record the first PACKET's reply mode before a name waits on DNS: a later numeric PACKET for the
/// same association must not choose the mode the lookup will use. The generation is session-wide, so
/// a recreated association cannot accept a lookup that belonged to an earlier one.
fn select_assoc(inner: &mut Inner, association: u16, stream: bool) -> Option<u64> {
    if let Some(assoc) = inner.udp.get(&association) {
        return Some(assoc.generation);
    }
    if inner.udp.len() >= MAX_ASSOCIATIONS_PER_SESSION {
        return None;
    }
    let generation = inner.next_generation;
    inner.next_generation = generation.wrapping_add(1);
    let sockets = Arc::clone(&inner.udp_sockets);
    inner
        .udp
        .insert(association, UdpAssoc::new(stream, sockets, generation));
    Some(generation)
}

/// Expire idle associations with everything that belonged to them, so a lookup that lands after the
/// expiry cannot recreate the association it was resolved for.
fn expire_udp(inner: &mut Inner, now: Instant, timeout: Duration) {
    let mut expired = std::mem::take(&mut inner.expired);
    expired.clear();
    expired.extend(
        inner
            .udp
            .iter()
            .filter(|(_, assoc)| now.duration_since(assoc.last) >= timeout)
            .map(|(association, _)| *association),
    );
    for association in expired.drain(..) {
        inner.udp.remove(&association);
        inner.reassembly.retain(|key, _| key.0 != association);
        inner.resolving.retain(|key, _| key.0 != association);
    }
    inner.expired = expired;
}

fn deliver_udp(
    inner: &mut Inner,
    association: u16,
    target: SocketAddr,
    payload: &[u8],
    now: Instant,
) {
    let Some(entry) = inner.udp.get_mut(&association) else {
        return;
    };
    entry.last = now;
    let Some(socket) = entry.socket_for(target) else {
        return;
    };
    let _ = socket.send_to(payload, target);
}

fn flush_inner(conn: &mut quiche::Connection, sock: &Arc<Datagram>, inner: &mut Inner) {
    let mut pending = std::mem::take(&mut inner.pending);
    flush_pending(conn, sock, &mut pending, &inner.next_uni);
    inner.pending = pending;
}

fn poll_udp(conn: &mut quiche::Connection, sock: &Datagram, inner: &mut Inner, now: Instant) {
    let max = conn.dgram_max_writable_len();
    let mut buf = std::mem::take(&mut inner.udp_buf);
    buf.resize(UDP_BUFFER, 0);
    let mut pending = std::mem::take(&mut inner.pending);
    let mut frame = std::mem::take(&mut inner.udp_frame);
    let mut swept = 0usize;
    let cursor = inner.udp_cursor;
    let mut after = cursor.is_none_or(|key| !inner.udp.contains_key(&key));
    let mut exhausted = false;
    let mut last_serviced = None;
    'sweep: for (association, assoc) in &mut inner.udp {
        if !after {
            if Some(*association) == cursor {
                after = true;
            }
            continue;
        }
        let UdpAssoc {
            v4,
            v6,
            stream,
            last,
            packet,
            turn_v6,
            ..
        } = assoc;
        let mode = if *stream {
            RelayMode::Quic
        } else {
            RelayMode::Native
        };
        let (first, second) = if *turn_v6 { (v6, v4) } else { (v4, v6) };
        *turn_v6 = !*turn_v6;
        let mut taken = 0usize;
        for socket in [first, second].into_iter().flatten() {
            loop {
                if taken >= UDP_PACKETS_PER_ASSOC || swept >= UDP_PACKETS_PER_SWEEP {
                    break;
                }
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        taken += 1;
                        swept += 1;
                        let address = match from.ip() {
                            IpAddr::V4(ip) => wire::Address::V4(ip.octets()),
                            IpAddr::V6(ip) => wire::Address::V6(ip.octets()),
                        };
                        *last = now;
                        *packet = next_packet(*packet);
                        send_message(
                            conn,
                            sock,
                            mode,
                            *association,
                            *packet,
                            address,
                            from.port(),
                            &buf[..n],
                            max,
                            &mut pending,
                            &mut frame,
                        );
                    }
                    Err(error) if is_wait(&error) => break,
                    Err(_) => break,
                }
            }
        }
        last_serviced = Some(*association);
        if swept >= UDP_PACKETS_PER_SWEEP {
            exhausted = true;
            break 'sweep;
        }
    }
    inner.udp_cursor = if exhausted { last_serviced } else { None };
    inner.pending = pending;
    inner.udp_buf = buf;
    inner.udp_frame = frame;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> (ferrox_core::tls::TlsServerConfig, Vec<Vec<u8>>) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tuic.test".to_owned()]).expect("mints");
        let roots = quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let identity = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: roots.clone(),
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            issuer: None,
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        (identity, roots)
    }

    fn test_out(address: SocketAddr, roots: Vec<Vec<u8>>) -> TuicOut {
        TuicOut {
            address: "127.0.0.1".to_owned(),
            port: address.port(),
            host: "tuic.test".to_owned(),
            uuid: [0x11; 16],
            password: "secret".to_owned(),
            mode: RelayMode::Quic,
            zero_rtt: true,
            cc: None,
            roots: Some(Arc::from(roots)),
            cert_pins: Arc::new([]),
            insecure: false,
            heartbeat: Duration::from_secs(30),
            lane: Mutex::new(None),
            session: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn a_pin_verifies_the_handshake() {
        let (identity, roots) = test_identity();
        let leaf = identity.certs[0].cert_chain[0].clone();
        let digest = ring::digest::digest(&ring::digest::SHA256, &leaf);
        let pin: [u8; 32] = digest.as_ref().try_into().expect("a sha256 digest");
        let mut config = quic::serve_config(&identity).expect("the server builds");
        let server = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let address = server.local_addr().expect("address");
        let server_thread = thread::spawn(move || {
            let sock = Datagram::plain(server).with_gro(false);
            let _ = quic::server_accept(&sock, address, &mut config);
        });
        let mut out = test_out(address, roots);
        out.zero_rtt = false;
        out.cert_pins = Arc::from(vec![pin]);
        let lane = out.lane().expect("a pinned handshake");
        assert!(
            lane.conn.lock().expect("the lane lock").is_established(),
            "the pin did not complete the handshake"
        );
        lane.stop.store(true, Ordering::Relaxed);
        server_thread.join().expect("the server thread");
    }

    #[test]
    fn a_resumed_lane_carries_application_data_before_the_handshake() {
        let (identity, roots) = test_identity();
        let mut config = quic::serve_config(&identity).expect("the server builds");
        config.enable_early_data();
        let server = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let address = server.local_addr().expect("address");
        let (early, observed) = std::sync::mpsc::channel();
        let server_thread = thread::spawn(move || {
            let sock = Datagram::plain(server).with_gro(false);
            let mut buf = vec![0u8; 65535];
            let mut out = vec![0u8; 65535];
            let mut first = quic::server_accept(&sock, address, &mut config);
            for _ in 0..20 {
                quic::server_idle(&mut first, &sock, &mut out);
                thread::sleep(Duration::from_millis(10));
            }
            drop(first);
            thread::sleep(Duration::from_millis(100));

            let deadline = Instant::now() + Duration::from_secs(5);
            let (n, from) = loop {
                assert!(Instant::now() < deadline, "no second Initial arrived");
                let Some((n, from)) = quic::server_poll(&sock, &mut buf) else {
                    continue;
                };
                if quiche::Header::from_slice(&mut buf[..n], 20)
                    .is_ok_and(|header| header.ty == quiche::Type::Initial)
                {
                    break (n, from);
                }
            };
            let mut scid = [0u8; 16];
            getrandom::fill(&mut scid).expect("random");
            let cid = quiche::ConnectionId::from_ref(&scid);
            let mut second =
                quiche::accept(&cid, None, address, from, &mut config).expect("accepts");
            second
                .recv(&mut buf[..n], quiche::RecvInfo { from, to: address })
                .expect("drives");
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let mut data = [0u8; 64];
                if let Ok((read, _)) = second.stream_recv(0, &mut data) {
                    if read > 0 {
                        assert!(
                            !second.is_established(),
                            "the server read early data only after the handshake"
                        );
                        early.send(data[..read].to_vec()).expect("reports");
                        break;
                    }
                }
                if let Some((n, from)) = quic::server_poll(&sock, &mut buf) {
                    second
                        .recv(&mut buf[..n], quiche::RecvInfo { from, to: address })
                        .expect("drives");
                }
            }
        });

        let out = test_out(address, roots);
        let first = out.lane().expect("the first lane");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "no session ticket was delivered");
            if out.session.lock().expect("the session lock").is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        first.stop.store(true, Ordering::Relaxed);
        let lane = out.lane().expect("the resumed lane");
        let (established, in_early) = {
            let conn = lane.conn.lock().expect("the lane lock");
            (conn.is_established(), conn.is_in_early_data())
        };
        assert!(in_early, "the lane is not in early data");
        assert!(!established, "the lane waited for the handshake");
        let mut conn = lane.conn.lock().expect("the lane lock");
        assert_eq!(
            conn.stream_send(0, b"early connect", false)
                .expect("queues"),
            13
        );
        quic::flush_egress(&mut conn, &lane.sock);
        drop(conn);
        assert_eq!(
            observed
                .recv_timeout(Duration::from_secs(5))
                .expect("the server reads early data before the handshake"),
            b"early connect"
        );
        server_thread.join().expect("the server thread");
    }

    fn empty_inner() -> (Inner, Sender<ResolveDone>) {
        let (done, resolved) = std::sync::mpsc::channel();
        (
            Inner {
                authed: false,
                auth: Vec::new(),
                auth_id: None,
                seen: HashSet::new(),
                uni: HashMap::new(),
                udp: HashMap::new(),
                udp_cursor: None,
                reassembly: HashMap::new(),
                next_uni: AtomicU64::new(3),
                pending: Vec::new(),
                resolving: HashMap::new(),
                next_generation: 0,
                resolve_done: done.clone(),
                resolved,
                udp_sockets: Arc::new(AtomicUsize::new(0)),
                udp_buf: Vec::new(),
                udp_frame: Vec::new(),
                readable: Vec::new(),
                expired: Vec::new(),
            },
            done,
        )
    }

    #[test]
    fn a_uuid_is_sixteen_bytes_and_refuses_anything_else() {
        assert_eq!(
            uuid_bytes("00112233-4455-6677-8899-aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert_eq!(uuid_bytes("0011"), None);
        assert_eq!(uuid_bytes("00112233445566778899aabbccddeefg"), None);
    }

    #[test]
    fn a_tuic_outbound_reads_the_reference_spellings() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"servers":[{"address":"tuic.test","server_port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","udp_relay_mode":"quic","congestion_control":"bbr","zero_rtt_handshake":true}]},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!((out.address.as_str(), out.port), ("tuic.test", 443));
        assert_eq!(out.mode, RelayMode::Quic);
        assert!(out.zero_rtt);
    }

    #[test]
    fn a_full_packet_fits_one_command() {
        let name = "a".repeat(wire::MAX_ADDRESS);
        let address = wire::address_port(&name, 9).expect("an address");
        let payload = vec![7u8; MAX_PACKET_PAYLOAD];
        let mut frame = Vec::new();
        wire::encode_fragment(1, 2, 1, 0, &address, &payload, &mut frame);
        assert!(
            frame.len() <= MAX_UNI_COMMAND,
            "{} > {}",
            frame.len(),
            MAX_UNI_COMMAND
        );
        let packet = wire::parse_packet(&frame).expect("the frame parses");
        assert_eq!(packet.payload.len(), MAX_PACKET_PAYLOAD);
        assert_eq!(packet.destination.expect("a destination").1, 9);
    }

    #[test]
    fn the_first_packets_mode_survives_a_later_numeric_packet() {
        let (mut inner, _done) = empty_inner();
        assert!(
            select_assoc(&mut inner, 4, true).is_some(),
            "the first packet wins"
        );
        assert!(
            select_assoc(&mut inner, 4, false).is_some(),
            "the association stays"
        );
        let assoc = inner.udp.get(&4).expect("the association is recorded");
        assert!(assoc.stream, "a later packet does not restate the mode");
    }

    #[test]
    fn a_late_resolution_does_not_recreate_a_dissociated_association() {
        let (mut inner, done) = empty_inner();
        let generation = select_assoc(&mut inner, 7, false).expect("the association is recorded");
        let key = (7u16, "example.test".to_owned(), 53u16);
        inner.resolving.insert(
            key.clone(),
            Resolving {
                generation,
                payloads: vec![vec![1]],
            },
        );
        inner.udp.remove(&7);
        done.send(ResolveDone {
            association: 7,
            host: "example.test".to_owned(),
            port: 53,
            target: None,
            payload: vec![2],
            generation,
        })
        .expect("the channel is open");
        drain_resolved(&mut inner, Instant::now());
        assert!(!inner.resolving.contains_key(&key));
        assert!(
            inner.udp.is_empty(),
            "a stale result does not recreate the association"
        );
    }

    #[test]
    fn an_idle_association_drops_a_late_resolution() {
        let (mut inner, done) = empty_inner();
        let generation = select_assoc(&mut inner, 9, false).expect("the association is recorded");
        let key = (9u16, "example.test".to_owned(), 53u16);
        inner.resolving.insert(
            key.clone(),
            Resolving {
                generation,
                payloads: vec![vec![1]],
            },
        );
        expire_udp(
            &mut inner,
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(1),
        );
        assert!(inner.udp.is_empty(), "the idle association expires");
        assert!(
            inner.resolving.is_empty(),
            "its pending lookup expires with it"
        );
        done.send(ResolveDone {
            association: 9,
            host: "example.test".to_owned(),
            port: 53,
            target: None,
            payload: vec![2],
            generation,
        })
        .expect("the channel is open");
        drain_resolved(&mut inner, Instant::now());
        assert!(
            inner.udp.is_empty(),
            "an expired lookup does not recreate the association"
        );
    }

    #[test]
    fn a_new_reno_name_is_quiches_reno() {
        assert_eq!(quiche_cc("new_reno"), "reno");
        assert_eq!(quiche_cc("reno"), "reno");
        assert_eq!(quiche_cc("cubic"), "cubic");
        assert_eq!(quiche_cc("bbr"), "bbr");
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","congestion_control":"new_reno"},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!(out.cc.as_deref(), Some("reno"));
        assert!(out.client_config().is_some());
    }

    #[test]
    fn a_single_fragment_packet_payload_is_not_copied() {
        let address = Some((wire::Address::V4([192, 0, 2, 1]), 53));
        let empty = Vec::new();
        let empty_packet = wire::Packet {
            association: 1,
            packet: 2,
            total: 1,
            index: 0,
            destination: address,
            payload: &empty,
        };
        let (_, base) =
            ferrox_core::alloc_count::measure(|| take_packet(&mut HashMap::new(), &empty_packet));
        let payload = vec![7u8; 32];
        let packet = wire::Packet {
            association: 1,
            packet: 3,
            total: 1,
            index: 0,
            destination: address,
            payload: &payload,
        };
        let source = payload.as_ptr();
        let (taken, counts) =
            ferrox_core::alloc_count::measure(|| take_packet(&mut HashMap::new(), &packet));
        let (destination, copied) = taken.expect("one packet");
        assert_eq!(
            destination,
            Destination::Address(SocketAddr::new(IpAddr::V4([192, 0, 2, 1].into()), 53))
        );
        assert_eq!(copied.as_ref(), payload);
        assert_eq!(copied.as_ptr(), source);
        assert_eq!(counts.allocs - base.allocs, 0);
        assert_eq!(counts.bytes - base.bytes, 0);
    }

    #[test]
    fn a_pin_only_outbound_builds_its_tls() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret"},"streamSettings":{"security":"tls","tlsSettings":{"pinnedPeerCertSha256":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}}]}"#,
        )
        .expect("parses");
        let out = outbound(&root)
            .expect("the outbound is read")
            .expect("a tuic outbound");
        assert_eq!(out.cert_pins.len(), 1);
        assert!(out.client_config().is_some());
    }

    #[test]
    fn a_tuic_udp_over_stream_is_refused_not_silently_mapped() {
        let base = r#"{"outbounds":[{"protocol":"tuic","settings":{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret"%s},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#;
        let config =
            crate::json::parse(&base.replace("%s", r#","udp_over_stream":true"#)).expect("parses");
        assert!(outbound(&config).is_err());
    }

    #[test]
    fn a_tuic_mode_or_congestion_name_outside_the_reference_is_refused() {
        for (field, value) in [
            ("udp_relay_mode", "stream"),
            ("congestion_control", "vegas"),
        ] {
            let config = format!(
                r#"{{"outbounds":[{{"protocol":"tuic","settings":{{"address":"tuic.test","port":443,"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret","{field}":"{value}"}},"streamSettings":{{"security":"tls","tlsSettings":{{"allowInsecure":true}}}}}}]}}"#
            );
            let root = crate::json::parse(&config).expect("parses");
            assert!(outbound(&root).is_err(), "{field} accepted {value}");
        }
    }

    #[test]
    fn a_retry_token_binds_the_source_and_both_connection_ids() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"retry");
        let from: SocketAddr = "192.0.2.7:1234".parse().expect("an address");
        let odcid = [7u8; 8];
        let scid = [9u8; SCID_LEN];
        let token = retry_token(&key, from, &odcid, &scid);
        assert_eq!(
            retry_token_valid(&key, from, &token),
            Some((odcid.to_vec(), scid))
        );
        let elsewhere: SocketAddr = "192.0.2.8:1234".parse().expect("an address");
        assert_eq!(retry_token_valid(&key, elsewhere, &token), None);
        let mut tampered = token.clone();
        tampered[0] ^= 1;
        assert_eq!(retry_token_valid(&key, from, &tampered), None);
        let long = [3u8; quiche::MAX_CONN_ID_LEN];
        let token = retry_token(&key, from, &long, &scid);
        assert_eq!(
            retry_token_valid(&key, from, &token),
            Some((long.to_vec(), scid))
        );
    }

    #[test]
    fn an_expired_retry_token_is_refused() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"retry");
        let from: SocketAddr = "192.0.2.7:1234".parse().expect("an address");
        let token = retry_token(&key, from, &[7u8; 8], &[9u8; SCID_LEN]);
        let mut body = token[..token.len() - RETRY_TOKEN_TAG].to_vec();
        let old = unix_now().saturating_sub(RETRY_TOKEN_TTL.as_secs() + 1);
        body[1..9].copy_from_slice(&old.to_le_bytes());
        let tag = ring::hmac::sign(&key, &body);
        body.extend_from_slice(tag.as_ref());
        assert_eq!(retry_token_valid(&key, from, &body), None);
    }

    #[test]
    fn a_delivered_reply_refreshes_the_sink_activity() {
        let sink = UdpSocket::bind("127.0.0.1:0").expect("a sink");
        let client = UdpSocket::bind("127.0.0.1:0").expect("a client");
        let source = Mutex::new(Some(client.local_addr().expect("an address")));
        let last = Mutex::new(Instant::now().checked_sub(UDP_IDLE).expect("an instant"));
        let address = wire::address_port("127.0.0.1", 9).expect("an address");
        let mut frame = Vec::new();
        wire::encode_fragment(1, 2, 1, 0, &address, b"hello", &mut frame);
        let packet = wire::parse_packet(&frame).expect("a packet");
        let mut head = Vec::new();
        client_reply(
            &packet,
            &mut HashMap::new(),
            &source,
            &last,
            &sink,
            &mut head,
        );
        let mut buf = [0u8; 64];
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a timeout");
        let (n, _) = client.recv_from(&mut buf).expect("the reply arrives");
        assert!(n > 5);
        assert!(last.lock().expect("the activity").elapsed() < UDP_IDLE);
    }
}

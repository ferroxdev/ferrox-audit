//! The reverse tunnel: a portal that lends its reach to a bridge behind a NAT.
//!
//! The wire is the reference's own: a VLESS request with command 4 carries a mux session,
//! and the portal answers a control datagram stream named `reverse` with a protobuf
//! `Control` message. The portal keeps a picker of live sessions, the bridge keeps a
//! monitor that opens another session when the live ones carry more than sixteen flows.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::conn::Connection;

/// The internal destination the portal writes control messages to; the reference spells it in
/// the mux target rather than in a stream of its own.
pub(crate) const CONTROL_DOMAIN: &str = "reverse";

pub(crate) const ACTIVE: i32 = 0;
pub(crate) const DRAIN: i32 = 1;

/// The reference's picker refuses to reuse a session for a new flow past this many flows; it is
/// a session lifetime, not a per-instant bound.
const SESSION_FLOWS: u32 = 256;

/// Bytes one downlink flow may queue before the session drops it rather than stall every other
/// flow behind a reader that stopped reading.
const FLOW_PENDING: usize = ferrox_core::mux::DEFAULT_CAP;

const HEARTBEAT: Duration = Duration::from_secs(2);
const MONITOR: Duration = Duration::from_secs(2);

/// The reference's bridge worker idle bound: a portal that stops heartbeating for this long is gone.
const WORKER_IDLE: Duration = Duration::from_secs(60);

/// A draining worker's heartbeat ended with its drain, so its open connections get this longer
/// bound instead of the active window; when it passes, the same half-open rule closes the tunnel.
const DRAIN_IDLE: Duration = Duration::from_secs(600);

/// One protobuf `Control`: a state and a random pad the reference writes to look unlike a
/// fixed shape. Unknown fields are skipped, and an absent state means `ACTIVE` — proto3 leaves
/// a zero field off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Control {
    pub(crate) state: i32,
    pub(crate) random: Vec<u8>,
}

impl Control {
    pub(crate) fn of(state: i32) -> Self {
        let mut random = vec![0u8; 32];
        let _ = getrandom::fill(&mut random);
        Self { state, random }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.random.len());
        if self.state != ACTIVE {
            out.push(0x08);
            put_varint(&mut out, self.state as u64);
        }
        out.push(0x9a);
        out.push(0x06);
        put_varint(&mut out, self.random.len() as u64);
        out.extend_from_slice(&self.random);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut state = ACTIVE;
        let mut random = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let key = get_varint(bytes, &mut at)?;
            let field = key >> 3;
            match (field, key & 7) {
                (1, 0) => state = i32::try_from(get_varint(bytes, &mut at)?).ok()?,
                (99, 2) => {
                    let len = usize::try_from(get_varint(bytes, &mut at)?).ok()?;
                    random = bytes.get(at..at.checked_add(len)?)?.to_vec();
                    at += len;
                }
                (_, 0) => {
                    get_varint(bytes, &mut at)?;
                }
                (_, 1) => at = at.checked_add(8)?,
                (_, 2) => {
                    let len = usize::try_from(get_varint(bytes, &mut at)?).ok()?;
                    at = at.checked_add(len)?;
                }
                (_, 5) => at = at.checked_add(4)?,
                _ => return None,
            }
            if at > bytes.len() {
                return None;
            }
        }
        Some(Self { state, random })
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn get_varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The address a downlink datagram names: the bridge's own socket, never a name.
fn source_addr(target: ferrox_core::mux::Target<'_>) -> Option<std::net::SocketAddr> {
    let address = match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        ferrox_core::addr::Addr::Name(_) => return None,
    };
    Some(std::net::SocketAddr::new(address, target.port))
}

/// The two ends of a tunnel: a reader one thread owns, a writer every flow shares, and the
/// close that wakes both.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;
type SharedReader = Arc<Mutex<Box<dyn Read + Send>>>;
type Closer = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Tunnel {
    reader: SharedReader,
    writer: SharedWriter,
    closer: Closer,
}

/// The read half of a tunnel, boxed into the shape a session or a mux server reads.
pub(crate) struct TunnelReader(SharedReader);

impl Read for TunnelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("tunnel reader poisoned"))?;
        reader.read(buf)
    }
}

impl Tunnel {
    pub(crate) fn new(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        closer: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            closer,
        }
    }

    pub(crate) fn from_connection(connection: &Connection) -> Option<Self> {
        let reader = connection.try_clone().ok()?;
        let writer = connection.try_clone().ok()?;
        let close = connection.try_clone().ok()?;
        Some(Self::new(
            Box::new(reader),
            Box::new(writer),
            Arc::new(move || {
                let _ = close.shutdown(std::net::Shutdown::Both);
            }),
        ))
    }

    pub(crate) fn reader(&self) -> TunnelReader {
        TunnelReader(Arc::clone(&self.reader))
    }

    /// A frame header and the payload it introduces, written under one lock so another flow cannot
    /// interleave, and read straight from the caller's two buffers.
    pub(crate) fn write_frame_parts(&self, header: &[u8], payload: &[u8]) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        crate::proxy::write_all_parts::<2>(&mut **writer, &[header, payload]).is_ok()
    }

    pub(crate) fn write_all(&self, bytes: &[u8]) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        writer.write_all(bytes).is_ok()
    }

    pub(crate) fn close(&self) {
        (self.closer)();
    }

    fn split(self) -> (TunnelReader, SharedWriter, Closer) {
        (
            TunnelReader(Arc::clone(&self.reader)),
            Arc::clone(&self.writer),
            Arc::clone(&self.closer),
        )
    }
}

/// Two connected loopback streams, the pipe the reverse tunnel rides so a carrier's own dial and
/// relay can stand in for a stream the mux has not been given.
pub(crate) fn loopback_pair() -> Option<(Connection, Connection)> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let address = listener.local_addr().ok()?;
    let client = Connection::from(TcpStream::connect(address).ok()?);
    let (server, _) = listener.accept().ok()?;
    drop(listener);
    Some((client, Connection::from(server)))
}

/// One mux flow: the queue its downlink bytes land in and the flag a teardown sets so a writer
/// parked on a full queue unwinds.
pub(crate) struct Flow {
    /// Each downlink chunk and, on a datagram flow, the address it came from.
    pub(crate) down: Receiver<(Vec<u8>, Option<std::net::SocketAddr>)>,
}

struct Slot {
    down: SyncSender<(Vec<u8>, Option<std::net::SocketAddr>)>,
    cancelled: Arc<AtomicBool>,
}

/// A live portal session: one mux client over the bridge's tunnel.
pub(crate) struct Session {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    closer: Arc<dyn Fn() + Send + Sync>,
    ids: Mutex<ferrox_core::mux::Ids>,
    slots: Mutex<HashMap<u16, Slot>>,
    active: AtomicU32,
    total: AtomicU32,
    done: AtomicBool,
    draining: AtomicBool,
    control: Mutex<Option<u16>>,
    ends: Mutex<(VecDeque<u16>, bool)>,
    portal: Weak<Portal>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("total", &self.total.load(Ordering::Relaxed))
            .field("done", &self.done.load(Ordering::Relaxed))
            .field("draining", &self.draining.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Session {
    fn new(portal: &Arc<Portal>, tunnel: Tunnel) -> Arc<Self> {
        let (reader, writer, closer) = tunnel.split();
        let session = Arc::new(Self {
            writer,
            closer,
            ids: Mutex::new(ferrox_core::mux::Ids::new(0)),
            slots: Mutex::new(HashMap::new()),
            active: AtomicU32::new(0),
            total: AtomicU32::new(0),
            done: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            control: Mutex::new(None),
            ends: Mutex::new((VecDeque::new(), false)),
            portal: Arc::downgrade(portal),
        });
        let reader = session.clone().read_loop(reader);
        session.clone().heartbeat();
        reader
    }

    /// Registers the session and starts its reader and heartbeat.
    pub(crate) fn attach(portal: &Arc<Portal>, tunnel: Tunnel) -> Arc<Self> {
        let session = Self::new(portal, tunnel);
        if let Ok(mut list) = portal.sessions.lock() {
            list.push(session.clone());
        }
        session
    }

    fn read_loop(self: Arc<Self>, mut reader: TunnelReader) -> Arc<Self> {
        let worker = Arc::clone(&self);
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; READ_SLICE];
            // Only a frame that straddles two reads is copied here: a whole frame is parsed where the read landed it.
            let mut carry: Vec<u8> = Vec::new();
            let drain_frames = |data: &[u8]| -> Option<usize> {
                let mut at = 0;
                loop {
                    match ferrox_core::mux::decode(&data[at..], ferrox_core::mux::NewTail::Forward)
                    {
                        Err(ferrox_core::mux::Error::Short { .. }) => return Some(at),
                        Err(_) => return None,
                        Ok((frame, used)) => {
                            at += used;
                            match frame.status {
                                ferrox_core::mux::Status::Keep => {
                                    let Some(payload) = frame.data else { continue };
                                    let Some(sender) = worker.sender(frame.id) else {
                                        continue;
                                    };
                                    let source = frame.target.and_then(source_addr);
                                    if sender.try_send((payload.to_vec(), source)).is_err() {
                                        worker.end_async(frame.id);
                                    }
                                }
                                ferrox_core::mux::Status::End => worker.end_async(frame.id),
                                ferrox_core::mux::Status::New
                                | ferrox_core::mux::Status::KeepAlive => {}
                            }
                        }
                    }
                }
            };
            loop {
                let n = match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        std::thread::sleep(MONITOR);
                        continue;
                    }
                    Err(_) => break,
                };
                if carry.is_empty() {
                    let data = &chunk[..n];
                    let Some(at) = drain_frames(data) else {
                        worker.finish();
                        return;
                    };
                    if at < n {
                        carry.extend_from_slice(&data[at..]);
                    }
                } else {
                    carry.extend_from_slice(&chunk[..n]);
                    let Some(at) = drain_frames(&carry) else {
                        worker.finish();
                        return;
                    };
                    if at == carry.len() {
                        carry.clear();
                    } else {
                        carry.drain(..at);
                    }
                }
            }
            worker.finish();
        });
        self
    }

    fn heartbeat(self: Arc<Self>) {
        std::thread::spawn(move || {
            let id = self.open_control();
            let Some(id) = id else {
                self.finish();
                return;
            };
            let mut counter = 0u32;
            let mut scratch = Vec::with_capacity(64);
            loop {
                std::thread::sleep(HEARTBEAT);
                if self.done.load(Ordering::Relaxed) {
                    return;
                }
                let state = if self.total.load(Ordering::Relaxed) > SESSION_FLOWS {
                    DRAIN
                } else {
                    ACTIVE
                };
                counter = (counter + 1) % 5;
                if state == DRAIN || counter == 1 {
                    let bytes = Control::of(state).encode();
                    let keep = ferrox_core::mux::Outgoing {
                        id,
                        status: ferrox_core::mux::Status::Keep,
                        options: ferrox_core::mux::DATA,
                        target: None,
                        global_id: None,
                    };
                    if !self.write_frame_to(&mut scratch, &keep, Some(&bytes)) {
                        self.finish();
                        return;
                    }
                    if state == DRAIN {
                        self.draining.store(true, Ordering::Relaxed);
                        let end =
                            ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
                        let _ = self.write_frame_to(&mut scratch, &end, None);
                        if let Ok(mut control) = self.control.lock() {
                            *control = None;
                        }
                        return;
                    }
                }
            }
        });
    }

    /// Opens the internal datagram stream the reference calls `reverse`; its first datagram is
    /// what names the stream, and the portal writes one `Control` per frame after it.
    fn open_control(&self) -> Option<u16> {
        let target =
            ferrox_core::mux::Target::of(ferrox_core::mux::Network::Udp, CONTROL_DOMAIN, 0);
        let (id, _flow) = self.open(target, u32::from(u16::MAX))?;
        if let Ok(mut control) = self.control.lock() {
            *control = Some(id);
        }
        Some(id)
    }

    /// Allocates a flow and sends its `New` frame. `cap` bounds its queued downlink.
    pub(crate) fn open(
        &self,
        target: ferrox_core::mux::Target<'_>,
        cap: u32,
    ) -> Option<(u16, Flow)> {
        if self.done.load(Ordering::Relaxed) || self.draining.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.ids.lock().ok()?.take().ok()?;
        let (down, receiver) = sync_channel(FLOW_PENDING.min(cap as usize).max(1));
        let cancelled = Arc::new(AtomicBool::new(false));
        if let Ok(mut slots) = self.slots.lock() {
            slots.insert(
                id,
                Slot {
                    down,
                    cancelled: Arc::clone(&cancelled),
                },
            );
        } else {
            return None;
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
        let new = ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(target),
            global_id: None,
        };
        let mut scratch = Vec::with_capacity(64);
        if !self.write_frame_to(&mut scratch, &new, None) {
            self.end(id);
            return None;
        }
        Some((id, Flow { down: receiver }))
    }

    pub(crate) fn send(&self, id: u16, data: &[u8]) -> bool {
        if data.len() > ferrox_core::mux::CHUNK_MAX {
            return false;
        }
        let keep = ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        let mut scratch = Vec::with_capacity(64);
        self.write_frame_to(&mut scratch, &keep, Some(data))
    }

    fn sender(&self, id: u16) -> Option<SyncSender<(Vec<u8>, Option<std::net::SocketAddr>)>> {
        self.slots
            .lock()
            .ok()?
            .get(&id)
            .map(|slot| slot.down.clone())
    }

    /// Ends one flow: the downlink queue drops so its pump sees EOF, and the peer learns the id
    /// is done.
    pub(crate) fn end(&self, id: u16) {
        let cancelled = self
            .slots
            .lock()
            .ok()
            .and_then(|mut slots| slots.remove(&id))
            .map(|slot| slot.cancelled);
        if let Some(cancelled) = cancelled {
            cancelled.store(true, Ordering::Relaxed);
            self.active.fetch_sub(1, Ordering::Relaxed);
            if let Ok(mut ids) = self.ids.lock() {
                ids.give_back();
            }
            let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
            let mut scratch = Vec::with_capacity(16);
            let _ = self.write_frame_to(&mut scratch, &end, None);
        }
    }

    /// End a flow without making the reader wait for the writer lock; the id returns to the pool
    /// only after the End frame is written, so a new flow cannot reuse it first.
    fn end_async(self: &Arc<Self>, id: u16) {
        let cancelled = self
            .slots
            .lock()
            .ok()
            .and_then(|mut slots| slots.remove(&id))
            .map(|slot| slot.cancelled);
        let Some(cancelled) = cancelled else {
            return;
        };
        cancelled.store(true, Ordering::Relaxed);
        self.active.fetch_sub(1, Ordering::Relaxed);
        let Ok(mut ends) = self.ends.lock() else {
            return;
        };
        ends.0.push_back(id);
        if ends.1 {
            return;
        }
        ends.1 = true;
        drop(ends);
        let worker = Arc::clone(self);
        std::thread::spawn(move || worker.flush_ends());
    }

    /// Writes the queued End frames on one worker, so a stalled tunnel cannot turn every closed flow into a thread.
    fn flush_ends(self: Arc<Self>) {
        loop {
            let id = {
                let Ok(mut ends) = self.ends.lock() else {
                    return;
                };
                if let Some(id) = ends.0.pop_front() {
                    id
                } else {
                    ends.1 = false;
                    return;
                }
            };
            let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
            let mut scratch = Vec::with_capacity(16);
            let _ = self.write_frame_to(&mut scratch, &end, None);
            if !self.done.load(Ordering::Relaxed) {
                if let Ok(mut ids) = self.ids.lock() {
                    ids.give_back();
                }
            }
        }
    }

    fn write_frame_to(
        &self,
        scratch: &mut Vec<u8>,
        frame: &ferrox_core::mux::Outgoing<'_>,
        data: Option<&[u8]>,
    ) -> bool {
        let Ok(mut writer) = self.writer.lock() else {
            return false;
        };
        if let Some(payload) = data {
            let at = frame.encode_header_into(scratch);
            frame.patch_payload_len(scratch, at, payload.len());
            return crate::proxy::write_all_parts::<2>(&mut **writer, &[scratch, payload]).is_ok();
        }
        scratch.clear();
        scratch.resize(frame.frame_len(0), 0);
        let written = frame.encode_into(None, scratch);
        writer.write_all(&scratch[..written]).is_ok()
    }

    /// The tunnel ended or the session gave up: every queued flow wakes and the picker stops
    /// seeing it.
    fn finish(self: &Arc<Self>) {
        if self.done.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(mut slots) = self.slots.lock() {
            for (_, slot) in slots.drain() {
                slot.cancelled.store(true, Ordering::Relaxed);
            }
        }
        if let Ok(mut ids) = self.ids.lock() {
            *ids = ferrox_core::mux::Ids::new(0);
        }
        (self.closer)();
        if let Some(portal) = self.portal.upgrade() {
            portal.forget(self);
        }
    }

    pub(crate) fn done(&self) -> bool {
        self.done.load(Ordering::Relaxed)
    }

    pub(crate) fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    pub(crate) fn active_connections(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

const READ_SLICE: usize = 32 * 1024;

/// A portal: the tag the bridge's exposed flows are routed to, and the live sessions that can
/// carry one.
pub(crate) struct Portal {
    tag: String,
    domain: String,
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl std::fmt::Debug for Portal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Portal")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Portal {
    pub(crate) fn new(tag: &str) -> Arc<Self> {
        Self::named(tag, "")
    }

    pub(crate) fn named(tag: &str, domain: &str) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.to_owned(),
            domain: domain.to_owned(),
            sessions: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        !self.domain.is_empty() && self.domain.eq_ignore_ascii_case(domain)
    }

    pub(crate) fn attach(self: &Arc<Self>, tunnel: Tunnel) -> Option<Arc<Session>> {
        if self.tag.is_empty() {
            return None;
        }
        Some(Session::attach(self, tunnel))
    }

    pub(crate) fn forget(&self, session: &Arc<Session>) {
        if let Ok(mut list) = self.sessions.lock() {
            list.retain(|seen| !Arc::ptr_eq(seen, session));
        }
    }

    /// The least-loaded live session, skipping a draining one until nothing else is left; the
    /// reference's own two passes.
    #[cfg(test)]
    pub(crate) fn pick(&self) -> Option<Arc<Session>> {
        self.pick_excluding(&[])
    }

    fn pick_excluding(&self, tried: &[Arc<Session>]) -> Option<Arc<Session>> {
        let mut list = self.sessions.lock().ok()?;
        list.retain(|session| !session.done());
        let least = |skip_draining: bool| {
            list.iter()
                .filter(|session| {
                    !session.done()
                        && (!skip_draining || !session.draining())
                        && !tried.iter().any(|seen| Arc::ptr_eq(seen, session))
                })
                .min_by_key(|session| session.active_connections())
                .cloned()
        };
        least(true).or_else(|| least(false))
    }

    /// Open a flow on a session that still accepts it, retrying when a picked session begins
    /// draining between the pick and the open.
    pub(crate) fn open(
        &self,
        target: ferrox_core::mux::Target<'_>,
        cap: u32,
    ) -> Option<(Arc<Session>, u16, Flow)> {
        let mut tried: Vec<Arc<Session>> = Vec::new();
        loop {
            let session = self.pick_excluding(&tried)?;
            if let Some((id, flow)) = session.open(target, cap) {
                return Some((session, id, flow));
            }
            tried.push(session);
        }
    }
}

/// The registry of portals one process serves, keyed by the reverse tag a user names.
#[derive(Debug, Default)]
pub(crate) struct Portals {
    by_tag: HashMap<String, Arc<Portal>>,
}

impl Portals {
    pub(crate) fn insert(&mut self, tag: &str) {
        self.by_tag
            .entry(tag.to_owned())
            .or_insert_with(|| Portal::new(tag));
    }

    /// Register a portal's domain, rejecting a domain another tag already claims so a bridge can
    /// never attach by domain to a portal the route proof did not select.
    pub(crate) fn insert_domain(&mut self, tag: &str, domain: &str) -> Result<(), String> {
        if let Some(existing) = self.by_tag.get(tag) {
            if existing.domain().is_empty() {
                // A tag can be registered by a user before its portal config names a domain.
            } else if existing.domain().eq_ignore_ascii_case(domain) {
                return Ok(());
            } else {
                return Err(format!(
                    "portal `{tag}` already names `{}`, not `{domain}`",
                    existing.domain()
                ));
            }
        }
        if let Some(portal) = self
            .by_tag
            .values()
            .find(|portal| portal.tag() != tag && portal.matches(domain))
        {
            return Err(format!(
                "portal domain `{domain}` is claimed by both `{}` and `{tag}`",
                portal.tag()
            ));
        }
        self.by_tag
            .insert(tag.to_owned(), Portal::named(tag, domain));
        Ok(())
    }

    pub(crate) fn for_domain(&self, domain: &str) -> Option<Arc<Portal>> {
        self.by_tag
            .values()
            .find(|portal| portal.matches(domain))
            .cloned()
    }

    pub(crate) fn get(&self, tag: &str) -> Option<Arc<Portal>> {
        self.by_tag.get(tag).cloned()
    }
}

static REGISTRY: std::sync::OnceLock<Arc<Portals>> = std::sync::OnceLock::new();

/// Publishes the portals one process serves so a protocol front can recognise a portal's domain
/// before it resolves the name or dials anything.
pub(crate) fn install_portals(portals: Arc<Portals>) {
    let _ = REGISTRY.set(portals);
}

/// The portal whose domain names this destination, if the reverse app configured one.
pub(crate) fn portal_for_domain(domain: &str) -> Option<Arc<Portal>> {
    REGISTRY
        .get()
        .and_then(|portals| portals.for_domain(domain))
}

/// The registered portal a rule target names, even when no startup rule named it.
pub(crate) fn portal_for_tag(tag: &str) -> Option<Arc<Portal>> {
    REGISTRY.get().and_then(|portals| portals.get(tag))
}

/// One worker's state, written by its control stream and read by the monitor.
pub(crate) struct WorkerState {
    state: AtomicI32,
    closed: AtomicBool,
    connections: AtomicU32,
    flows: AtomicU32,
    rotated: AtomicU32,
    last_control: Mutex<Instant>,
}

impl WorkerState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicI32::new(ACTIVE),
            closed: AtomicBool::new(false),
            connections: AtomicU32::new(0),
            flows: AtomicU32::new(0),
            rotated: AtomicU32::new(0),
            last_control: Mutex::new(Instant::now()),
        })
    }

    /// One `Control` message from the portal: the state it names, and the liveness a heartbeat
    /// carries whether or not it changes the state.
    pub(crate) fn control(&self, bytes: &[u8]) {
        self.touch();
        let Some(control) = Control::decode(bytes) else {
            self.closed.store(true, Ordering::Relaxed);
            return;
        };
        self.state.store(control.state, Ordering::Relaxed);
    }

    pub(crate) fn touch(&self) {
        if let Ok(mut last) = self.last_control.lock() {
            *last = Instant::now();
        }
    }

    pub(crate) fn closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub(crate) fn active(&self) -> bool {
        self.state.load(Ordering::Relaxed) == ACTIVE && !self.closed.load(Ordering::Relaxed)
    }

    pub(crate) fn draining(&self) -> bool {
        self.state.load(Ordering::Relaxed) == DRAIN && !self.closed.load(Ordering::Relaxed)
    }

    /// A worker the portal stopped heartbeating carries no flow the monitor can route, and its
    /// tunnel may be half-open, so the monitor closes it instead of keeping it forever.
    pub(crate) fn stale(&self, after: Duration) -> bool {
        self.last_control
            .lock()
            .map_or(true, |last| last.elapsed() >= after)
    }

    pub(crate) fn note_connection(self: &Arc<Self>) -> ConnectionGuard {
        self.connections.fetch_add(1, Ordering::Relaxed);
        self.flows.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard {
            worker: Arc::clone(self),
        }
    }

    pub(crate) fn connections(&self) -> u32 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Flows this worker has carried over its lifetime; the monitor rotates a session before the
    /// reference's per-session flow bound, so this counter only rises.
    pub(crate) fn flows(&self) -> u32 {
        self.flows.load(Ordering::Relaxed)
    }

    /// Flows already accounted for by the replacement this worker started, so completed lifetime
    /// flows open at most one tunnel instead of one per monitor tick.
    pub(crate) fn rotated(&self) -> u32 {
        self.rotated.load(Ordering::Relaxed)
    }

    pub(crate) fn mark_rotated(&self, at: u32) {
        self.rotated.store(at, Ordering::Relaxed);
    }
}

/// One live flow on a bridge worker; dropping it releases the slot the monitor counts.
pub(crate) struct ConnectionGuard {
    worker: Arc<WorkerState>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.worker.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The tunnel a worker opened and the state its control stream writes.
pub(crate) struct BridgeHandle {
    pub(crate) tunnel: Tunnel,
    pub(crate) state: Arc<WorkerState>,
    /// The worker this tunnel replaced, so one healthy replacement covers it until it drains.
    pub(crate) replaces: Option<Arc<WorkerState>>,
}

/// Runs one bridge monitor until the process ends. `start` opens the tunnel the monitor then
/// hands to the mux server; it answers `None` when the server refuses.
pub(crate) fn monitor<F>(tag: &str, start: F)
where
    F: Fn(&str) -> Option<BridgeHandle> + Send + 'static,
{
    let owned = tag.to_owned();
    let spawned = owned.clone();
    std::thread::spawn(move || {
        let mut workers: Vec<BridgeHandle> = Vec::new();
        loop {
            workers.retain(|worker| {
                let state = &worker.state;
                let live = if state.draining() {
                    state.connections() > 0 && !state.stale(DRAIN_IDLE)
                } else {
                    !state.stale(WORKER_IDLE) && (state.active() || state.connections() > 0)
                };
                if !live {
                    worker.tunnel.close();
                }
                live
            });
            let mut live = 0u32;
            let mut covered: Vec<Arc<WorkerState>> = Vec::new();
            for worker in &workers {
                if let Some(original) = &worker.replaces {
                    if worker.state.active() && !worker.state.stale(WORKER_IDLE) {
                        covered.push(Arc::clone(original));
                    }
                }
            }
            let mut marks: Vec<(Arc<WorkerState>, u32)> = Vec::new();
            for worker in &workers {
                if worker.state.active() {
                    live = live.saturating_add(1);
                    let flows = worker.state.flows();
                    if flows.saturating_sub(worker.state.rotated()) > 16
                        && !covered
                            .iter()
                            .any(|covered| Arc::ptr_eq(covered, &worker.state))
                    {
                        marks.push((Arc::clone(&worker.state), flows));
                    }
                }
            }
            if live == 0 || !marks.is_empty() {
                if let Some(mut handle) = start(&spawned) {
                    if let Some((state, at)) = marks.into_iter().next() {
                        state.mark_rotated(at);
                        handle.replaces = Some(state);
                    }
                    workers.push(handle);
                }
            }
            std::thread::sleep(MONITOR);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_message_is_the_references_protobuf() {
        let active = Control {
            state: ACTIVE,
            random: vec![0xaa, 0xbb],
        };
        // proto3 omits a zero state; field 99 is a length-delimited 794 (`9a 06`).
        assert_eq!(active.encode(), [0x9a, 0x06, 0x02, 0xaa, 0xbb]);
        let drain = Control {
            state: DRAIN,
            random: vec![0xaa],
        };
        assert_eq!(drain.encode(), [0x08, 0x01, 0x9a, 0x06, 0x01, 0xaa]);
    }

    #[test]
    fn an_absent_state_is_active_and_unknown_fields_are_skipped() {
        let mut bytes = Control {
            state: ACTIVE,
            random: Vec::new(),
        }
        .encode();
        assert_eq!(
            Control::decode(&bytes).map(|control| control.state),
            Some(ACTIVE)
        );
        // field 2, varint; field 3, fixed64; field 4, fixed32; then the state.
        bytes.extend_from_slice(&[0x10, 0x2a, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x08, 0x01]);
        assert_eq!(
            Control::decode(&bytes).map(|control| control.state),
            Some(DRAIN)
        );
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_guessed() {
        assert!(Control::decode(&[0x08]).is_none());
        assert!(Control::decode(&[0x9a, 0x06, 0x04, 0x01]).is_none());
    }

    #[test]
    fn a_loopback_tunnel_carries_bytes_both_ways() {
        let (a, b) = loopback_pair().expect("a loopback pair");
        let a = Tunnel::from_connection(&a).expect("a tunnel");
        let b = Tunnel::from_connection(&b).expect("a tunnel");
        assert!(a.write_all(b"portal"));
        let mut buf = [0u8; 6];
        assert_eq!(b.reader().read(&mut buf).expect("reads"), 6);
        assert_eq!(&buf, b"portal");
        assert!(b.write_all(b"bridge"));
        let mut buf = [0u8; 6];
        assert_eq!(a.reader().read(&mut buf).expect("reads"), 6);
        assert_eq!(&buf, b"bridge");
    }
}

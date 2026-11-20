//! `AnyTLS` over TLS or plain TCP: password prologue, frame multiplexing, and session reuse.

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{self, Destination};
use ferrox_core::tls::{TlsConfig, TlsProvider as _};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

const WASTE: u8 = 0;
const SYN: u8 = 1;
const PSH: u8 = 2;
const FIN: u8 = 3;
const SETTINGS: u8 = 4;
const ALERT: u8 = 5;
const UPDATE_PADDING: u8 = 6;
const SYNACK: u8 = 7;
const HEART_REQUEST: u8 = 8;
const HEART_RESPONSE: u8 = 9;
const SERVER_SETTINGS: u8 = 10;

const VERSION: u32 = 2;
const HEADER: usize = 7;
const MAX_FRAME: usize = 0xffff;
const PASSWORD_LEN: usize = 32;
const POLL: Duration = Duration::from_millis(100);
const OPEN_TIMEOUT: Duration = Duration::from_secs(3);
const STREAM_QUEUE_LIMIT: usize = 64 * 1024;
const QUEUE_CHUNKS: usize = 16;
const SESSION_QUEUE_LIMIT: usize = 8 * 1024 * 1024;

const DEFAULT_PADDING: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

type Reader = Box<dyn Read + Send>;
type Writer = Box<dyn Write + Send>;

#[derive(Clone)]
enum PaddingStep {
    Check,
    Range(usize, usize),
}

enum PaddingSize {
    Check,
    Bytes(usize),
}

#[derive(Clone)]
struct Padding {
    raw: Vec<u8>,
    md5: String,
    stop: u32,
    records: BTreeMap<u32, Vec<PaddingStep>>,
}

impl Padding {
    fn new(raw: &[u8]) -> Option<Self> {
        let scheme = parse_settings(raw);
        if scheme.is_empty() {
            return None;
        }
        let stop = scheme.get("stop")?.parse::<i64>().ok()? as u32;
        let md5 = format!("{:x}", md5::compute(raw));
        let mut records = BTreeMap::new();
        for (key, value) in &scheme {
            let Ok(packet) = key.parse::<u32>() else {
                continue;
            };
            if packet.to_string() != *key {
                continue;
            }
            let mut steps = Vec::new();
            for item in value.split(',') {
                if item == "c" {
                    steps.push(PaddingStep::Check);
                    continue;
                }
                let Some((low, high)) = item.split_once('-') else {
                    continue;
                };
                let (Ok(low), Ok(high)) = (low.parse::<i64>(), high.parse::<i64>()) else {
                    continue;
                };
                let (low, high) = if low > high { (high, low) } else { (low, high) };
                if low <= 0 || high > (1 << 20) {
                    continue;
                }
                steps.push(PaddingStep::Range(low as usize, high as usize));
            }
            if !steps.is_empty() {
                records.insert(packet, steps);
            }
        }
        Some(Self {
            raw: raw.to_vec(),
            md5,
            stop,
            records,
        })
    }

    fn default_scheme() -> Self {
        Self::new(DEFAULT_PADDING).expect("the default padding scheme parses")
    }

    fn handshake_padding(&self) -> usize {
        match self.records.get(&0).and_then(|steps| steps.first()) {
            Some(PaddingStep::Range(low, high)) => a_size(*low, *high),
            _ => 0,
        }
    }

    fn steps(&self, packet: u32) -> Vec<PaddingSize> {
        self.records
            .get(&packet)
            .map(|steps| {
                steps
                    .iter()
                    .map(|step| match step {
                        PaddingStep::Check => PaddingSize::Check,
                        PaddingStep::Range(low, high) => PaddingSize::Bytes(a_size(*low, *high)),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn a_size(low: usize, high: usize) -> usize {
    if high <= low {
        return low;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return low;
    }
    low + (u64::from_le_bytes(bytes) % (high - low) as u64) as usize
}

#[derive(Clone)]
enum Terminal {
    Eof,
    Failed(String),
}

struct QueueUsage {
    bytes: usize,
    closed: bool,
}

struct QueueBudget {
    limit: usize,
    used: Mutex<QueueUsage>,
    wake: Condvar,
}

impl QueueBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: Mutex::new(QueueUsage {
                bytes: 0,
                closed: false,
            }),
            wake: Condvar::new(),
        }
    }

    fn reserve(&self, bytes: usize, alive: &AtomicBool) -> bool {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        while used.bytes.saturating_add(bytes) > self.limit
            && !used.closed
            && alive.load(Ordering::Relaxed)
        {
            used = self
                .wake
                .wait_timeout(used, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if used.closed || !alive.load(Ordering::Relaxed) {
            return false;
        }
        used.bytes += bytes;
        true
    }

    fn release(&self, bytes: usize) {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        used.bytes = used.bytes.saturating_sub(bytes);
        drop(used);
        self.wake.notify_all();
    }

    fn close(&self) {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        used.closed = true;
        drop(used);
        self.wake.notify_all();
    }
}

struct StreamInner {
    queue: VecDeque<Vec<u8>>,
    head: usize,
    queued: usize,
    terminal: Option<Terminal>,
}

struct StreamState {
    inner: Mutex<StreamInner>,
    wake: Condvar,
    armed: AtomicBool,
    budget: Arc<QueueBudget>,
}

impl StreamState {
    fn new(budget: Arc<QueueBudget>) -> Self {
        Self {
            inner: Mutex::new(StreamInner {
                queue: VecDeque::new(),
                head: 0,
                queued: 0,
                terminal: None,
            }),
            wake: Condvar::new(),
            armed: AtomicBool::new(false),
            budget,
        }
    }

    fn push(&self, data: Vec<u8>, alive: &AtomicBool) {
        if data.is_empty() {
            return;
        }
        if !self.budget.reserve(data.len(), alive) {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        while inner.terminal.is_none()
            && inner.queued.saturating_add(data.len()) > STREAM_QUEUE_LIMIT
            && alive.load(Ordering::Relaxed)
        {
            inner = self
                .wake
                .wait_timeout(inner, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if inner.terminal.is_some() || !alive.load(Ordering::Relaxed) {
            drop(inner);
            self.budget.release(data.len());
            return;
        }
        let state = &mut *inner;
        state.queued += data.len();
        // A frame keeps its own buffer until the stream holds QUEUE_CHUNKS of them; past that a small frame rides the tail, so a one-byte-frame peer cannot buy one allocation per byte.
        if state.queue.len() < QUEUE_CHUNKS {
            state.queue.push_back(data);
        } else if let Some(tail) = state.queue.back_mut() {
            tail.extend_from_slice(&data);
        }
        drop(inner);
        self.wake.notify_all();
    }

    fn end(&self, terminal: Terminal) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.terminal.is_none() {
            inner.terminal = Some(terminal);
        }
        drop(inner);
        self.wake.notify_all();
    }

    fn read(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
        alive: &AtomicBool,
    ) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if !inner.queue.is_empty() {
                let state = &mut *inner;
                let mut filled = 0;
                while filled < buf.len() {
                    let Some(front) = state.queue.front() else {
                        break;
                    };
                    let take = (front.len() - state.head).min(buf.len() - filled);
                    buf[filled..filled + take]
                        .copy_from_slice(&front[state.head..state.head + take]);
                    filled += take;
                    state.head += take;
                    let drained = state.head == front.len();
                    if drained {
                        state.head = 0;
                        state.queue.pop_front();
                    }
                }
                state.queued -= filled;
                drop(inner);
                self.budget.release(filled);
                self.wake.notify_all();
                return Ok(filled);
            }
            if let Some(terminal) = &inner.terminal {
                return match terminal {
                    Terminal::Eof => Ok(0),
                    Terminal::Failed(why) => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        why.clone(),
                    )),
                };
            }
            if !alive.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "anytls session closed",
                ));
            }
            let wait = timeout.unwrap_or(POLL);
            let (next, result) = self
                .wake
                .wait_timeout(inner, wait)
                .unwrap_or_else(PoisonError::into_inner);
            inner = next;
            if result.timed_out() && timeout.is_some() && inner.queue.is_empty() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
        }
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        let bytes = self
            .inner
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .queued;
        self.budget.release(bytes);
    }
}

struct Shared {
    writer: Mutex<Option<Writer>>,
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
    alive: AtomicBool,
    next_id: AtomicU32,
    settings_received: AtomicBool,
    peer_version: AtomicU32,
    padding: Mutex<Padding>,
    pending: Mutex<Option<Vec<u8>>>,
    packet_count: AtomicU32,
    send_padding: AtomicBool,
    queue_budget: Arc<QueueBudget>,
    shutdown: Option<Connection>,
}

impl Shared {
    fn new(writer: Writer, padding: Padding, server: bool) -> Self {
        Self::with_shutdown(writer, padding, server, None)
    }

    fn with_shutdown(
        writer: Writer,
        padding: Padding,
        server: bool,
        shutdown: Option<Connection>,
    ) -> Self {
        Self {
            writer: Mutex::new(Some(writer)),
            streams: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            next_id: AtomicU32::new(1),
            settings_received: AtomicBool::new(false),
            peer_version: AtomicU32::new(0),
            padding: Mutex::new(padding),
            pending: Mutex::new(None),
            packet_count: AtomicU32::new(0),
            send_padding: AtomicBool::new(!server),
            queue_budget: Arc::new(QueueBudget::new(SESSION_QUEUE_LIMIT)),
            shutdown,
        }
    }

    fn stream_state(&self) -> StreamState {
        StreamState::new(Arc::clone(&self.queue_budget))
    }

    fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    fn write_frame(&self, command: u8, stream: u32, payload: &[u8]) -> std::io::Result<()> {
        if payload.len() > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "anytls frame too large",
            ));
        }
        self.write_packet(&frame_bytes(command, stream, payload))
    }

    fn queue_pending(&self, packet: Vec<u8>) {
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(packet);
    }

    fn has_pending(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        let result = self.write_packet_locked(packet);
        if result.is_err() {
            self.shutdown("anytls session write failed");
        }
        result
    }

    fn write_packet_locked(&self, packet: &[u8]) -> std::io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(writer) = writer.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "anytls session closed",
            ));
        };
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let combined = pending.map(|mut pending| {
            pending.extend_from_slice(packet);
            pending
        });
        let packet = combined.as_deref().unwrap_or(packet);
        if !self.send_padding.load(Ordering::Relaxed) {
            writer.write_all(packet)?;
            return writer.flush();
        }
        let count = self.packet_count.fetch_add(1, Ordering::Relaxed) + 1;
        let padding = self
            .padding
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if count >= padding.stop {
            self.send_padding.store(false, Ordering::Relaxed);
            writer.write_all(packet)?;
            return writer.flush();
        }
        let mut data = packet;
        for size in padding.steps(count) {
            let size = match size {
                PaddingSize::Check => {
                    if data.is_empty() {
                        break;
                    }
                    continue;
                }
                PaddingSize::Bytes(size) => size,
            };
            if data.len() > size {
                writer.write_all(&data[..size])?;
                data = &data[size..];
                continue;
            }
            let records = size.div_ceil(MAX_FRAME);
            let mut record = Vec::with_capacity(size + records * HEADER);
            if data.is_empty() {
                let mut remaining = size;
                while remaining > 0 {
                    let waste = remaining.min(MAX_FRAME);
                    push_waste(&mut record, waste);
                    remaining -= waste;
                }
            } else {
                record.extend_from_slice(data);
                data = &[];
                let mut remaining = size.saturating_sub(record.len());
                while remaining > HEADER {
                    let waste = (remaining - HEADER).min(MAX_FRAME);
                    push_waste(&mut record, waste);
                    remaining -= HEADER + waste;
                }
            }
            writer.write_all(&record)?;
        }
        if !data.is_empty() {
            writer.write_all(data)?;
        }
        writer.flush()
    }

    fn insert_stream(&self, id: u32, state: &Arc<StreamState>) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::clone(state));
    }

    fn remove_stream(&self, id: u32) {
        if let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
        {
            state.end(Terminal::Eof);
        }
    }

    fn shutdown(&self, why: &str) {
        if !self.alive.swap(false, Ordering::SeqCst) {
            return;
        }
        self.queue_budget.close();
        if let Some(raw) = self.shutdown.as_ref() {
            let _ = raw.shutdown(Shutdown::Both);
        }
        if let Some(writer) = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            drop(writer);
        }
        let states = {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *streams)
        };
        for state in states.into_values() {
            state.end(Terminal::Failed(why.to_owned()));
        }
    }
}

struct Session {
    shared: Arc<Shared>,
    owner: Option<Weak<AnyTlsOut>>,
}

impl Session {
    fn alive(&self) -> bool {
        self.shared.alive()
    }

    fn open_stream(self: &Arc<Self>, destination: &Destination) -> Option<AnyTlsStream> {
        if !self.alive() {
            return None;
        }
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(self.shared.stream_state());
        self.shared.insert_stream(id, &state);
        let syn = frame_bytes(SYN, id, &[]);
        let mut address = Vec::new();
        if encode_address(destination, &mut address).is_err() {
            self.shared.remove_stream(id);
            return None;
        }
        let psh = frame_bytes(PSH, id, &address);
        let sent = if self.shared.has_pending() {
            let mut packet = syn;
            packet.extend_from_slice(&psh);
            self.shared.write_packet(&packet)
        } else {
            self.shared
                .write_packet(&syn)
                .and_then(|()| self.shared.write_packet(&psh))
        };
        if sent.is_err() {
            self.shared.remove_stream(id);
            return None;
        }
        Some(AnyTlsStream {
            session: Arc::clone(self),
            id,
            state,
            fin_sent: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
            holders: Arc::new(AtomicUsize::new(1)),
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shared.shutdown("session closed");
    }
}

pub(crate) struct AnyTlsStream {
    session: Arc<Session>,
    id: u32,
    state: Arc<StreamState>,
    fin_sent: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    holders: Arc<AtomicUsize>,
}

impl Clone for AnyTlsStream {
    fn clone(&self) -> Self {
        self.holders.fetch_add(1, Ordering::Relaxed);
        Self {
            session: Arc::clone(&self.session),
            id: self.id,
            state: Arc::clone(&self.state),
            fin_sent: Arc::clone(&self.fin_sent),
            closed: Arc::clone(&self.closed),
            holders: Arc::clone(&self.holders),
        }
    }
}

impl AnyTlsStream {
    fn finish_write(&self) {
        if self.fin_sent.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.session.shared.alive() {
            let _ = self.session.shared.write_frame(FIN, self.id, &[]);
        }
    }

    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.finish_write();
        self.session.shared.remove_stream(self.id);
        if let Some(owner) = self.session.owner.as_ref().and_then(Weak::upgrade) {
            owner.release(Arc::clone(&self.session));
        }
    }

    fn read_until(&self, buf: &mut [u8], deadline: Instant) -> std::io::Result<usize> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
            }
            match self
                .state
                .read(buf, Some(left.min(POLL)), &self.session.shared.alive)
            {
                Err(error) if !is_wait(&error) => return Err(error),
                Err(_) => {}
                Ok(n) => return Ok(n),
            }
        }
    }

    fn read_exact(&self, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
        let mut at = 0;
        while at < buf.len() {
            match self.read_until(&mut buf[at..], deadline)? {
                0 => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                n => at += n,
            }
        }
        Ok(())
    }

    fn synack(&self, payload: &[u8]) {
        if self.session.shared.alive()
            && self.session.shared.peer_version.load(Ordering::Relaxed) >= VERSION
        {
            let _ = self.session.shared.write_frame(SYNACK, self.id, payload);
        }
    }
}

impl Read for AnyTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // A relay lane reads this stream to learn whether the peer has bytes, so its corpus matches a socket's armed read rather than a frame's wait.
        let timeout = self
            .state
            .armed
            .load(Ordering::Relaxed)
            .then_some(crate::budgets::RELAY_POLL);
        self.state.read(buf, timeout, &self.session.shared.alive)
    }
}

impl Write for AnyTlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut packet = Vec::with_capacity(buf.len() + HEADER);
        for chunk in buf.chunks(MAX_FRAME) {
            push_frame(&mut packet, PSH, self.id, chunk);
        }
        self.session.shared.write_packet(&packet)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let result = {
            let mut writer = self
                .session
                .shared
                .writer
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match writer.as_mut() {
                Some(writer) => writer.flush(),
                None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            }
        };
        if result.is_err() {
            self.session.shared.shutdown("anytls session write failed");
        }
        result
    }
}

impl proxy::Duplicate for AnyTlsStream {
    fn duplicate(&self) -> Option<Self> {
        Some(self.clone())
    }

    fn arm_read(&self) {
        self.state.armed.store(true, Ordering::Relaxed);
    }
}

impl proxy::HalfShut for AnyTlsStream {
    // A FIN ends the whole stream, so only drop may send one.
    fn spill(&self) {}
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if self.holders.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.close();
        }
    }
}

pub(crate) struct AnyTlsOut {
    address: String,
    port: u16,
    password: [u8; PASSWORD_LEN],
    client: String,
    tls: Arc<TlsConfig>,
    padding: Padding,
    pool: Mutex<Vec<Arc<Session>>>,
}

impl std::fmt::Debug for AnyTlsOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsOut")
            .field("address", &self.address)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl AnyTlsOut {
    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        proxy::resolve_outbound(&self.address, self.port)
    }

    pub(crate) fn dial(self: &Arc<Self>, client: &Connection, target: &Destination) {
        let Some(stream) = self.open(target) else {
            return;
        };
        proxy::relay_anytls_stream(client, stream, None);
    }

    fn open(self: &Arc<Self>, target: &Destination) -> Option<AnyTlsStream> {
        for _ in 0..2 {
            let session = self.session()?;
            if let Some(stream) = session.open_stream(target) {
                return Some(stream);
            }
            session.shared.shutdown("session could not open the stream");
        }
        None
    }

    fn session(self: &Arc<Self>) -> Option<Arc<Session>> {
        let mut pool = self.pool.lock().ok()?;
        while let Some(session) = pool.pop() {
            if session.alive() {
                return Some(session);
            }
        }
        drop(pool);
        self.connect()
    }

    fn connect(self: &Arc<Self>) -> Option<Arc<Session>> {
        let server = proxy::resolve_outbound(&self.address, self.port)?;
        let session = proxy::anytls_dial_session(&server, &self.tls)?;
        let (mut reader, mut writer) = proxy::anytls_client_halves(session)?;
        let padding_len = self.padding.handshake_padding().min(u16::MAX as usize);
        let mut prologue = Vec::with_capacity(PASSWORD_LEN + 2 + padding_len);
        prologue.extend_from_slice(&self.password);
        prologue.extend_from_slice(&(padding_len as u16).to_be_bytes());
        prologue.resize(prologue.len() + padding_len, 0);
        write_all_retry(&mut *writer, &prologue).ok()?;
        let shared = Arc::new(Shared::new(writer, self.padding.clone(), false));
        let settings = settings_bytes(VERSION, Some(&self.client), Some(&self.padding.md5));
        if settings.len() > MAX_FRAME {
            return None;
        }
        shared.queue_pending(frame_bytes(SETTINGS, 0, &settings));
        let session = Arc::new(Session {
            shared: Arc::clone(&shared),
            owner: Some(Arc::downgrade(self)),
        });
        let read_shared = Arc::clone(&shared);
        std::thread::spawn(move || read_loop(&mut *reader, &read_shared));
        Some(session)
    }

    fn release(&self, session: Arc<Session>) {
        if session.alive() {
            if let Ok(mut pool) = self.pool.lock() {
                if pool.len() < 8 {
                    pool.push(session);
                }
            }
        }
    }
}

pub(crate) fn outbound(root: &Json) -> Result<Option<AnyTlsOut>, String> {
    let Some(first) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|list| list.first())
    else {
        return Ok(None);
    };
    if first.get("protocol").and_then(Json::as_str) != Some("anytls") {
        return Ok(None);
    }
    let settings = first
        .get("settings")
        .ok_or("anytls outbound has no settings")?;
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
        .ok_or("anytls outbound has no server address")?;
    let port = field("port")
        .or_else(|| field("server_port"))
        .and_then(Json::as_port)
        .ok_or("anytls outbound has no server port")?;
    let password = field("password")
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("anytls outbound has no password")?;
    let tls = crate::config::outbound_tls(first, address)?;
    let client = field("client")
        .or_else(|| field("client_metadata"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let padding = field("padding_scheme")
        .or_else(|| field("paddingScheme"))
        .and_then(padding_scheme)
        .and_then(|raw| Padding::new(raw.as_bytes()))
        .unwrap_or_else(Padding::default_scheme);
    Ok(Some(AnyTlsOut {
        address: address.to_owned(),
        port,
        password: password_hash(password),
        client,
        tls,
        padding,
        pool: Mutex::new(Vec::new()),
    }))
}

pub(crate) fn serve_inbound(
    address: &str,
    inbound: &Json,
    path: &str,
    freedom: bool,
    stop: Option<Arc<proxy::Stop>>,
) -> bool {
    let settings = inbound.get("settings");
    let mut passwords = Vec::new();
    if let Some(listed) = settings
        .and_then(|node| node.get("users").or_else(|| node.get("clients")))
        .and_then(Json::as_arr)
    {
        for user in listed {
            if let Some(password) = user
                .get("password")
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty())
            {
                passwords.push(password_hash(password));
            }
        }
    }
    if passwords.is_empty() {
        if let Some(password) = settings
            .and_then(|node| node.get("password"))
            .and_then(Json::as_str)
            .filter(|value| !value.is_empty())
        {
            passwords.push(password_hash(password));
        }
    }
    if passwords.is_empty() {
        eprintln!("anytls inbound in {path} names no password: serves nothing");
        return false;
    }
    let security = crate::config::stream_security(inbound);
    let tls = if security == "tls" {
        if let Some(identity) = crate::config::inbound_tls_identity(inbound) {
            Some(identity)
        } else {
            eprintln!("unreadable anytls tls identity in {path}: serves nothing");
            return false;
        }
    } else if security.is_empty() || security == "none" {
        None
    } else {
        eprintln!("anytls inbound in {path} asks for `{security}`: serves nothing");
        return false;
    };
    let padding = settings
        .and_then(|node| {
            node.get("padding_scheme")
                .or_else(|| node.get("paddingScheme"))
        })
        .and_then(padding_scheme)
        .and_then(|raw| Padding::new(raw.as_bytes()))
        .unwrap_or_else(Padding::default_scheme);
    let target = match crate::conn::parse_target(address) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("anytls inbound in {path} cannot resolve {address}: {error}");
            return false;
        }
    };
    let listener = match crate::conn::Listener::bind(&target) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("anytls inbound in {path} cannot listen on {address}: {error}");
            return false;
        }
    };
    let halted = stop.as_ref().map(|stop| stop.shared());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if halted
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::SeqCst))
            {
                break;
            }
            let Ok(stream) = stream else {
                continue;
            };
            let tls = tls.clone();
            let passwords = passwords.clone();
            let padding = padding.clone();
            std::thread::spawn(move || {
                serve_connection(stream, tls, &passwords, padding, freedom);
            });
        }
        drop(listener);
        if let Some(stop) = stop {
            stop.mark_closed();
        }
    });
    true
}

type ServerIdentity = Arc<ferrox_core::tls::TlsServerConfig>;

fn serve_connection(
    stream: Connection,
    tls: Option<ServerIdentity>,
    passwords: &[[u8; PASSWORD_LEN]],
    padding: Padding,
    freedom: bool,
) {
    let deadline = Instant::now() + crate::budgets::handshake();
    let Ok(raw) = stream.try_clone() else {
        return;
    };
    if raw
        .set_read_timeout(Some(crate::budgets::handshake()))
        .is_err()
    {
        return;
    }
    let (mut reader, writer): (Reader, Writer) = if let Some(identity) = tls {
        let Ok(mut session) = ferrox_core::tls::accept(identity.as_ref(), stream) else {
            return;
        };
        if session.handshake().is_err() {
            return;
        }
        let Some(halves) = proxy::anytls_server_halves(session) else {
            return;
        };
        halves
    } else {
        let Ok(writer) = stream.try_clone() else {
            return;
        };
        (Box::new(stream), Box::new(writer))
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if raw
        .set_read_timeout(Some(left.max(Duration::from_millis(1))))
        .is_err()
    {
        return;
    }
    let mut prologue = [0u8; PASSWORD_LEN + 2];
    if read_exact_deadline(&mut *reader, &mut prologue, deadline).is_err() {
        return;
    }
    if !passwords.iter().any(|password| {
        let mut diff = 0u8;
        for (left, right) in password.iter().zip(&prologue[..PASSWORD_LEN]) {
            diff |= left ^ right;
        }
        diff == 0
    }) {
        return;
    }
    let padding_len = usize::from(u16::from_be_bytes([
        prologue[PASSWORD_LEN],
        prologue[PASSWORD_LEN + 1],
    ]));
    if padding_len > 0 {
        let mut discard = [0u8; 1024];
        let mut left = padding_len;
        while left > 0 {
            let take = left.min(discard.len());
            if read_exact_deadline(&mut *reader, &mut discard[..take], deadline).is_err() {
                return;
            }
            left -= take;
        }
    }
    if raw.set_read_timeout(None).is_err() {
        return;
    }
    let session = Arc::new(Session {
        shared: Arc::new(Shared::with_shutdown(writer, padding, true, Some(raw))),
        owner: None,
    });
    let context = Arc::new(ServerContext { freedom });
    read_server(&mut *reader, &session, &context);
}

struct ServerContext {
    freedom: bool,
}

fn read_server(reader: &mut dyn Read, session: &Arc<Session>, context: &Arc<ServerContext>) {
    let shared = Arc::clone(&session.shared);
    while let Ok(Some(frame)) = read_frame(reader, &shared.alive) {
        if !shared.alive() {
            break;
        }
        match frame.command {
            PSH => {
                let state = shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&frame.stream)
                    .cloned();
                if let Some(state) = state {
                    state.push(frame.payload, &shared.alive);
                }
            }
            SYN => {
                if !shared.settings_received.load(Ordering::Relaxed) {
                    let _ =
                        shared.write_frame(ALERT, 0, b"anytls: client did not send its settings");
                    break;
                }
                if shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains_key(&frame.stream)
                {
                    continue;
                }
                let state = Arc::new(shared.stream_state());
                shared.insert_stream(frame.stream, &state);
                let stream = AnyTlsStream {
                    session: Arc::clone(session),
                    id: frame.stream,
                    state,
                    fin_sent: Arc::new(AtomicBool::new(false)),
                    closed: Arc::new(AtomicBool::new(false)),
                    holders: Arc::new(AtomicUsize::new(1)),
                };
                let context = Arc::clone(context);
                std::thread::spawn(move || serve_stream(stream, &context));
            }
            FIN => {
                let state = shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&frame.stream);
                if let Some(state) = state {
                    state.end(Terminal::Eof);
                }
            }
            SETTINGS => {
                if frame.payload.is_empty() {
                    continue;
                }
                let settings = parse_settings(&frame.payload);
                shared.settings_received.store(true, Ordering::Relaxed);
                let padding = shared
                    .padding
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                if settings.get("padding-md5").map(String::as_str) != Some(padding.md5.as_str())
                    && padding.raw.len() <= MAX_FRAME
                {
                    let _ = shared.write_frame(UPDATE_PADDING, 0, &padding.raw);
                }
                if let Some(version) = settings.get("v").and_then(|text| text.parse::<u32>().ok()) {
                    if version >= VERSION {
                        shared.peer_version.store(version, Ordering::Relaxed);
                        let answer = settings_bytes(VERSION, None, None);
                        let _ = shared.write_frame(SERVER_SETTINGS, 0, &answer);
                    }
                }
            }
            HEART_REQUEST => {
                let _ = shared.write_frame(HEART_RESPONSE, frame.stream, &[]);
            }
            ALERT => break,
            _ => {}
        }
    }
    shared.shutdown("anytls session ended");
}

fn serve_stream(stream: AnyTlsStream, context: &ServerContext) {
    let deadline = Instant::now() + OPEN_TIMEOUT;
    let Ok(destination) = read_address_stream(&stream, deadline) else {
        stream.synack(b"anytls: bad destination");
        stream.close();
        return;
    };
    if !context.freedom {
        stream.synack(b"anytls: freedom is disabled");
        stream.close();
        return;
    }
    let resolved = match destination {
        Address::Name(host, port) => proxy::resolve_outbound(&host, port),
        Address::Address(address) => Some(address),
    };
    let Some(upstream) = resolved.and_then(|address| proxy::dial_or_report(&address)) else {
        stream.synack(b"anytls: dial failed");
        stream.close();
        return;
    };
    stream.synack(&[]);
    proxy::relay_anytls_stream(&upstream, stream, None);
}

fn read_loop(reader: &mut dyn Read, shared: &Arc<Shared>) {
    while shared.alive() {
        let Ok(Some(frame)) = read_frame(reader, &shared.alive) else {
            break;
        };
        match frame.command {
            PSH => {
                let state = shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&frame.stream)
                    .cloned();
                if let Some(state) = state {
                    state.push(frame.payload, &shared.alive);
                }
            }
            FIN => {
                let state = shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&frame.stream);
                if let Some(state) = state {
                    state.end(Terminal::Eof);
                }
            }
            SYNACK => {
                if frame.payload.is_empty() {
                    continue;
                }
                let why = String::from_utf8_lossy(&frame.payload).into_owned();
                let state = shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&frame.stream);
                if shared.alive() {
                    let _ = shared.write_frame(FIN, frame.stream, &[]);
                }
                if let Some(state) = state {
                    state.end(Terminal::Failed(why));
                }
            }
            UPDATE_PADDING => {
                if let Some(padding) = Padding::new(&frame.payload) {
                    *shared
                        .padding
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = padding;
                }
            }
            ALERT => {
                let why = String::from_utf8_lossy(&frame.payload).into_owned();
                shared.shutdown(&why);
                return;
            }
            HEART_REQUEST => {
                let _ = shared.write_frame(HEART_RESPONSE, frame.stream, &[]);
            }
            _ => {}
        }
    }
    shared.shutdown("anytls session ended");
}

struct Frame {
    command: u8,
    stream: u32,
    payload: Vec<u8>,
}

fn frame_bytes(command: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    push_frame(&mut frame, command, stream, payload);
    frame
}

fn push_frame(out: &mut Vec<u8>, command: u8, stream: u32, payload: &[u8]) {
    push_header(out, command, stream, payload.len());
    out.extend_from_slice(payload);
}

fn push_waste(out: &mut Vec<u8>, len: usize) {
    push_header(out, WASTE, 0, len);
    out.resize(out.len() + len, 0);
}

fn push_header(out: &mut Vec<u8>, command: u8, stream: u32, length: usize) {
    out.push(command);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(&(length as u16).to_be_bytes());
}

fn read_frame(reader: &mut dyn Read, alive: &AtomicBool) -> std::io::Result<Option<Frame>> {
    let mut header = [0u8; HEADER];
    let mut at = 0;
    while at < header.len() {
        if !alive.load(Ordering::Relaxed) {
            return Ok(None);
        }
        match reader.read(&mut header[at..]) {
            Ok(0) => {
                if at == 0 {
                    return Ok(None);
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            Ok(n) => at += n,
            Err(error) => {
                if !is_wait(&error) {
                    return Err(error);
                }
            }
        }
    }
    let command = header[0];
    let stream = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    let mut payload = vec![0u8; length];
    let mut at = 0;
    while at < length {
        if !alive.load(Ordering::Relaxed) {
            return Ok(None);
        }
        match reader.read(&mut payload[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => at += n,
            Err(error) => {
                if !is_wait(&error) {
                    return Err(error);
                }
            }
        }
    }
    Ok(Some(Frame {
        command,
        stream,
        payload,
    }))
}

fn read_exact_deadline(
    reader: &mut dyn Read,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        match reader.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => at += n,
            Err(error) => {
                if !is_wait(&error) {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

fn write_all_retry(writer: &mut dyn Write, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match writer.write(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(n) => buf = &buf[n..],
            Err(error) => {
                if !is_wait(&error) {
                    return Err(error);
                }
            }
        }
    }
    writer.flush()
}

fn is_wait(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

enum Address {
    Name(String, u16),
    Address(SocketAddr),
}

fn encode_address(destination: &Destination, out: &mut Vec<u8>) -> Result<(), ()> {
    match destination {
        Destination::Name(host, port) => {
            let host = host.as_bytes();
            if host.len() > 255 {
                return Err(());
            }
            out.push(3);
            out.push(host.len() as u8);
            out.extend_from_slice(host);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Destination::Address(address) => match address.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
        },
    }
    Ok(())
}

fn read_address_from(
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<()>,
) -> std::io::Result<Address> {
    let mut kind = [0u8; 1];
    read(&mut kind)?;
    let host = match kind[0] {
        1 => {
            let mut octets = [0u8; 4];
            read(&mut octets)?;
            std::net::IpAddr::V4(octets.into()).to_string()
        }
        4 => {
            let mut octets = [0u8; 16];
            read(&mut octets)?;
            std::net::IpAddr::V6(octets.into()).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            read(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            read(&mut name)?;
            String::from_utf8(name)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?
        }
        _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    };
    let mut port = [0u8; 2];
    read(&mut port)?;
    let port = u16::from_be_bytes(port);
    if kind[0] == 3 {
        return Ok(Address::Name(host, port));
    }
    let ip = host
        .parse()
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok(Address::Address(SocketAddr::new(ip, port)))
}

fn read_address_stream(stream: &AnyTlsStream, deadline: Instant) -> std::io::Result<Address> {
    read_address_from(|buf| stream.read_exact(buf, deadline))
}

#[cfg(test)]
fn read_address(reader: &mut dyn Read, deadline: Instant) -> std::io::Result<Address> {
    read_address_from(|buf| read_exact_deadline(reader, buf, deadline))
}

fn password_hash(password: &str) -> [u8; PASSWORD_LEN] {
    let digest = Sha256::digest(password.as_bytes());
    let mut hash = [0u8; PASSWORD_LEN];
    hash.copy_from_slice(&digest);
    hash
}

fn settings_bytes(version: u32, client: Option<&str>, padding_md5: Option<&str>) -> Vec<u8> {
    let mut fields = BTreeMap::new();
    fields.insert("v".to_owned(), version.to_string());
    if let Some(client) = client {
        fields.insert("client".to_owned(), client.to_owned());
    }
    if let Some(md5) = padding_md5 {
        fields.insert("padding-md5".to_owned(), md5.to_owned());
    }
    let mut out = String::new();
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
    }
    out.into_bytes()
}

fn padding_scheme(node: &Json) -> Option<String> {
    node.as_str().map(str::to_owned).or_else(|| {
        let lines = node
            .as_arr()?
            .iter()
            .map(Json::as_str)
            .collect::<Option<Vec<_>>>()?;
        Some(lines.join("\n"))
    })
}

fn parse_settings(payload: &[u8]) -> BTreeMap<String, String> {
    let mut parsed = BTreeMap::new();
    let text = String::from_utf8_lossy(payload);
    for line in text.split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            parsed.insert(key.to_owned(), value.to_owned());
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sink(Arc<Mutex<Vec<u8>>>);

    struct OneByte {
        bytes: Vec<u8>,
        at: usize,
    }

    impl Read for OneByte {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.at == self.bytes.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.bytes[self.at];
            self.at += 1;
            Ok(1)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_stream(shared: &Arc<Shared>, id: u32) -> AnyTlsStream {
        AnyTlsStream {
            session: Arc::new(Session {
                shared: Arc::clone(shared),
                owner: None,
            }),
            id,
            state: Arc::new(shared.stream_state()),
            fin_sent: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
            holders: Arc::new(AtomicUsize::new(1)),
        }
    }

    #[test]
    fn a_padding_record_matches_the_reference_arithmetic() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let padding = Padding::new(b"stop=8\n1=100-100").expect("parses");
        let shared = Shared::new(Box::new(Sink(Arc::clone(&written))), padding, false);
        shared.write_frame(PSH, 1, b"abc").expect("writes");
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes.len(), 100);
        assert_eq!(bytes[0], PSH);
        assert_eq!(u16::from_be_bytes([bytes[5], bytes[6]]), 3);
        assert_eq!(&bytes[7..10], b"abc");
        assert_eq!(bytes[10], WASTE);
        assert_eq!(u16::from_be_bytes([bytes[15], bytes[16]]), 83);
        assert!(bytes[17..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_duplicate_holds_the_stream_open() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(Arc::clone(&written))),
            Padding::new(b"stop=0").expect("parses"),
            false,
        ));
        let session = Arc::new(Session {
            shared: Arc::clone(&shared),
            owner: None,
        });
        let stream = AnyTlsStream {
            session,
            id: 7,
            state: Arc::new(shared.stream_state()),
            fin_sent: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
            holders: Arc::new(AtomicUsize::new(1)),
        };
        let duplicate = stream.clone();
        drop(stream);
        assert!(written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
        drop(duplicate);
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes[0], FIN);
        assert_eq!(bytes.len(), HEADER);
    }

    #[test]
    fn a_spill_keeps_the_stream_writable() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(Arc::clone(&written))),
            Padding::new(b"stop=0").expect("parses"),
            false,
        ));
        let mut stream = test_stream(&shared, 9);
        crate::proxy::HalfShut::spill(&stream);
        stream.write_all(b"still open").expect("writes");
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes[0], PSH);
        assert_eq!(u16::from_be_bytes([bytes[5], bytes[6]]), 10);
        assert_eq!(&bytes[7..17], b"still open");
        assert!(bytes.iter().all(|byte| *byte != FIN));
    }

    #[test]
    fn a_synack_waits_for_a_v2_peer() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(Arc::clone(&written))),
            Padding::new(b"stop=0").expect("parses"),
            true,
        ));
        let stream = test_stream(&shared, 1);
        stream.synack(&[]);
        assert!(written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
        shared.peer_version.store(VERSION, Ordering::Relaxed);
        stream.synack(&[]);
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes[0], SYNACK);
        assert_eq!(bytes.len(), HEADER);
    }

    #[test]
    fn the_default_padding_md5_is_the_reference_one() {
        assert_eq!(
            Padding::default_scheme().md5,
            "75cff2ad89aadf5e257059ee571ebe11"
        );
    }

    #[test]
    fn settings_are_sorted_and_round_trip() {
        let raw = settings_bytes(2, Some("ferrox"), Some("abc"));
        assert_eq!(raw, b"client=ferrox\npadding-md5=abc\nv=2");
        let parsed = parse_settings(&raw);
        assert_eq!(parsed.get("v").map(String::as_str), Some("2"));
        assert_eq!(parsed.get("client").map(String::as_str), Some("ferrox"));
        let empty = settings_bytes(2, Some(""), Some("abc"));
        assert_eq!(empty, b"client=\npadding-md5=abc\nv=2");
        let answer = settings_bytes(2, None, None);
        assert_eq!(answer, b"v=2");
    }

    #[test]
    fn padding_scheme_steps_and_handshake_match_the_reference() {
        let padding =
            Padding::new(b"stop=8\n0=30-30\n2=10-20,c,30-30\n3=9-9,500-1000").expect("parses");
        assert_eq!(padding.handshake_padding(), 30);
        let steps = padding.steps(2);
        assert_eq!(steps.len(), 3);
        assert!(matches!(&steps[0], PaddingSize::Bytes(size) if (10..20).contains(size)));
        assert!(matches!(steps[1], PaddingSize::Check));
        assert!(matches!(steps[2], PaddingSize::Bytes(30)));
        assert_eq!(padding.steps(9).len(), 0);
    }

    #[test]
    fn outbound_spellings_parse() {
        let tls =
            r#""streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": true}}"#;
        let nested = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "anytls", "settings": {{"servers": [{{"address": "a.test", "port": 443, "password": "secret", "client_metadata": "meta"}}]}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&nested).expect("builds").expect("anytls");
        assert_eq!(parsed.address, "a.test");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.client, "meta");

        let flat = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "anytls", "settings": {{"address": "b.test", "port": 8443, "password": "secret"}}, {tls}}}]}}"#
        ))
        .expect("parses");
        let parsed = outbound(&flat).expect("builds").expect("anytls");
        assert_eq!(parsed.address, "b.test");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.client, "");
    }

    #[test]
    fn addresses_survive_split_reads() {
        let destination = Destination::Name("example.com".to_owned(), 443);
        let mut encoded = Vec::new();
        encode_address(&destination, &mut encoded).expect("encodes");
        let mut reader = OneByte {
            bytes: encoded.clone(),
            at: 0,
        };
        assert!(matches!(
            read_address(&mut reader, Instant::now() + OPEN_TIMEOUT),
            Ok(Address::Name(host, 443)) if host == "example.com"
        ));
        encoded.pop();
        let mut reader = OneByte {
            bytes: encoded,
            at: 0,
        };
        let error = read_address(&mut reader, Instant::now() + OPEN_TIMEOUT)
            .err()
            .expect("short address");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn stream_addresses_survive_split_frames() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(Arc::clone(&written))),
            Padding::default_scheme(),
            false,
        ));
        let destination = Destination::Name("example.com".to_owned(), 443);
        let mut encoded = Vec::new();
        encode_address(&destination, &mut encoded).expect("encodes");
        let stream = test_stream(&shared, 1);
        for byte in &encoded {
            stream.state.push(vec![*byte], &shared.alive);
        }
        assert!(matches!(
            read_address_stream(&stream, Instant::now() + OPEN_TIMEOUT),
            Ok(Address::Name(host, 443)) if host == "example.com"
        ));

        let short = test_stream(&shared, 2);
        encoded.pop();
        short.state.push(encoded, &shared.alive);
        short.state.end(Terminal::Eof);
        let error = read_address_stream(&short, Instant::now() + OPEN_TIMEOUT)
            .err()
            .expect("short address");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_read_drains_across_queued_frames_and_then_the_end() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(written)),
            Padding::default_scheme(),
            false,
        ));
        let stream = test_stream(&shared, 4);
        stream.state.push(vec![0xa; 3], &shared.alive);
        stream.state.push(vec![0xb; 2], &shared.alive);
        stream.state.end(Terminal::Eof);
        let mut buf = [0u8; 4];
        assert_eq!(
            stream
                .state
                .read(&mut buf, None, &shared.alive)
                .expect("reads"),
            4
        );
        assert_eq!(buf, [0xa, 0xa, 0xa, 0xb]);
        assert_eq!(
            stream
                .state
                .read(&mut buf, None, &shared.alive)
                .expect("reads"),
            1
        );
        assert_eq!(buf[0], 0xb);
        assert_eq!(
            stream
                .state
                .read(&mut buf, None, &shared.alive)
                .expect("ends"),
            0
        );
    }

    #[test]
    fn a_queued_frame_keeps_the_buffer_it_arrived_in() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(written)),
            Padding::default_scheme(),
            false,
        ));
        let stream = test_stream(&shared, 6);
        for size in [MAX_FRAME, 4096, 1] {
            let payload = vec![0x5a; size];
            let base = payload.as_ptr();
            let room = payload.capacity();
            stream.state.push(payload, &shared.alive);
            let inner = stream
                .state
                .inner
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let queued = inner.queue.back().expect("a queued chunk");
            assert_eq!(queued.as_ptr(), base);
            assert_eq!(queued.capacity(), room);
            drop(inner);
            let mut buf = vec![0u8; size];
            assert_eq!(
                stream
                    .state
                    .read(&mut buf, None, &shared.alive)
                    .expect("reads"),
                size
            );
            assert!(buf.iter().all(|byte| *byte == 0x5a));
        }
    }

    #[test]
    fn a_stream_queue_keeps_its_slots_bounded() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared::new(
            Box::new(Sink(written)),
            Padding::default_scheme(),
            false,
        ));
        let stream = test_stream(&shared, 5);
        for _ in 0..4096 {
            stream.state.push(vec![0x7], &shared.alive);
        }
        let inner = stream
            .state
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(inner.queue.len() <= QUEUE_CHUNKS);
        assert_eq!(inner.queued, 4096);
    }

    #[test]
    fn addresses_round_trip() {
        for destination in [
            Destination::Name("example.com".to_owned(), 443),
            Destination::Address("192.0.2.1:80".parse().expect("parses")),
            Destination::Address("[2001:db8::1]:53".parse().expect("parses")),
        ] {
            let mut encoded = Vec::new();
            encode_address(&destination, &mut encoded).expect("encodes");
            let decoded = read_address(&mut encoded.as_slice(), Instant::now() + OPEN_TIMEOUT)
                .expect("decodes");
            match (destination, decoded) {
                (Destination::Name(left, left_port), Address::Name(right, right_port)) => {
                    assert_eq!((left, left_port), (right, right_port));
                }
                (Destination::Address(left), Address::Address(right)) => assert_eq!(left, right),
                _ => panic!("the address family changed"),
            }
        }
    }
}

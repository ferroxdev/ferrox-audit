//! sing-mux's session layer: one carrier carries smux, yamux or HTTP/2 CONNECT streams.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

use crate::h2;
use crate::muxpool::{Deliver, Uplink};
use crate::proxy::Destination;

pub(crate) const HOST: &str = "sp.mux.sing-box.arpa";
pub(crate) const PORT: u16 = 444;

/// How the session frames its streams after the rendezvous request.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum Protocol {
    Smux,
    Yamux,
    H2Mux,
}

impl Protocol {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "" | "h2mux" => Some(Self::H2Mux),
            "smux" => Some(Self::Smux),
            "yamux" => Some(Self::Yamux),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Smux => 0,
            Self::Yamux => 1,
            Self::H2Mux => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Smux),
            1 => Some(Self::Yamux),
            2 => Some(Self::H2Mux),
            _ => None,
        }
    }
}

pub(crate) fn is_rendezvous(host: &str, port: u16) -> bool {
    host.eq_ignore_ascii_case(HOST) && port == PORT
}

const VERSION0: u8 = 0;
const VERSION1: u8 = 1;
const FIRST_PADDINGS: usize = 16;

const SMUX_SYN: u8 = 0;
const SMUX_FIN: u8 = 1;
const SMUX_PSH: u8 = 2;
const SMUX_NOP: u8 = 3;
const SMUX_FRAME: usize = 8;
const SMUX_DATA_MAX: usize = 32768;

const YAMUX_DATA: u8 = 0;
const YAMUX_WINDOW: u8 = 1;
const YAMUX_PING: u8 = 2;
const YAMUX_SYN: u16 = 1;
const YAMUX_ACK: u16 = 2;
const YAMUX_FIN: u16 = 4;
const YAMUX_RST: u16 = 8;
const YAMUX_STREAM_WINDOW: i64 = 256 * 1024;

const H2_WINDOW: i64 = 4 * 1024 * 1024;
const H2_DATA_MAX: usize = 16 * 1024;
const H2_FRAME_CAP: usize = 4 * 1024 * 1024;
const H2_SETTINGS_INITIAL: u16 = 4;
const H2_SETTINGS_MAX_CONCURRENT: u16 = 3;
const H2_SETTINGS_MAX_FRAME: u16 = 5;
const H2_MAX_STREAMS: usize = 256;
const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;
const MAX_STREAMS: usize = 1024;
const RESET_QUEUE: usize = MAX_STREAMS;

/// One stream's opening request: a TCP destination, or the destination a connected UDP flow
/// speaks to; `packet_addr` marks the full-cone form where every frame names its own address.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) target: Destination,
    pub(crate) udp: bool,
    pub(crate) packet_addr: bool,
}

fn read_request(read: &mut dyn Read) -> Option<(Protocol, bool)> {
    let mut head = [0u8; 2];
    crate::proxy::read_exact(read, &mut head).ok()?;
    if head[0] > VERSION1 {
        return None;
    }
    let protocol = Protocol::from_code(head[1])?;
    let mut padding = false;
    if head[0] == VERSION1 {
        let mut flag = [0u8; 1];
        crate::proxy::read_exact(read, &mut flag).ok()?;
        padding = flag[0] != 0;
        if padding {
            let mut size = [0u8; 2];
            crate::proxy::read_exact(read, &mut size).ok()?;
            skip(read, usize::from(u16::from_be_bytes(size)))?;
        }
    }
    Some((protocol, padding))
}

fn write_request(write: &mut dyn Write, protocol: Protocol, padding: bool) -> io::Result<()> {
    if !padding {
        return write.write_all(&[VERSION0, protocol.code()]);
    }
    let padding_len = 256 + random_u16()? % 512;
    let mut head = [0u8; 5];
    head[0] = VERSION1;
    head[1] = protocol.code();
    head[2] = 1;
    head[3..].copy_from_slice(&(padding_len as u16).to_be_bytes());
    write.write_all(&head)?;
    let mut left = padding_len;
    let zeros = [0u8; 256];
    while left > 0 {
        let take = left.min(zeros.len());
        write.write_all(&zeros[..take])?;
        left -= take;
    }
    Ok(())
}

fn random_u16() -> io::Result<usize> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(usize::from(u16::from_be_bytes(bytes)))
}

fn skip(read: &mut dyn Read, mut left: usize) -> Option<()> {
    let mut scratch = [0u8; 256];
    while left > 0 {
        let take = left.min(scratch.len());
        crate::proxy::read_exact(read, &mut scratch[..take]).ok()?;
        left -= take;
    }
    Some(())
}

fn read_some(read: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match read.read(buf) {
            Err(error) if ferrox_core::tls::TlsError::is_timeout(&error) => {}
            other => return other,
        }
    }
}

struct PaddedReader {
    inner: Box<dyn Read + Send>,
    count: u8,
    data_left: usize,
    padding_left: usize,
}

impl PaddedReader {
    fn new(inner: Box<dyn Read + Send>) -> Self {
        Self {
            inner,
            count: 0,
            data_left: 0,
            padding_left: 0,
        }
    }
}

impl Read for PaddedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.data_left > 0 {
                let take = out.len().min(self.data_left);
                crate::proxy::read_exact(&mut *self.inner, &mut out[..take])?;
                self.data_left -= take;
                return Ok(take);
            }
            if self.padding_left > 0 {
                let mut scratch = [0u8; 256];
                let take = self.padding_left.min(scratch.len());
                crate::proxy::read_exact(&mut *self.inner, &mut scratch[..take])?;
                self.padding_left -= take;
                continue;
            }
            if self.count >= FIRST_PADDINGS as u8 {
                return read_some(&mut *self.inner, out);
            }
            let mut head = [0u8; 4];
            crate::proxy::read_exact(&mut *self.inner, &mut head)?;
            self.data_left = usize::from(u16::from_be_bytes([head[0], head[1]]));
            self.padding_left = usize::from(u16::from_be_bytes([head[2], head[3]]));
            self.count += 1;
        }
    }
}

struct PaddedWriter {
    inner: Box<dyn Write + Send>,
    count: u8,
}

impl PaddedWriter {
    fn new(inner: Box<dyn Write + Send>) -> Self {
        Self { inner, count: 0 }
    }
}

impl Write for PaddedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.count >= FIRST_PADDINGS as u8 {
            return self.inner.write(data);
        }
        let take = data.len().min(u16::MAX as usize);
        let padding_len = 256 + random_u16()? % 512;
        let mut frame = Vec::with_capacity(4 + take + padding_len);
        frame.extend_from_slice(&(take as u16).to_be_bytes());
        frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
        frame.extend_from_slice(&data[..take]);
        frame.resize(4 + take + padding_len, 0);
        self.inner.write_all(&frame)?;
        self.count += 1;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Window {
    state: Mutex<WindowState>,
    wake: Condvar,
}

struct WindowState {
    value: i64,
    closed: bool,
    #[cfg(test)]
    waiting: usize,
}

#[cfg(test)]
fn note_wait(state: &mut WindowState, waiting: bool) {
    if waiting {
        state.waiting += 1;
    } else {
        state.waiting -= 1;
    }
}

#[cfg(not(test))]
fn note_wait(_state: &mut WindowState, _waiting: bool) {}

impl Window {
    fn new(value: i64) -> Self {
        Self {
            state: Mutex::new(WindowState {
                value,
                closed: false,
                #[cfg(test)]
                waiting: 0,
            }),
            wake: Condvar::new(),
        }
    }

    fn take_up_to(&self, size: usize) -> Option<usize> {
        self.take_up_to_while(size, None)
    }

    fn take_up_to_while(&self, size: usize, closed: Option<&AtomicBool>) -> Option<usize> {
        let limit = i64::try_from(size).unwrap_or(i64::MAX);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if state.closed || closed.is_some_and(|closed| closed.load(Ordering::Relaxed)) {
                return None;
            }
            if state.value > 0 {
                let taken = state.value.min(limit);
                state.value -= taken;
                return Some(usize::try_from(taken).unwrap_or(usize::MAX));
            }
            note_wait(&mut state, true);
            state = match self.wake.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            note_wait(&mut state, false);
        }
    }

    fn notify_waiters(&self) {
        // Hold the lock across the notification so a waiter cannot miss it between its check and wait.
        match self.state.lock() {
            Ok(state) => drop(state),
            Err(poisoned) => drop(poisoned.into_inner()),
        }
        self.wake.notify_all();
    }

    fn add(&self, size: i64) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.value = state.value.saturating_add(size);
        drop(state);
        self.wake.notify_all();
    }

    fn close(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closed = true;
        drop(state);
        self.wake.notify_all();
    }
}

pub(crate) struct Msg {
    pub(crate) data: Vec<u8>,
    pub(crate) end: bool,
    pub(crate) credit: usize,
}

struct Queue {
    state: Mutex<QueueState>,
    space: Condvar,
    limit: usize,
}

struct QueueState {
    messages: VecDeque<Msg>,
    queued: usize,
    closed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Push {
    Queued,
    Full,
    Closed,
}

impl Queue {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                messages: VecDeque::new(),
                queued: 0,
                closed: false,
            }),
            space: Condvar::new(),
            limit,
        })
    }

    fn push(&self, msg: Msg) -> Push {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.closed {
            return Push::Closed;
        }
        // The demux thread is shared: a stream that overruns its queue is reset, never waited on.
        if state.queued.saturating_add(msg.data.len()) > self.limit {
            return Push::Full;
        }
        state.queued += msg.data.len();
        state.messages.push_back(msg);
        drop(state);
        self.space.notify_all();
        Push::Queued
    }

    fn pop(&self) -> Option<Msg> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        while state.messages.is_empty() && !state.closed {
            state = match self.space.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        let msg = state.messages.pop_front()?;
        state.queued -= msg.data.len();
        drop(state);
        self.space.notify_all();
        Some(msg)
    }

    fn try_pop(&self) -> Option<Msg> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let msg = state.messages.pop_front()?;
        state.queued -= msg.data.len();
        drop(state);
        self.space.notify_all();
        Some(msg)
    }

    fn is_closed(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.closed,
            Err(poisoned) => poisoned.into_inner().closed,
        }
    }

    fn close(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closed = true;
        drop(state);
        self.space.notify_all();
    }
}

struct Sink {
    queue: Arc<Queue>,
    window: Arc<Window>,
    closed: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
    awaiting_status: bool,
    remote_end: bool,
    local_end: bool,
}

pub(crate) struct Replies {
    queue: Arc<Queue>,
    inner: Arc<Inner>,
    id: u32,
}

impl Replies {
    /// A reply, blocking until one is queued. The caller settles its window credit once the bytes
    /// are out: a credit write blocks on the carrier's writer and must not hold a collected batch.
    pub(crate) fn recv(&self) -> Result<Msg, std::sync::mpsc::RecvError> {
        self.queue.pop().ok_or(std::sync::mpsc::RecvError)
    }

    /// A reply already queued, for the downlink's drain behind `recv`.
    pub(crate) fn try_recv(&self) -> Option<Msg> {
        self.queue.try_pop()
    }

    /// Hands a served reply's window back to the peer.
    pub(crate) fn settle(&self, credit: usize) {
        self.inner.credit(self.id, credit);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

fn defer_close(close: Arc<dyn Fn() + Send + Sync>) {
    let callback = Arc::clone(&close);
    if std::thread::Builder::new()
        .name("singmux-close".to_owned())
        .spawn(move || close())
        .is_err()
    {
        callback();
    }
}

struct Inner {
    protocol: Protocol,
    role: Role,
    write: Mutex<Box<dyn Write + Send>>,
    sinks: Mutex<HashMap<u32, Sink>>,
    resets: Mutex<Option<SyncSender<u32>>>,
    credits: Mutex<Option<SyncSender<()>>>,
    pending_credit: AtomicUsize,
    accept_tx: Mutex<Option<Sender<Stream>>>,
    accept_rx: Mutex<Receiver<Stream>>,
    next_id: AtomicU32,
    initial_window: Mutex<i64>,
    connection_window: Window,
    dead: AtomicBool,
    finished: AtomicBool,
    close: Arc<dyn Fn() + Send + Sync>,
    decoder: Mutex<h2::Decoder>,
    self_ref: OnceLock<Weak<Inner>>,
}

impl Inner {
    fn start(
        protocol: Protocol,
        role: Role,
        read: Box<dyn Read + Send>,
        write: Box<dyn Write + Send>,
        close: Arc<dyn Fn() + Send + Sync>,
    ) -> Option<Arc<Self>> {
        let (accept_tx, accept_rx) = channel();
        let inner = Arc::new(Self {
            protocol,
            role,
            write: Mutex::new(write),
            sinks: Mutex::new(HashMap::new()),
            resets: Mutex::new(None),
            credits: Mutex::new(None),
            pending_credit: AtomicUsize::new(0),
            accept_tx: Mutex::new(Some(accept_tx)),
            accept_rx: Mutex::new(accept_rx),
            next_id: AtomicU32::new(if role == Role::Client { 1 } else { 2 }),
            initial_window: Mutex::new(match protocol {
                Protocol::Smux => i64::MAX,
                Protocol::Yamux => YAMUX_STREAM_WINDOW,
                Protocol::H2Mux => 65_535,
            }),
            connection_window: Window::new(if protocol == Protocol::H2Mux {
                65_535
            } else {
                i64::MAX
            }),
            dead: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            close,
            decoder: Mutex::new(h2::Decoder::default()),
            self_ref: OnceLock::new(),
        });
        let _ = inner.self_ref.set(Arc::downgrade(&inner));
        if protocol == Protocol::H2Mux {
            if role == Role::Client {
                inner.write_raw(h2::MAGIC).ok()?;
            }
            inner.write_settings().ok()?;
        }
        let reader = Arc::clone(&inner);
        std::thread::spawn(move || reader.read_loop(read));
        Some(inner)
    }

    fn write_raw(&self, bytes: &[u8]) -> io::Result<()> {
        let mut write = match self.write.lock() {
            Ok(write) => write,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.dead() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = write.write_all(bytes).and_then(|()| write.flush());
        if result.is_err() {
            self.dead.store(true, Ordering::Relaxed);
        }
        drop(write);
        if result.is_err() {
            self.finish();
        }
        result
    }

    fn write_settings(&self) -> io::Result<()> {
        if self.protocol != Protocol::H2Mux {
            return Ok(());
        }
        let mut settings = Vec::with_capacity(6 * 3);
        settings.extend_from_slice(&H2_SETTINGS_INITIAL.to_be_bytes());
        settings.extend_from_slice(&(H2_WINDOW as u32).to_be_bytes());
        settings.extend_from_slice(&H2_SETTINGS_MAX_CONCURRENT.to_be_bytes());
        settings.extend_from_slice(&(H2_MAX_STREAMS as u32).to_be_bytes());
        settings.extend_from_slice(&H2_SETTINGS_MAX_FRAME.to_be_bytes());
        settings.extend_from_slice(&(H2_FRAME_CAP as u32).to_be_bytes());
        let mut frame = Vec::with_capacity(9 + settings.len() + 13);
        frame.extend_from_slice(&h2::frame_head(settings.len(), h2::T_SETTINGS, 0, 0));
        frame.extend_from_slice(&settings);
        frame.extend_from_slice(&h2::frame_head(4, h2::T_WINDOW, 0, 0));
        frame.extend_from_slice(&((H2_WINDOW - 65_535) as u32).to_be_bytes());
        self.write_raw(&frame)
    }

    fn open(&self, _target: &Destination, expect_status: bool) -> Option<Stream> {
        if self.role != Role::Client || self.dead() {
            return None;
        }
        let id = match self.protocol {
            Protocol::Smux => self.next_id.fetch_add(2, Ordering::Relaxed) + 2,
            Protocol::Yamux | Protocol::H2Mux => self.next_id.fetch_add(2, Ordering::Relaxed),
        };
        let stream = self.attach(id);
        if expect_status {
            self.expect_status(id);
        }
        let opened = match self.protocol {
            Protocol::Smux => self.write_frame(&smux_head(SMUX_SYN, id, 0), &[]),
            Protocol::Yamux => self.write_frame(
                &yamux_head(YAMUX_WINDOW, YAMUX_SYN, id, YAMUX_STREAM_WINDOW as u32),
                &[],
            ),
            Protocol::H2Mux => self.write_headers(id, true),
        };
        if !opened {
            self.release(id);
            return None;
        }
        Some(stream)
    }

    fn attach(&self, id: u32) -> Stream {
        let queue = Queue::new(match self.protocol {
            Protocol::Smux => 64 * 1024,
            Protocol::Yamux => YAMUX_STREAM_WINDOW as usize,
            Protocol::H2Mux => H2_WINDOW as usize,
        });
        let mut sinks = match self.sinks.lock() {
            Ok(sinks) => sinks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let initial = match self.initial_window.lock() {
            Ok(window) => window,
            Err(poisoned) => poisoned.into_inner(),
        };
        let window = Arc::new(Window::new(*initial));
        let closed = Arc::new(AtomicBool::new(false));
        let reset = Arc::new(AtomicBool::new(false));
        sinks.insert(
            id,
            Sink {
                queue: Arc::clone(&queue),
                window: Arc::clone(&window),
                closed: Arc::clone(&closed),
                reset: Arc::clone(&reset),
                awaiting_status: false,
                remote_end: false,
                local_end: false,
            },
        );
        drop(sinks);
        drop(initial);
        Stream {
            inner: self.clone_handle(),
            id,
            replies: Some(queue),
            request: Vec::new(),
            request_sent: AtomicBool::new(false),
            closed,
            reset,
            window,
            buffer: Mutex::new(ReadState::default()),
            read_done: false,
        }
    }

    fn clone_handle(&self) -> Arc<Inner> {
        self.self_ref
            .get()
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| panic!("session handle was not installed"))
    }

    fn accept(&self) -> Option<Stream> {
        match self.accept_rx.lock() {
            Ok(receiver) => receiver.recv().ok(),
            Err(poisoned) => poisoned.into_inner().recv().ok(),
        }
    }

    fn can_attach(&self) -> bool {
        let cap = if self.protocol == Protocol::H2Mux {
            H2_MAX_STREAMS
        } else {
            MAX_STREAMS
        };
        self.sinks.lock().is_ok_and(|sinks| sinks.len() < cap)
    }

    fn expect_status(&self, id: u32) {
        let mut sinks = match self.sinks.lock() {
            Ok(sinks) => sinks,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(sink) = sinks.get_mut(&id) {
            sink.awaiting_status = true;
        }
    }

    fn offer(&self, stream: Stream) {
        let id = stream.id;
        let sender = match self.accept_tx.lock() {
            Ok(sender) => sender.as_ref().cloned(),
            Err(poisoned) => poisoned.into_inner().as_ref().cloned(),
        };
        if sender.is_none_or(|sender| sender.send(stream).is_err()) {
            self.release(id);
        }
    }

    fn dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    fn write_frame(&self, head: &[u8], data: &[u8]) -> bool {
        self.write_frame_while(head, data, None, None)
    }

    fn write_frame_while(
        &self,
        head: &[u8],
        data: &[u8],
        closed: Option<&AtomicBool>,
        reset: Option<&AtomicBool>,
    ) -> bool {
        let mut write = match self.write.lock() {
            Ok(write) => write,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.dead()
            || closed.is_some_and(|closed| closed.load(Ordering::Relaxed))
            || reset.is_some_and(|reset| reset.load(Ordering::Relaxed))
        {
            return false;
        }
        let ok =
            write.write_all(head).is_ok() && write.write_all(data).is_ok() && write.flush().is_ok();
        if !ok {
            self.dead.store(true, Ordering::Relaxed);
        }
        drop(write);
        if !ok {
            self.finish();
        }
        ok
    }

    fn write_headers(&self, id: u32, request: bool) -> bool {
        let block = if request {
            h2::block_encode(&[(":method", "CONNECT"), (":authority", "localhost")])
        } else {
            h2::block_encode(&[(":status", "200")])
        };
        let mut frame = Vec::with_capacity(9 + block.len());
        frame.extend_from_slice(&h2::frame_head(
            block.len(),
            h2::T_HEADERS,
            h2::F_END_HEADERS,
            id,
        ));
        frame.extend_from_slice(&block);
        self.write_raw(&frame).is_ok()
    }

    fn send_data(
        &self,
        id: u32,
        data: &[u8],
        end: bool,
        closed: &AtomicBool,
        reset: &AtomicBool,
    ) -> bool {
        if data.is_empty() && !end {
            return true;
        }
        match self.protocol {
            Protocol::Smux => {
                let flags = if end { SMUX_FIN } else { SMUX_PSH };
                self.write_frame_while(
                    &smux_head(flags, id, data.len()),
                    data,
                    Some(closed),
                    Some(reset),
                )
            }
            Protocol::Yamux => {
                let flags = if end { YAMUX_FIN } else { 0 };
                self.write_frame_while(
                    &yamux_head(YAMUX_DATA, flags, id, data.len() as u32),
                    data,
                    Some(closed),
                    Some(reset),
                )
            }
            Protocol::H2Mux => {
                let flags = if end { h2::F_END } else { 0 };
                self.write_frame_while(
                    &h2::frame_head(data.len(), h2::T_DATA, flags, id),
                    data,
                    Some(closed),
                    Some(reset),
                )
            }
        }
    }

    fn send_end(&self, id: u32, reset: &AtomicBool) -> bool {
        match self.protocol {
            Protocol::Smux => {
                self.write_frame_while(&smux_head(SMUX_FIN, id, 0), &[], None, Some(reset))
            }
            Protocol::Yamux => self.write_frame_while(
                &yamux_head(YAMUX_WINDOW, YAMUX_FIN, id, 0),
                &[],
                None,
                Some(reset),
            ),
            Protocol::H2Mux => self.write_frame_while(
                &h2::frame_head(0, h2::T_DATA, h2::F_END, id),
                &[],
                None,
                Some(reset),
            ),
        }
    }

    fn send_reset(&self, id: u32) -> bool {
        match self.protocol {
            Protocol::Smux => self.write_frame(&smux_head(SMUX_FIN, id, 0), &[]),
            Protocol::Yamux => self.write_frame(&yamux_head(YAMUX_WINDOW, YAMUX_RST, id, 0), &[]),
            Protocol::H2Mux => {
                self.write_frame(&h2::frame_head(4, h2::T_RST, 0, id), &8u32.to_be_bytes())
            }
        }
    }

    /// The demux cannot wait on the carrier: resets drain on a thread of their own.
    fn defer_reset(&self, id: u32, reset: &AtomicBool) {
        if reset.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut resets = match self.resets.lock() {
            Ok(resets) => resets,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.dead() {
            return;
        }
        if resets.is_some() {
            let failed = resets
                .as_ref()
                .is_some_and(|sender| sender.try_send(id).is_err());
            if failed {
                drop(resets);
                self.finish_deferred();
            }
            return;
        }
        let (sender, pending) = sync_channel(RESET_QUEUE);
        let inner = Arc::downgrade(&self.clone_handle());
        let spawned = std::thread::Builder::new()
            .name("singmux-reset".to_owned())
            .spawn(move || {
                while let Ok(id) = pending.recv() {
                    let Some(inner) = inner.upgrade() else {
                        break;
                    };
                    inner.send_reset(id);
                }
            });
        if spawned.is_err() {
            drop(resets);
            self.finish_deferred();
            return;
        }
        *resets = Some(sender.clone());
        drop(resets);
        let _ = sender.try_send(id);
    }

    fn defer_credit(&self, credit: usize) {
        if self.protocol != Protocol::H2Mux || credit == 0 {
            return;
        }
        self.pending_credit.fetch_add(credit, Ordering::Relaxed);
        let mut credits = match self.credits.lock() {
            Ok(credits) => credits,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.dead() {
            return;
        }
        if credits.is_none() {
            let (sender, wake) = sync_channel(1);
            let inner = Arc::downgrade(&self.clone_handle());
            let spawned = std::thread::Builder::new()
                .name("singmux-credit".to_owned())
                .spawn(move || {
                    while wake.recv().is_ok() {
                        let Some(inner) = inner.upgrade() else {
                            break;
                        };
                        let credit = inner.pending_credit.swap(0, Ordering::Relaxed);
                        inner.send_connection_credit(credit);
                    }
                });
            if spawned.is_err() {
                drop(credits);
                self.finish();
                return;
            }
            *credits = Some(sender);
        }
        let disconnected = credits.as_ref().is_some_and(|wake| {
            matches!(
                wake.try_send(()),
                Err(std::sync::mpsc::TrySendError::Disconnected(()))
            )
        });
        if disconnected {
            drop(credits);
            self.finish();
        }
    }

    fn send_connection_credit(&self, credit: usize) {
        let mut left = credit;
        while left > 0 && self.protocol == Protocol::H2Mux {
            let amount = left.min(0x7fff_ffff);
            let mut frame = [0u8; 13];
            frame[..9].copy_from_slice(&h2::frame_head(4, h2::T_WINDOW, 0, 0));
            frame[9..].copy_from_slice(&u32::try_from(amount).unwrap().to_be_bytes());
            if self.write_raw(&frame).is_err() {
                self.finish();
                return;
            }
            left -= amount;
        }
    }

    fn release(&self, id: u32) {
        let sink = match self.sinks.lock() {
            Ok(mut sinks) => sinks.remove(&id),
            Err(poisoned) => poisoned.into_inner().remove(&id),
        };
        if let Some(sink) = sink {
            sink.closed.store(true, Ordering::Relaxed);
            sink.window.close();
            sink.queue.close();
            self.connection_window.notify_waiters();
        }
    }

    fn reap(&self, id: u32) {
        let sink = match self.sinks.lock() {
            Ok(mut sinks) => sinks.remove(&id),
            Err(poisoned) => poisoned.into_inner().remove(&id),
        };
        if let Some(sink) = sink {
            sink.closed.store(true, Ordering::Relaxed);
            sink.window.close();
            self.connection_window.notify_waiters();
        }
    }

    fn end_remote(&self, id: u32) {
        let done = {
            let Ok(mut sinks) = self.sinks.lock() else {
                return;
            };
            let Some(sink) = sinks.get_mut(&id) else {
                return;
            };
            sink.remote_end = true;
            sink.local_end
        };
        if done {
            self.reap(id);
        }
    }

    fn end_local(&self, id: u32) {
        let done = {
            let Ok(mut sinks) = self.sinks.lock() else {
                return;
            };
            let Some(sink) = sinks.get_mut(&id) else {
                return;
            };
            sink.local_end = true;
            sink.remote_end
        };
        if done {
            self.reap(id);
        }
    }

    fn deliver(&self, id: u32, data: &[u8], end: bool) {
        self.deliver_credit(id, data, end, data.len());
    }

    fn deliver_credit(&self, id: u32, data: &[u8], end: bool, credit: usize) {
        let (queue, reset_stream, awaiting_status) = {
            let mut sinks = match self.sinks.lock() {
                Ok(sinks) => sinks,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(sink) = sinks.get_mut(&id) else {
                drop(sinks);
                self.defer_credit(credit);
                return;
            };
            let awaiting = sink.awaiting_status;
            if awaiting && (!data.is_empty() || end) {
                sink.awaiting_status = false;
            }
            (Arc::clone(&sink.queue), Arc::clone(&sink.reset), awaiting)
        };
        let mut data = data;
        let mut credit = if self.protocol == Protocol::Smux {
            0
        } else {
            credit
        };
        if awaiting_status {
            match data.split_first() {
                Some((0, rest)) => {
                    self.credit(id, 1);
                    credit = credit.saturating_sub(1);
                    data = rest;
                }
                Some(_) => {
                    self.defer_credit(credit);
                    self.release(id);
                    return;
                }
                None => {}
            }
        }
        if data.is_empty() && !end {
            if queue.is_closed() {
                self.defer_credit(credit);
                self.defer_reset(id, &reset_stream);
                self.release(id);
                return;
            }
            self.credit(id, credit);
            return;
        }
        match queue.push(Msg {
            data: data.to_vec(),
            end,
            credit,
        }) {
            Push::Queued => {
                if end {
                    queue.close();
                    self.end_remote(id);
                }
            }
            Push::Full | Push::Closed => {
                self.defer_credit(credit);
                self.defer_reset(id, &reset_stream);
                self.release(id);
            }
        }
    }

    fn take_window(&self, window: &Window, size: usize, closed: &AtomicBool) -> Option<usize> {
        match self.protocol {
            Protocol::Smux => Some(size),
            Protocol::Yamux => window.take_up_to(size),
            Protocol::H2Mux => {
                let connection = self
                    .connection_window
                    .take_up_to_while(size, Some(closed))?;
                let Some(stream) = window.take_up_to(connection) else {
                    self.connection_window
                        .add(i64::try_from(connection).unwrap_or(i64::MAX));
                    return None;
                };
                if stream < connection {
                    self.connection_window
                        .add(i64::try_from(connection - stream).unwrap_or(i64::MAX));
                }
                Some(stream)
            }
        }
    }

    fn refund_window(&self, window: &Window, size: usize) {
        let size = i64::try_from(size).unwrap_or(i64::MAX);
        if self.protocol != Protocol::Smux {
            window.add(size);
        }
        if self.protocol == Protocol::H2Mux {
            self.connection_window.add(size);
        }
    }

    fn credit(&self, id: u32, credit: usize) {
        if credit == 0 {
            return;
        }
        if self.protocol == Protocol::Yamux {
            let _ = self.write_frame(&yamux_head(YAMUX_WINDOW, 0, id, credit as u32), &[]);
        } else if self.protocol == Protocol::H2Mux {
            let mut frames = Vec::with_capacity(18);
            frames.extend_from_slice(&h2::frame_head(4, h2::T_WINDOW, 0, id));
            frames.extend_from_slice(&(credit as u32).to_be_bytes());
            frames.extend_from_slice(&h2::frame_head(4, h2::T_WINDOW, 0, 0));
            frames.extend_from_slice(&(credit as u32).to_be_bytes());
            let _ = self.write_raw(&frames);
        }
    }

    fn read_loop(self: Arc<Self>, read: Box<dyn Read + Send>) {
        match self.protocol {
            Protocol::Smux => self.smux_loop(read),
            Protocol::Yamux => self.yamux_loop(read),
            Protocol::H2Mux => self.h2_loop(read),
        }
        self.finish();
    }

    fn finish(&self) {
        if self.teardown() {
            (self.close)();
        }
    }

    fn finish_deferred(&self) {
        if self.teardown() {
            defer_close(Arc::clone(&self.close));
        }
    }

    fn teardown(&self) -> bool {
        self.dead.store(true, Ordering::Relaxed);
        if self.finished.swap(true, Ordering::Relaxed) {
            return false;
        }
        match self.resets.lock() {
            Ok(mut resets) => drop(resets.take()),
            Err(poisoned) => drop(poisoned.into_inner().take()),
        }
        match self.credits.lock() {
            Ok(mut credits) => drop(credits.take()),
            Err(poisoned) => drop(poisoned.into_inner().take()),
        }
        self.connection_window.close();
        match self.accept_tx.lock() {
            Ok(mut sender) => drop(sender.take()),
            Err(poisoned) => drop(poisoned.into_inner().take()),
        }
        let sinks = match self.sinks.lock() {
            Ok(mut sinks) => std::mem::take(&mut *sinks),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for (_, sink) in sinks {
            sink.closed.store(true, Ordering::Relaxed);
            sink.window.close();
            sink.queue.close();
        }
        true
    }

    fn smux_loop(&self, mut read: Box<dyn Read + Send>) {
        let mut head = [0u8; SMUX_FRAME];
        loop {
            if self.dead() {
                return;
            }
            if crate::proxy::read_exact(&mut *read, &mut head).is_err() {
                return;
            }
            let len = usize::from(u16::from_le_bytes([head[2], head[3]]));
            let id = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
            let mut data = vec![0u8; len];
            if len > 0 && crate::proxy::read_exact(&mut *read, &mut data).is_err() {
                return;
            }
            if self.dead() {
                return;
            }
            match head[1] {
                SMUX_SYN => {
                    if self.can_attach() {
                        self.offer(self.attach(id));
                    } else {
                        self.send_reset(id);
                    }
                }
                SMUX_PSH => self.deliver(id, &data, false),
                SMUX_FIN => self.deliver(id, &[], true),
                SMUX_NOP => {}
                _ => return,
            }
        }
    }

    fn yamux_loop(&self, mut read: Box<dyn Read + Send>) {
        let mut head = [0u8; 12];
        loop {
            if self.dead() {
                return;
            }
            if crate::proxy::read_exact(&mut *read, &mut head).is_err() {
                return;
            }
            if head[0] != 0 {
                return;
            }
            let kind = head[1];
            let flags = u16::from_be_bytes([head[2], head[3]]);
            let id = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            let len = u32::from_be_bytes([head[8], head[9], head[10], head[11]]) as usize;
            let mut data = Vec::new();
            if kind == YAMUX_DATA {
                if len > H2_FRAME_CAP {
                    return;
                }
                data = vec![0u8; len];
                if len > 0 && crate::proxy::read_exact(&mut *read, &mut data).is_err() {
                    return;
                }
            }
            if self.dead() {
                return;
            }
            match kind {
                YAMUX_DATA => {
                    if flags & YAMUX_SYN != 0 {
                        if self.can_attach() {
                            self.offer(self.attach(id));
                        } else {
                            self.send_reset(id);
                            continue;
                        }
                    }
                    if flags & YAMUX_RST != 0 {
                        self.release(id);
                    } else {
                        self.deliver(id, &data, flags & YAMUX_FIN != 0);
                    }
                }
                YAMUX_WINDOW => {
                    if flags & YAMUX_SYN != 0 {
                        if self.can_attach() {
                            self.offer(self.attach(id));
                            let _ =
                                self.write_frame(&yamux_head(YAMUX_WINDOW, YAMUX_ACK, id, 0), &[]);
                        } else {
                            self.send_reset(id);
                        }
                    } else if flags & YAMUX_RST != 0 {
                        self.release(id);
                    } else {
                        self.add_window(id, i64::from(len as u32));
                        if flags & YAMUX_FIN != 0 {
                            self.deliver(id, &[], true);
                        }
                    }
                }
                YAMUX_PING => {
                    if flags & YAMUX_SYN != 0 {
                        let _ = self
                            .write_frame(&yamux_head(YAMUX_PING, YAMUX_ACK, 0, len as u32), &[]);
                    }
                }
                _ => return,
            }
        }
    }

    fn add_window(&self, id: u32, delta: i64) {
        if let Ok(sinks) = self.sinks.lock() {
            if let Some(sink) = sinks.get(&id) {
                sink.window.add(delta);
            }
        }
    }

    fn h2_loop(&self, mut read: Box<dyn Read + Send>) {
        if self.role == Role::Server {
            let mut magic = [0u8; 24];
            if crate::proxy::read_exact(&mut *read, &mut magic).is_err() || magic != *h2::MAGIC {
                return;
            }
        }
        let mut continuation: Option<(u32, Vec<u8>)> = None;
        loop {
            if self.dead() {
                return;
            }
            let Some((len, kind, flags, id)) = h2::read_head(&mut *read) else {
                return;
            };
            if len > H2_FRAME_CAP {
                return;
            }
            let mut body = vec![0u8; len];
            if len > 0 && crate::proxy::read_exact(&mut *read, &mut body).is_err() {
                return;
            }
            if self.dead() {
                return;
            }
            match kind {
                h2::T_SETTINGS => {
                    if flags & h2::F_ACK == 0 {
                        self.h2_settings(&body);
                        let _ =
                            self.write_frame(&h2::frame_head(0, h2::T_SETTINGS, h2::F_ACK, 0), &[]);
                    }
                }
                h2::T_WINDOW => {
                    if body.len() == 4 {
                        let delta = i64::from(
                            u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7fff_ffff,
                        );
                        if id == 0 {
                            self.connection_window.add(delta);
                        } else {
                            self.add_window(id, delta);
                        }
                    }
                }
                h2::T_DATA => {
                    let data = h2_data(flags, &body);
                    self.deliver_credit(id, data, flags & h2::F_END != 0, body.len());
                }
                h2::T_HEADERS => {
                    let block = h2_headers(flags, &body);
                    if block.len() > h2::HEAD_CAP {
                        return;
                    }
                    if flags & h2::F_END_HEADERS == 0 {
                        continuation = Some((id, block.to_vec()));
                    } else {
                        self.h2_headers(id, block);
                    }
                }
                h2::T_CONT => {
                    if let Some((stream, mut block)) = continuation.take() {
                        let next = h2_headers(flags, &body);
                        if block.len() + next.len() > h2::HEAD_CAP {
                            return;
                        }
                        block.extend_from_slice(next);
                        if flags & h2::F_END_HEADERS == 0 {
                            continuation = Some((stream, block));
                        } else {
                            self.h2_headers(stream, &block);
                        }
                    }
                }
                h2::T_RST => self.release(id),
                h2::T_PING => {
                    if flags & h2::F_ACK == 0 {
                        let _ =
                            self.write_frame(&h2::frame_head(len, h2::T_PING, h2::F_ACK, 0), &body);
                    }
                }
                h2::T_GOAWAY => return,
                _ => {}
            }
        }
    }

    fn h2_settings(&self, body: &[u8]) {
        let mut at = 0;
        let mut initial = None;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value = u32::from_be_bytes(body[at + 2..at + 6].try_into().unwrap());
            if id == H2_SETTINGS_INITIAL {
                initial = Some(i64::from(value));
            }
            at += 6;
        }
        let Some(initial) = initial else {
            return;
        };
        let sinks = match self.sinks.lock() {
            Ok(sinks) => sinks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut window = match self.initial_window.lock() {
            Ok(window) => window,
            Err(poisoned) => poisoned.into_inner(),
        };
        let delta = initial - *window;
        *window = initial;
        if delta == 0 {
            return;
        }
        for sink in sinks.values() {
            sink.window.add(delta);
        }
    }

    fn h2_headers(&self, id: u32, block: &[u8]) {
        let mut status = None;
        let mut method = None;
        let mut decoder = match self.decoder.lock() {
            Ok(decoder) => decoder,
            Err(poisoned) => poisoned.into_inner(),
        };
        let block_ok = decoder.decode(block, &mut |name, value| {
            if name == b":status" {
                status = std::str::from_utf8(value)
                    .ok()
                    .and_then(|text| text.parse::<u16>().ok());
            } else if name == b":method" {
                method = Some(value == b"CONNECT");
            }
        });
        if block_ok.is_none() {
            return;
        }
        match self.role {
            Role::Server => {
                if method != Some(true)
                    || self.sinks.lock().is_ok_and(|sinks| sinks.contains_key(&id))
                    || !self.can_attach()
                {
                    self.send_reset(id);
                    return;
                }
                if !self.write_headers(id, false) {
                    return;
                }
                self.offer(self.attach(id));
            }
            Role::Client => {
                if status != Some(200) {
                    self.deliver(id, &[], true);
                }
            }
        }
    }
}

fn smux_head(cmd: u8, id: u32, len: usize) -> [u8; SMUX_FRAME] {
    let mut head = [0u8; SMUX_FRAME];
    head[0] = 1;
    head[1] = cmd;
    head[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    head[4..].copy_from_slice(&id.to_le_bytes());
    head
}

fn yamux_head(kind: u8, flags: u16, id: u32, len: u32) -> [u8; 12] {
    let mut head = [0u8; 12];
    head[0] = 0;
    head[1] = kind;
    head[2..4].copy_from_slice(&flags.to_be_bytes());
    head[4..8].copy_from_slice(&id.to_be_bytes());
    head[8..].copy_from_slice(&len.to_be_bytes());
    head
}

fn h2_data(flags: u8, body: &[u8]) -> &[u8] {
    if flags & h2::F_PADDED == 0 {
        return body;
    }
    let Some((&pad, rest)) = body.split_first() else {
        return &[];
    };
    let pad = usize::from(pad);
    if pad > rest.len() {
        return &[];
    }
    &rest[..rest.len() - pad]
}

fn h2_headers(flags: u8, body: &[u8]) -> &[u8] {
    let mut rest = body;
    if flags & h2::F_PADDED != 0 && !rest.is_empty() {
        let pad = usize::from(rest[0]);
        rest = &rest[1..];
        if pad > rest.len() {
            return &[];
        }
        rest = &rest[..rest.len() - pad];
    }
    if flags & h2::F_PRIORITY != 0 && rest.len() >= 5 {
        rest = &rest[5..];
    }
    rest
}

#[derive(Default)]
struct ReadState {
    buffer: VecDeque<Msg>,
    at: usize,
}

pub(crate) struct Stream {
    inner: Arc<Inner>,
    id: u32,
    replies: Option<Arc<Queue>>,
    request: Vec<u8>,
    request_sent: AtomicBool,
    closed: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
    window: Arc<Window>,
    buffer: Mutex<ReadState>,
    read_done: bool,
}

impl Stream {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        if !self.request_sent.swap(true, Ordering::Relaxed)
            && !self.request.is_empty()
            && !self.write_windowed(&self.request)
        {
            return false;
        }
        self.write_windowed(data)
    }

    fn write_windowed(&self, data: &[u8]) -> bool {
        let mut offset = 0;
        while offset < data.len() {
            let left = data.len() - offset;
            let chunk = match self.inner.protocol {
                Protocol::Smux => left.min(SMUX_DATA_MAX),
                Protocol::Yamux | Protocol::H2Mux => left.min(H2_DATA_MAX),
            };
            let Some(taken) = self.inner.take_window(&self.window, chunk, &self.closed) else {
                return false;
            };
            if self.closed.load(Ordering::Relaxed) {
                self.inner.refund_window(&self.window, taken);
                return false;
            }
            if !self.write_chunk(&data[offset..offset + taken]) {
                self.inner.refund_window(&self.window, taken);
                return false;
            }
            offset += taken;
        }
        true
    }

    fn write_chunk(&self, data: &[u8]) -> bool {
        self.inner
            .send_data(self.id, data, false, &self.closed, &self.reset)
    }

    pub(crate) fn take_replies(&mut self) -> Option<Replies> {
        self.replies.take().map(|queue| Replies {
            queue,
            inner: Arc::clone(&self.inner),
            id: self.id,
        })
    }

    pub(crate) fn writer(&self) -> StreamWriter {
        StreamWriter {
            inner: Arc::clone(&self.inner),
            id: self.id,
            closed: Arc::clone(&self.closed),
            reset: Arc::clone(&self.reset),
            window: Arc::clone(&self.window),
        }
    }

    pub(crate) fn finish(&self) {
        let first = !self.closed.swap(true, Ordering::Relaxed);
        self.window.close();
        self.inner.connection_window.notify_waiters();
        if first {
            self.inner.send_end(self.id, &self.reset);
        }
        self.inner.end_local(self.id);
    }

    pub(crate) fn reset(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if !self.reset.swap(true, Ordering::Relaxed) {
            self.inner.send_reset(self.id);
        }
        self.window.close();
        self.inner.release(self.id);
    }
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut state = match self.buffer.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if state.buffer.front().is_some() {
                if let Some(msg) = state.buffer.pop_front_if(|front| front.data.is_empty()) {
                    if msg.end {
                        self.read_done = true;
                    }
                    self.inner.credit(self.id, msg.credit);
                    if self.read_done && state.buffer.is_empty() {
                        return Ok(0);
                    }
                    continue;
                }
                let (take, done) = {
                    let front = state.buffer.front().expect("front");
                    let take = (front.data.len() - state.at).min(out.len());
                    out[..take].copy_from_slice(&front.data[state.at..state.at + take]);
                    (take, state.at + take == front.data.len())
                };
                state.at += take;
                if done {
                    let msg = state.buffer.pop_front().expect("front");
                    state.at = 0;
                    if msg.end {
                        self.read_done = true;
                    }
                    self.inner.credit(self.id, msg.credit);
                }
                return Ok(take);
            }
            if self.read_done {
                return Ok(0);
            }
            let Some(replies) = self.replies.clone() else {
                return Ok(0);
            };
            drop(state);
            let Some(msg) = replies.pop() else {
                self.read_done = true;
                return Ok(0);
            };
            state = match self.buffer.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.buffer.push_back(msg);
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Relaxed) {
            self.finish();
        }
    }
}

pub(crate) struct StreamWriter {
    inner: Arc<Inner>,
    id: u32,
    closed: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
    window: Arc<Window>,
}

impl StreamWriter {
    fn finish(&self) {
        let first = !self.closed.swap(true, Ordering::Relaxed);
        self.window.close();
        self.inner.connection_window.notify_waiters();
        if first {
            self.inner.send_end(self.id, &self.reset);
        }
        self.inner.end_local(self.id);
    }
}

fn short_write(offset: usize) -> io::Result<usize> {
    if offset > 0 {
        Ok(offset)
    } else {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

impl Write for StreamWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut offset = 0;
        while offset < data.len() {
            let left = data.len() - offset;
            let chunk = match self.inner.protocol {
                Protocol::Smux => left.min(SMUX_DATA_MAX),
                Protocol::Yamux | Protocol::H2Mux => left.min(H2_DATA_MAX),
            };
            let Some(taken) = self.inner.take_window(&self.window, chunk, &self.closed) else {
                return short_write(offset);
            };
            if self.closed.load(Ordering::Relaxed) {
                self.inner.refund_window(&self.window, taken);
                return short_write(offset);
            }
            if !self.inner.send_data(
                self.id,
                &data[offset..offset + taken],
                false,
                &self.closed,
                &self.reset,
            ) {
                self.inner.refund_window(&self.window, taken);
                return short_write(offset);
            }
            offset += taken;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(crate) struct Client {
    session: Arc<Inner>,
}

impl Client {
    pub(crate) fn connect(
        protocol: Protocol,
        padding: bool,
        read: Box<dyn Read + Send>,
        write: Box<dyn Write + Send>,
        close: Arc<dyn Fn() + Send + Sync>,
    ) -> Option<Self> {
        let mut write = write;
        write_request(&mut write, protocol, padding).ok()?;
        let (read, write): (Box<dyn Read + Send>, Box<dyn Write + Send>) = if padding {
            (
                Box::new(PaddedReader::new(read)),
                Box::new(PaddedWriter::new(write)),
            )
        } else {
            (read, write)
        };
        let session = Inner::start(protocol, Role::Client, read, write, close)?;
        Some(Self { session })
    }
}

pub(crate) struct Flow {
    stream: Stream,
}

impl Flow {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        self.stream.send(data)
    }

    pub(crate) fn take_replies(&mut self) -> Option<Replies> {
        self.stream.take_replies()
    }

    pub(crate) fn end_upload(&self) {
        self.stream.finish();
    }

    pub(crate) fn close(self) {
        self.stream.finish();
    }
}

/// A connected datagram stream: every write is one `[u16 len][payload]` frame, and the reader
/// hands each reply to the association that owns the flow.
pub(crate) struct UdpFlow {
    writer: Mutex<StreamWriter>,
    closed: Arc<AtomicBool>,
}

impl UdpFlow {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        if data.len() > u16::MAX as usize || self.closed.load(Ordering::Relaxed) {
            return false;
        }
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let mut writer = match self.writer.lock() {
            Ok(writer) => writer,
            Err(poisoned) => poisoned.into_inner(),
        };
        writer.write_all(&frame).is_ok()
    }

    pub(crate) fn close(self) {
        let writer = match self.writer.into_inner() {
            Ok(writer) => writer,
            Err(poisoned) => poisoned.into_inner(),
        };
        writer.finish();
    }
}

pub(crate) struct Server {
    session: Arc<Inner>,
}

impl Server {
    pub(crate) fn accept(
        mut read: Box<dyn Read + Send>,
        write: Box<dyn Write + Send>,
        close: Arc<dyn Fn() + Send + Sync>,
    ) -> Option<Self> {
        let (protocol, padding) = read_request(&mut *read)?;
        let (read, write): (Box<dyn Read + Send>, Box<dyn Write + Send>) = if padding {
            (
                Box::new(PaddedReader::new(read)),
                Box::new(PaddedWriter::new(write)),
            )
        } else {
            (read, write)
        };
        let session = Inner::start(protocol, Role::Server, read, write, close)?;
        Some(Self { session })
    }

    pub(crate) fn next(&self) -> Option<Stream> {
        self.session.accept()
    }
}

pub(crate) struct Pool {
    protocol: Protocol,
    padding: bool,
    cap: usize,
    open: Box<dyn Fn() -> Option<Uplink> + Send + Sync>,
    sessions: Mutex<Vec<Arc<Inner>>>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Pool")
            .field("protocol", &self.protocol)
            .field("padding", &self.padding)
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl Pool {
    pub(crate) fn new(
        protocol: Protocol,
        padding: bool,
        cap: usize,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            padding,
            cap: cap.max(1),
            open: Box::new(open),
            sessions: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn dial(&self, target: &Destination) -> Option<Flow> {
        let mut sessions = match self.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        };
        sessions.retain(|session| !session.dead());
        for session in sessions.iter() {
            if stream_count(session) >= self.cap {
                continue;
            }
            if let Some(flow) = open_on(session, target) {
                return Some(flow);
            }
        }
        let uplink = (self.open)()?;
        let session = Client::connect(
            self.protocol,
            self.padding,
            uplink.read,
            uplink.write,
            uplink.close,
        )?;
        let Some(flow) = open_on(&session.session, target) else {
            session.session.finish();
            return None;
        };
        sessions.push(session.session);
        Some(flow)
    }

    pub(crate) fn dial_udp(&self, target: &Destination, deliver: &Deliver) -> Option<UdpFlow> {
        let mut sessions = match self.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        };
        sessions.retain(|session| !session.dead());
        for session in sessions.iter() {
            if stream_count(session) >= self.cap {
                continue;
            }
            if let Some(flow) = open_udp_on(session, target, deliver) {
                return Some(flow);
            }
        }
        let uplink = (self.open)()?;
        let session = Client::connect(
            self.protocol,
            self.padding,
            uplink.read,
            uplink.write,
            uplink.close,
        )?;
        let Some(flow) = open_udp_on(&session.session, target, deliver) else {
            session.session.finish();
            return None;
        };
        sessions.push(session.session);
        Some(flow)
    }
}

fn stream_count(session: &Inner) -> usize {
    session.sinks.lock().map_or(0, |sinks| sinks.len())
}

fn open_on(session: &Inner, target: &Destination) -> Option<Flow> {
    let mut stream = session.open(target, true)?;
    stream.request = encode_request(target, false);
    if !stream.send(&[]) {
        stream.reset();
        return None;
    }
    Some(Flow { stream })
}

fn open_udp_on(session: &Inner, target: &Destination, deliver: &Deliver) -> Option<UdpFlow> {
    let mut stream = session.open(target, false)?;
    stream.request = encode_request(target, true);
    if !stream.send(&[]) {
        stream.reset();
        return None;
    }
    let writer = stream.writer();
    let closed = Arc::clone(&stream.closed);
    let deliver = Arc::clone(deliver);
    std::thread::spawn(move || read_udp_packets(stream, &deliver));
    Some(UdpFlow {
        writer: Mutex::new(writer),
        closed,
    })
}

fn read_udp_packets(mut stream: Stream, deliver: &Deliver) {
    let mut status = [0u8; 1];
    if stream.read_exact(&mut status).is_err() || status[0] != 0 {
        return;
    }
    loop {
        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).is_err() {
            return;
        }
        let len = usize::from(u16::from_be_bytes(head));
        let mut data = vec![0u8; len];
        if len > 0 && stream.read_exact(&mut data).is_err() {
            return;
        }
        deliver(&data, None);
    }
}

fn encode_request(target: &Destination, udp: bool) -> Vec<u8> {
    let flags = if udp { FLAG_UDP } else { 0 };
    let mut out = Vec::with_capacity(3 + target.addr_len());
    out.extend_from_slice(&flags.to_be_bytes());
    target.push_addr(&mut out, 4, 3);
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

/// Decodes one stream request from a server-side stream and writes a TCP success byte; a UDP
/// request writes nothing until its first reply, as sing-mux does.
pub(crate) fn accept_request(stream: &mut Stream) -> Option<Request> {
    let mut flags = [0u8; 2];
    stream.read_exact(&mut flags).ok()?;
    let flags = u16::from_be_bytes(flags);
    let target = read_destination(stream)?;
    if flags & !(FLAG_UDP | FLAG_ADDR) != 0 {
        return None;
    }
    let udp = flags & FLAG_UDP != 0;
    let packet_addr = flags & FLAG_ADDR != 0;
    if !udp && (packet_addr || !stream.send(&[0])) {
        return None;
    }
    Some(Request {
        target,
        udp,
        packet_addr,
    })
}

fn read_destination(stream: &mut Stream) -> Option<Destination> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind).ok()?;
    match kind[0] {
        1 => {
            let mut body = [0u8; 4];
            stream.read_exact(&mut body).ok()?;
            let ip = std::net::Ipv4Addr::from(body);
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).ok()?;
            Some(Destination::Address(std::net::SocketAddr::new(
                ip.into(),
                u16::from_be_bytes(port),
            )))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).ok()?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).ok()?;
            Some(Destination::Name(
                String::from_utf8(name).ok()?,
                u16::from_be_bytes(port),
            ))
        }
        4 => {
            let mut body = [0u8; 16];
            stream.read_exact(&mut body).ok()?;
            let ip = std::net::Ipv6Addr::from(body);
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).ok()?;
            Some(Destination::Address(std::net::SocketAddr::new(
                ip.into(),
                u16::from_be_bytes(port),
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Shutdown, TcpListener, TcpStream};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    fn round_trip(protocol: Protocol, padding: bool) {
        let (client, server) = pair();
        let server_read = server.try_clone().expect("server read");
        let server_write = server.try_clone().expect("server write");
        let client_read = client.try_clone().expect("client read");
        let client_write = client.try_clone().expect("client write");
        let stop = client.try_clone().expect("client stop");
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = stop.shutdown(Shutdown::Both);
        });
        let worker = std::thread::spawn(move || {
            let session = Server::accept(
                Box::new(server_read),
                Box::new(server_write),
                Arc::new(|| {}),
            )
            .expect("server");
            let mut stream = session.next().expect("stream");
            let request = accept_request(&mut stream).expect("request");
            assert!(!request.udp);
            assert_eq!(request.target.authority(), "example.com:443");
            let mut body = [0u8; 4];
            stream.read_exact(&mut body).expect("body");
            assert_eq!(&body, b"ping");
            assert!(stream.send(b"pong"));
            stream.finish();
        });
        let session = Client::connect(
            protocol,
            padding,
            Box::new(client_read),
            Box::new(client_write),
            Arc::clone(&close),
        )
        .expect("client");
        let target = Destination::Name("example.com".to_owned(), 443);
        let mut flow = open_on(&session.session, &target).expect("flow");
        assert!(flow.send(b"ping"));
        let mut body = [0u8; 4];
        flow.stream.read_exact(&mut body).expect("reply");
        assert_eq!(&body, b"pong");
        flow.close();
        close();
        worker.join().expect("worker");
    }

    fn udp_round_trip(protocol: Protocol, padding: bool) {
        let (client, server) = pair();
        let server_read = server.try_clone().expect("server read");
        let server_write = server.try_clone().expect("server write");
        let client_read = client.try_clone().expect("client read");
        let client_write = client.try_clone().expect("client write");
        let stop = client.try_clone().expect("client stop");
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = stop.shutdown(Shutdown::Both);
        });
        let worker = std::thread::spawn(move || {
            let session = Server::accept(
                Box::new(server_read),
                Box::new(server_write),
                Arc::new(|| {}),
            )
            .expect("server");
            let mut stream = session.next().expect("stream");
            let request = accept_request(&mut stream).expect("request");
            assert!(request.udp);
            assert!(!request.packet_addr);
            assert_eq!(request.target.authority(), "example.com:443");
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).expect("length");
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
            stream.read_exact(&mut body).expect("body");
            assert_eq!(&body, b"ping");
            let mut writer = stream.writer();
            let mut reply = Vec::with_capacity(6);
            reply.push(0);
            reply.extend_from_slice(&4u16.to_be_bytes());
            reply.extend_from_slice(b"pong");
            writer.write_all(&reply).expect("reply");
            writer.finish();
        });
        let session = Client::connect(
            protocol,
            padding,
            Box::new(client_read),
            Box::new(client_write),
            Arc::clone(&close),
        )
        .expect("client");
        let target = Destination::Name("example.com".to_owned(), 443);
        let (sender, replies) = std::sync::mpsc::channel();
        let deliver: Deliver = Arc::new(move |data, _| {
            let _ = sender.send(data.to_vec());
        });
        let flow = open_udp_on(&session.session, &target, &deliver).expect("flow");
        assert!(flow.send(b"ping"));
        let reply = replies
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("reply");
        assert_eq!(&reply, b"pong");
        flow.close();
        close();
        worker.join().expect("worker");
    }

    #[test]
    fn a_deferred_close_callback_does_not_block_the_demux() {
        let (client, _server) = pair();
        let client_read = client.try_clone().expect("client read");
        let client_write = client.try_clone().expect("client write");
        let (entered, running) = channel();
        let (release, blocked) = channel();
        let blocked = Arc::new(Mutex::new(blocked));
        let close: Arc<dyn Fn() + Send + Sync> = {
            let blocked = Arc::clone(&blocked);
            Arc::new(move || {
                let _ = entered.send(());
                if let Ok(blocked) = blocked.lock() {
                    let _ = blocked.recv();
                }
            })
        };
        let session = Client::connect(
            Protocol::Yamux,
            false,
            Box::new(client_read),
            Box::new(client_write),
            close,
        )
        .expect("client");
        let started = std::time::Instant::now();
        session.session.finish_deferred();
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "deferred teardown returns without running the carrier close"
        );
        running
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the close worker runs the callback");
        release.send(()).expect("releases the close callback");
    }

    #[test]
    fn a_dial_returns_before_the_server_status() {
        let (client, server) = pair();
        let server_read = server.try_clone().expect("server read");
        let server_write = server.try_clone().expect("server write");
        let client_read = client.try_clone().expect("client read");
        let client_write = client.try_clone().expect("client write");
        let stop = client.try_clone().expect("client stop");
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = stop.shutdown(Shutdown::Both);
        });
        let worker = std::thread::spawn(move || {
            let session = Server::accept(
                Box::new(server_read),
                Box::new(server_write),
                Arc::new(|| {}),
            )
            .expect("server");
            let mut stream = session.next().expect("stream");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let request = accept_request(&mut stream).expect("request");
            assert!(!request.udp);
            let mut body = [0u8; 4];
            stream.read_exact(&mut body).expect("body");
            assert_eq!(&body, b"ping");
            assert!(stream.send(b"pong"));
            stream.finish();
        });
        let session = Client::connect(
            Protocol::Yamux,
            false,
            Box::new(client_read),
            Box::new(client_write),
            Arc::clone(&close),
        )
        .expect("client");
        let target = Destination::Name("example.com".to_owned(), 443);
        let start = std::time::Instant::now();
        let mut flow = open_on(&session.session, &target).expect("flow");
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
        assert!(flow.send(b"ping"));
        let mut body = [0u8; 4];
        flow.stream.read_exact(&mut body).expect("reply");
        assert_eq!(&body, b"pong");
        flow.close();
        close();
        worker.join().expect("worker");
    }

    #[test]
    fn a_remote_end_keeps_the_window_until_the_local_side_finishes() {
        let (client, server) = pair();
        let client_read = client.try_clone().expect("client read");
        let client_write = client.try_clone().expect("client write");
        let stop = client.try_clone().expect("client stop");
        let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = stop.shutdown(Shutdown::Both);
        });
        let session = Client::connect(
            Protocol::Yamux,
            false,
            Box::new(client_read),
            Box::new(client_write),
            close,
        )
        .expect("client");
        let target = Destination::Name("example.com".to_owned(), 443);
        let flow = open_on(&session.session, &target).expect("flow");
        let id = flow.stream.id;
        session.session.deliver(id, b"", true);
        assert!(
            session
                .session
                .sinks
                .lock()
                .is_ok_and(|sinks| sinks.contains_key(&id)),
            "a remote end does not unmap the window before the local send end"
        );
        flow.close();
        assert!(
            session
                .session
                .sinks
                .lock()
                .is_ok_and(|sinks| !sinks.contains_key(&id)),
            "the local end releases the window after both directions finished"
        );
        drop(server);
    }

    struct PartialFailWriter {
        gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
        calls: Arc<AtomicUsize>,
    }

    impl Write for PartialFailWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let (lock, wake) = &*self.gate;
                let mut state = lock.lock().expect("gate");
                state.0 = true;
                wake.notify_all();
                while !state.1 {
                    state = wake.wait(state).expect("gate");
                }
                return Ok(1.min(buf.len()));
            }
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn window_waiters(session: &Inner) -> usize {
        let window = &session.connection_window;
        let state = window.state.lock().expect("window");
        state.waiting
    }

    #[test]
    fn a_failed_carrier_write_stops_the_next_writer() {
        let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let (session, held) = held_h2_session(Box::new(std::io::sink()));
        let stream = session.attach(1);
        assert_eq!(
            session.take_window(&stream.window, 65_535, &stream.closed),
            Some(65_535),
            "the test starts with an exhausted connection window"
        );
        let (started, waiting) = channel();
        let (released, done) = channel();
        let waiter = {
            let session = Arc::clone(&session);
            let window = Arc::clone(&stream.window);
            let closed = Arc::clone(&stream.closed);
            std::thread::spawn(move || {
                started.send(()).expect("started");
                released
                    .send(session.take_window(&window, 1, &closed).is_none())
                    .expect("released");
            })
        };
        waiting
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("waiter started");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while window_waiters(&session) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the credit waiter enters the window wait before the negative window"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            done.recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "a credit waiter blocks while the connection window is exhausted"
        );
        *session.write.lock().expect("write") = Box::new(PartialFailWriter {
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
        });
        let first = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || session.write_frame(&[1, 2, 3], &[4]))
        };
        {
            let (lock, wake) = &*gate;
            let mut state = lock.lock().expect("gate");
            while !state.0 {
                state = wake.wait(state).expect("gate");
            }
        }
        let second = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || session.write_frame(&[5], &[]))
        };
        {
            let (lock, wake) = &*gate;
            let mut state = lock.lock().expect("gate");
            state.1 = true;
            wake.notify_all();
        }
        assert!(
            !first.join().expect("first"),
            "the partially written frame reports failure"
        );
        assert_eq!(
            done.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(true),
            "finish releases a credit waiter after the carrier fails"
        );
        waiter.join().expect("waiter");
        assert!(
            !second.join().expect("second"),
            "a writer waiting on the failed frame must not reach the carrier"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "only the failing head is written, and the next writer sees the closed session"
        );
        drop(held);
    }

    struct StoppingReader {
        entered: Sender<()>,
        wake: Receiver<()>,
        done: Sender<()>,
    }

    impl Read for StoppingReader {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            let _ = self.entered.send(());
            let _ = self.wake.recv();
            let _ = self.done.send(());
            Ok(0)
        }
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _data: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_carrier_write_wakes_the_reader() {
        let (wake, stopped) = channel();
        let (done, reader_done) = channel();
        let (entered, reading) = channel();
        let session = Inner::start(
            Protocol::Smux,
            Role::Client,
            Box::new(StoppingReader {
                entered,
                wake: stopped,
                done,
            }),
            Box::new(BrokenWriter),
            Arc::new(move || {
                let _ = wake.send(());
            }),
        )
        .expect("session");
        assert_eq!(
            reading.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(()),
            "the reader is inside read before the write fails"
        );
        assert!(!session.write_frame(&[1], &[]), "the write reports failure");
        assert_eq!(
            reader_done.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(()),
            "the reader exits without a manual release"
        );
    }

    #[test]
    fn a_window_hands_back_only_the_credit_it_has() {
        let window = Window::new(1_024);
        assert_eq!(window.take_up_to(16_384), Some(1_024));
        window.close();
        assert_eq!(window.take_up_to(1), None);
    }

    #[test]
    fn a_closed_window_refuses_remaining_credit() {
        let window = Window::new(1_024);
        window.close();
        assert_eq!(
            window.take_up_to(1),
            None,
            "a closed window must not hand out credit a writer could still spend"
        );
    }

    #[test]
    fn an_open_stream_keeps_connection_credit() {
        let window = Window::new(2);
        let closed = AtomicBool::new(false);
        assert_eq!(
            window.take_up_to_while(1, Some(&closed)),
            Some(1),
            "the connection window must hand out credit while the stream is open"
        );
        closed.store(true, Ordering::Relaxed);
        assert_eq!(
            window.take_up_to_while(1, Some(&closed)),
            None,
            "a closed stream must stop taking connection credit"
        );
    }

    #[test]
    fn an_oversized_first_message_is_refused() {
        let queue = Queue::new(4);
        assert_eq!(
            queue.push(Msg {
                data: b"12345".to_vec(),
                end: false,
                credit: 0,
            }),
            Push::Full,
            "the queue bound holds even when the oversized frame is the only one"
        );
        assert!(queue.try_pop().is_none());
    }

    #[test]
    fn a_full_queue_refuses_a_message_instead_of_blocking_the_session() {
        let queue = Queue::new(4);
        assert_eq!(
            queue.push(Msg {
                data: b"1234".to_vec(),
                end: false,
                credit: 0,
            }),
            Push::Queued
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        let pushed = Arc::clone(&queue);
        std::thread::spawn(move || {
            let _ = sender.send(pushed.push(Msg {
                data: b"5".to_vec(),
                end: false,
                credit: 0,
            }));
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(Push::Full),
            "a full queue must refuse the message instead of blocking the demux thread"
        );
        queue.close();
        assert_eq!(
            queue.push(Msg {
                data: b"6".to_vec(),
                end: false,
                credit: 0,
            }),
            Push::Closed
        );
    }

    struct HeldReader(Receiver<()>);

    impl Read for HeldReader {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    struct GateWriter {
        gate: Arc<(Mutex<bool>, Condvar)>,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for GateWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let (lock, wake) = &*self.gate;
            let mut open = lock.lock().expect("gate");
            while !*open {
                open = wake.wait(open).expect("gate");
            }
            drop(open);
            self.seen.lock().expect("seen").extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn held_session(write: Box<dyn Write + Send>) -> (Arc<Inner>, Sender<()>) {
        let (held, reader) = channel();
        let session = Inner::start(
            Protocol::Smux,
            Role::Client,
            Box::new(HeldReader(reader)),
            write,
            Arc::new(|| {}),
        )
        .expect("session");
        (session, held)
    }

    fn held_h2_session(write: Box<dyn Write + Send>) -> (Arc<Inner>, Sender<()>) {
        let (held, reader) = channel();
        let session = Inner::start(
            Protocol::H2Mux,
            Role::Client,
            Box::new(HeldReader(reader)),
            write,
            Arc::new(|| {}),
        )
        .expect("session");
        (session, held)
    }

    #[test]
    fn an_overfull_stream_resets_without_waiting_for_the_carrier() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (session, held) = held_session(Box::new(GateWriter {
            gate: Arc::clone(&gate),
            seen: Arc::clone(&seen),
        }));
        let stream = session.attach(1);
        let mut writer = stream.writer();
        let deliver = Arc::clone(&session);
        let (done, waited) = channel();
        let worker = std::thread::spawn(move || {
            deliver.deliver_credit(1, &vec![0u8; 64 * 1024], false, 0);
            deliver.deliver_credit(1, b"x", false, 0);
            let _ = done.send(());
        });
        assert_eq!(
            waited.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(()),
            "the demux returned before the carrier accepted the reset"
        );
        {
            let (lock, wake) = &*gate;
            *lock.lock().expect("gate") = true;
            wake.notify_all();
        }
        worker.join().expect("worker");
        let fin = smux_head(SMUX_FIN, 1, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !seen
            .lock()
            .expect("seen")
            .windows(SMUX_FRAME)
            .any(|frame| frame == fin)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the overfull stream sends its own Smux FIN after the gate opens"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            writer.write(b"x").is_err(),
            "the released stream refuses a retained writer"
        );
        drop(held);
    }

    #[test]
    fn data_after_a_remote_end_releases_the_waiting_writer() {
        let (session, held) = held_session(Box::new(std::io::sink()));
        let stream = session.attach(1);
        let mut writer = stream.writer();
        session.deliver(1, b"", true);
        session.deliver(1, b"late", false);
        assert!(
            writer.write(b"x").is_err(),
            "a frame after the remote end must not leave a writer free to send"
        );
        assert!(
            session
                .sinks
                .lock()
                .is_ok_and(|sinks| !sinks.contains_key(&1)),
            "the overflowed stream leaves the carrier's table"
        );
        drop(held);
    }

    #[test]
    fn streams_round_trip_over_each_protocol() {
        for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
            round_trip(protocol, false);
        }
    }

    #[test]
    fn datagrams_round_trip_over_each_protocol() {
        for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
            udp_round_trip(protocol, false);
        }
    }

    #[test]
    fn padding_round_trips_over_each_protocol() {
        for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
            round_trip(protocol, true);
        }
    }

    #[test]
    fn packet_addr_frames_each_datagram_with_its_destination() {
        for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
            let (client, server) = pair();
            let server_read = server.try_clone().expect("server read");
            let server_write = server.try_clone().expect("server write");
            let client_read = client.try_clone().expect("client read");
            let client_write = client.try_clone().expect("client write");
            let stop = client.try_clone().expect("client stop");
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let _ = stop.shutdown(Shutdown::Both);
            });
            let worker = std::thread::spawn(move || {
                let session = Server::accept(
                    Box::new(server_read),
                    Box::new(server_write),
                    Arc::new(|| {}),
                )
                .expect("server");
                let mut stream = session.next().expect("stream");
                let request = accept_request(&mut stream).expect("request");
                assert!(request.udp);
                assert!(request.packet_addr);
                let mut atyp = [0u8; 2];
                stream.read_exact(&mut atyp).expect("address");
                assert_eq!(atyp, [3, 9]);
                let mut name = [0u8; 9];
                stream.read_exact(&mut name).expect("address body");
                assert_eq!(&name, b"192.0.2.1");
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).expect("port");
                assert_eq!(u16::from_be_bytes(port), 7);
                let mut head = [0u8; 2];
                stream.read_exact(&mut head).expect("length");
                let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
                stream.read_exact(&mut body).expect("body");
                assert_eq!(&body, b"ping");
                let mut writer = stream.writer();
                let mut reply = Vec::new();
                reply.push(0);
                reply.extend_from_slice(b"\x03\x09192.0.2.1");
                reply.extend_from_slice(&7u16.to_be_bytes());
                reply.extend_from_slice(&4u16.to_be_bytes());
                reply.extend_from_slice(b"pong");
                writer.write_all(&reply).expect("reply");
                writer.finish();
            });
            let session = Client::connect(
                protocol,
                false,
                Box::new(client_read),
                Box::new(client_write),
                Arc::clone(&close),
            )
            .expect("client");
            let target = Destination::Name("example.com".to_owned(), 443);
            let mut stream = session.session.open(&target, false).expect("opens");
            let mut request = encode_request(&target, true);
            request[..2].copy_from_slice(&(FLAG_UDP | FLAG_ADDR).to_be_bytes());
            stream.request = request;
            assert!(stream.send(&[]));
            let mut datagram = Vec::new();
            datagram.extend_from_slice(b"\x03\x09192.0.2.1");
            datagram.extend_from_slice(&7u16.to_be_bytes());
            datagram.extend_from_slice(&4u16.to_be_bytes());
            datagram.extend_from_slice(b"ping");
            assert!(stream.send(&datagram));
            let mut status = [0u8; 1];
            stream.read_exact(&mut status).expect("status");
            assert_eq!(status, [0]);
            let mut address = [0u8; 2];
            stream.read_exact(&mut address).expect("reply address");
            assert_eq!(address, [3, 9]);
            let mut name = [0u8; 9];
            stream.read_exact(&mut name).expect("reply name");
            assert_eq!(&name, b"192.0.2.1");
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).expect("reply port");
            assert_eq!(u16::from_be_bytes(port), 7);
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).expect("reply length");
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
            stream.read_exact(&mut body).expect("reply body");
            assert_eq!(&body, b"pong");
            stream.finish();
            close();
            worker.join().expect("worker");
        }
    }

    #[test]
    fn request_names_and_padding_round_trip() {
        for (name, protocol) in [
            ("smux", Protocol::Smux),
            ("yamux", Protocol::Yamux),
            ("h2mux", Protocol::H2Mux),
            ("", Protocol::H2Mux),
        ] {
            assert_eq!(Protocol::parse(name), Some(protocol));
        }
        assert_eq!(Protocol::parse("mux.cool"), None);
        let mut encoded = Vec::new();
        write_request(&mut encoded, Protocol::Yamux, true).expect("encode");
        assert_eq!(encoded[..3], [1, 1, 1]);
        let mut input = encoded.as_slice();
        assert_eq!(
            read_request(&mut input).expect("decode"),
            (Protocol::Yamux, true)
        );
    }
}

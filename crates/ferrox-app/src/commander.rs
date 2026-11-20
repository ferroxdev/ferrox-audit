//! The management API: a gRPC `HandlerService` an operator reaches over the same config xray reads.
//!
//! xray serves the unary calls over HTTP/2 in clear text; this tree already carries the framing
//! for its own gRPC transport, so the server reads the same preface and frames here and writes the
//! five-byte message prefix itself. Nothing is dialed to answer a call in `listen` mode, and in
//! outbound mode the routed link is the transport.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::conn::Connection;
use crate::h2;
use crate::json::Json;
use crate::vmess;

/// What the `api` app names: the tag routing reaches in outbound mode, and the address a listener
/// answers on in listen mode. xray treats the two as independent: a config may name either or both.
#[derive(Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ApiConfig {
    pub(crate) tag: String,
    pub(crate) listen: Option<String>,
    pub(crate) handler: bool,
    pub(crate) stats: bool,
    pub(crate) logger: bool,
    pub(crate) observatory: bool,
    pub(crate) routing: bool,
}

impl ApiConfig {
    pub(crate) fn from_proto(bytes: &[u8]) -> Result<Self, String> {
        let mut config = Self::default();
        let mut reader = Pb::new(bytes);
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, Value::Bytes(tag)) => {
                    config.tag = String::from_utf8(tag.to_vec())
                        .map_err(|_| "xray.app.commander.Config: tag is not utf-8".to_owned())?;
                }
                (2, Value::Bytes(service)) => {
                    let (name, _) = typed(service)?;
                    config.service(&name);
                }
                (3, Value::Bytes(listen)) => {
                    config.listen = Some(
                        std::str::from_utf8(listen)
                            .map_err(|_| {
                                "xray.app.commander.Config: listen is not utf-8".to_owned()
                            })?
                            .to_owned(),
                    );
                }
                (_, value) => {
                    return Err(format!(
                        "xray.app.commander.Config: field {field} {value:?}"
                    ))
                }
            }
        }
        Ok(config)
    }

    fn service(&mut self, name: &str) {
        match name {
            "xray.app.proxyman.command.Config" => self.handler = true,
            "xray.app.stats.command.Config" => self.stats = true,
            "xray.app.log.command.Config" => self.logger = true,
            "xray.app.router.command.Config" => self.routing = true,
            "xray.core.app.observatory.command.Config" | "xray.app.observatory.command.Config" => {
                self.observatory = true;
            }
            "xray.app.commander.ReflectionConfig" => {}
            other => eprintln!("commander: service `{other}` is not carried; skipped"),
        }
    }

    pub(crate) fn from_json(root: &Json) -> Option<Self> {
        let api = root.get("api")?;
        let tag = api
            .get("tag")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let listen = api
            .get("listen")
            .and_then(Json::as_str)
            .filter(|listen| !listen.is_empty())
            .map(str::to_owned);
        let mut config = Self {
            tag,
            listen,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        };
        if let Some(services) = api.get("services").and_then(Json::as_arr) {
            for service in services.iter().filter_map(Json::as_str) {
                if service.eq_ignore_ascii_case("HandlerService") {
                    config.handler = true;
                } else if service.eq_ignore_ascii_case("StatsService") {
                    config.stats = true;
                } else if service.eq_ignore_ascii_case("LoggerService") {
                    config.logger = true;
                } else if service.eq_ignore_ascii_case("ObservatoryService") {
                    config.observatory = true;
                } else if service.eq_ignore_ascii_case("RoutingService") {
                    config.routing = true;
                } else if service.eq_ignore_ascii_case("ReflectionService") {
                } else {
                    eprintln!("commander: service `{service}` is not carried; skipped");
                }
            }
        }
        Some(config)
    }
}

/// One handler this process serves, with what removal and user management need. A handler whose
/// listener the tree cannot stop carries no stops and answers `RemoveInbound` with that reason.
struct Inbound {
    tag: String,
    raw: Option<Vec<u8>>,
    protocol: String,
    users: Option<vmess::UsersRef>,
    stops: Vec<(Arc<crate::proxy::Stop>, String)>,
}

/// The configured outbounds as they arrived, for the one call that lists them back.
struct Outbound {
    tag: String,
    raw: Vec<u8>,
}

#[derive(Default)]
struct State {
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound>,
}

/// The management app itself: the service selection plus the handlers it learns at startup and by
/// the calls that add or remove them.
pub(crate) struct Api {
    config: ApiConfig,
    state: Mutex<State>,
    mutation: Mutex<()>,
    start: std::time::Instant,
    runtime: std::sync::OnceLock<Arc<crate::proxy::Runtime>>,
    observatory: std::sync::OnceLock<Option<Arc<crate::observatory::Observatory>>>,
    #[cfg(test)]
    cap_reached: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("config", &self.config)
            .field(
                "state",
                &self.state.lock().map(|state| state.inbounds.len()),
            )
            .field("mutation", &self.mutation.try_lock().is_ok())
            .field("start", &self.start)
            .field("runtime", &self.runtime.get().is_some())
            .field("observatory", &self.observatory.get().is_some())
            .finish_non_exhaustive()
    }
}

/// The management API answers from a fixed worker count; a peer that opens more sockets than this is refused rather than given a thread.
const API_WORKERS: usize = 8;
const API_STACK: usize = 256 * 1024;
const API_IDLE: Duration = Duration::from_secs(30);
/// What one admitted connection may pin: the open-call cap is advertised in its SETTINGS, the header
/// cap is the tree's own, and the message cap is the reference's gRPC receive limit.
const API_CALLS: usize = 100;
/// The receive limit the service advertises is a message size; the five-byte gRPC envelope rides on top of it.
const CALL_MAX: usize = 4 * 1024 * 1024;
const CALL_ENVELOPE: usize = 5;
const WIRE_MAX: usize = CALL_MAX + CALL_ENVELOPE;
const H2_MAX_FRAME: usize = 16_384;
/// What a connection's open calls may hold together: two maximum messages in flight, so the product
/// of the call cap and the message cap is not what one peer can pin.
const API_HELD: usize = 2 * WIRE_MAX;
static API_SLOTS: crate::limit::Slots = crate::limit::Slots::new(API_WORKERS);
static API_REFUSED: AtomicBool = AtomicBool::new(false);

fn refuse_api() {
    if !API_REFUSED.swap(true, Ordering::Relaxed) {
        eprintln!("commander: {API_WORKERS} management connections are busy; refusing more");
    }
}

impl Api {
    pub(crate) fn new(config: ApiConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(State::default()),
            mutation: Mutex::new(()),
            start: std::time::Instant::now(),
            runtime: std::sync::OnceLock::new(),
            observatory: std::sync::OnceLock::new(),
            #[cfg(test)]
            cap_reached: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn watch_header_cap(&self, sender: std::sync::mpsc::Sender<()>) {
        *self
            .cap_reached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
    }

    #[cfg(test)]
    fn header_cap_reached(&self, headers: usize) {
        if headers != h2::HEAD_CAP {
            return;
        }
        if let Some(sender) = self
            .cap_reached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = sender.send(());
        }
    }

    pub(crate) fn tag(&self) -> &str {
        &self.config.tag
    }

    /// A routed API owns its tag as an outbound handler; a listening API only owns the socket.
    pub(crate) fn routed(&self) -> bool {
        self.config.listen.is_none()
    }

    /// The startup context a later `AddInbound` needs; set once the routes are built.
    pub(crate) fn set_runtime(&self, runtime: Arc<crate::proxy::Runtime>) {
        let _ = self.runtime.set(runtime);
    }

    pub(crate) fn set_observatory(
        &self,
        observatory: Option<Arc<crate::observatory::Observatory>>,
    ) {
        let _ = self.observatory.set(observatory);
    }

    fn runtime(&self) -> Result<&Arc<crate::proxy::Runtime>, (u32, String)> {
        self.runtime
            .get()
            .ok_or_else(|| (13, "commander runtime is unavailable".to_owned()))
    }

    pub(crate) fn seed_outbounds(&self, seed: &[(String, Vec<u8>)]) {
        if let Ok(mut state) = self.state.lock() {
            state.outbounds = seed
                .iter()
                .filter(|(tag, _)| self.routed() || tag != &self.config.tag)
                .map(|(tag, raw)| Outbound {
                    tag: tag.clone(),
                    raw: raw.clone(),
                })
                .collect();
        }
    }

    /// A JSON config carries no protobuf handler, so the listing synthesizes the tag the
    /// reference would return and removal still knows which configured tag it names.
    pub(crate) fn seed_json_outbounds(&self, root: &crate::json::Json) {
        let list = root
            .get("outbounds")
            .and_then(crate::json::Json::as_arr)
            .unwrap_or(&[]);
        if let Ok(mut state) = self.state.lock() {
            state.outbounds = list
                .iter()
                .filter_map(|outbound| {
                    let tag = outbound
                        .get("tag")
                        .and_then(crate::json::Json::as_str)
                        .filter(|tag| {
                            !tag.is_empty() && (!self.routed() || *tag != self.config.tag)
                        })?;
                    let mut raw = Vec::new();
                    field_str(&mut raw, 1, tag);
                    Some(Outbound {
                        tag: tag.to_owned(),
                        raw,
                    })
                })
                .collect();
        }
    }

    pub(crate) fn register_inbound(
        &self,
        tag: &str,
        raw: Option<Vec<u8>>,
        protocol: &str,
        users: Option<vmess::UsersRef>,
        stops: Vec<(Arc<crate::proxy::Stop>, String)>,
    ) {
        if !self.config.handler || (tag.is_empty() && raw.is_none()) {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            if !tag.is_empty() {
                if let Some(existing) = state.inbounds.iter_mut().find(|entry| entry.tag == tag) {
                    existing.stops.extend(stops);
                    if existing.raw.is_none() {
                        existing.raw = raw;
                    }
                    if existing.users.is_none() {
                        existing.users = users;
                    }
                    return;
                }
            }
            state.inbounds.push(Inbound {
                tag: tag.to_owned(),
                raw,
                protocol: protocol.to_owned(),
                users,
                stops,
            });
        }
    }

    /// Bind the configured listen address and answer accepted connections from a bounded set of workers.
    pub(crate) fn serve_listen(self: &Arc<Self>) -> Result<(), String> {
        let Some(address) = self.config.listen.clone() else {
            return Ok(());
        };
        let targets = if address.starts_with("unix:") {
            vec![crate::conn::parse_target(&address)
                .map_err(|error| format!("cannot resolve {address}: {error}"))?]
        } else {
            address
                .to_socket_addrs()
                .map_err(|error| format!("cannot resolve {address}: {error}"))?
                .map(crate::conn::Target::Ip)
                .collect()
        };
        let mut last = None;
        let mut listener = None;
        for target in &targets {
            match crate::conn::Listener::bind(target) {
                Ok(bound) => {
                    listener = Some(bound);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let Some(listener) = listener else {
            let error = last.map_or_else(
                || "address resolved to nothing".to_owned(),
                |e| e.to_string(),
            );
            return Err(format!("cannot listen on {address}: {error}"));
        };
        let api = Arc::clone(self);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Some(slot) = API_SLOTS.acquire() else {
                    refuse_api();
                    continue;
                };
                let api = Arc::clone(&api);
                let worker = thread::Builder::new()
                    .name("ferrox-api".to_owned())
                    .stack_size(API_STACK)
                    .spawn(move || {
                        let _slot = slot;
                        api.serve_stream(stream);
                    });
                if let Err(error) = worker {
                    eprintln!("commander: cannot start a management worker: {error}");
                }
            }
        });
        Ok(())
    }

    /// One HTTP/2 connection's worth of calls under the configured idle bound.
    pub(crate) fn serve_stream(&self, stream: Connection) {
        self.serve_stream_with_idle(stream, API_IDLE);
    }

    /// A tunnel the rules routed to the API tag, under the same slot cap as the listener.
    pub(crate) fn serve_routed(&self, stream: Connection) {
        let Some(_slot) = API_SLOTS.acquire() else {
            refuse_api();
            return;
        };
        self.serve_stream(stream);
    }

    /// One HTTP/2 connection's worth of calls. The client opens the preface and its SETTINGS, then
    /// a HEADERS/DATA pair per call; this answers each completed body in arrival order. Every frame
    /// head waits only for the configured idle bound, not the relay's retry grain.
    #[allow(clippy::too_many_lines)]
    fn serve_stream_with_idle(&self, mut stream: Connection, idle: Duration) {
        if stream.set_read_timeout(Some(idle)).is_err()
            || stream.set_write_timeout(Some(idle)).is_err()
        {
            return;
        }
        let mut preface = [0u8; 24];
        if stream.read_exact(&mut preface).is_err() || &preface != h2::MAGIC {
            return;
        }
        if !h2::write_frame(&mut stream, h2::T_SETTINGS, 0, 0, &settings()) {
            return;
        }
        let mut decoder = h2::Decoder::default();
        let mut calls: HashMap<u32, Call> = HashMap::new();
        let mut discard: Option<(u32, Vec<u8>)> = None;
        let mut continuation: Option<u32> = None;
        let mut responses: HashMap<u32, Response> = HashMap::new();
        let mut flow = Flow::new();
        let mut last_id = 0u32;
        while let Some((len, kind, flags, id)) = h2::read_head_bounded(&mut stream) {
            let cap = match kind {
                h2::T_HEADERS | h2::T_CONT => h2::HEAD_CAP,
                _ => WIRE_MAX,
            };
            if len > cap {
                goaway(&mut stream, h2::E_FRAME_SIZE, last_id);
                return;
            }
            let body = if matches!(
                kind,
                h2::T_HEADERS
                    | h2::T_CONT
                    | h2::T_DATA
                    | h2::T_SETTINGS
                    | h2::T_WINDOW
                    | h2::T_PING
                    | h2::T_RST
                    | h2::T_GOAWAY
            ) {
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).is_err() {
                    return;
                }
                body
            } else {
                let mut left = len;
                let mut waste = [0u8; 4096];
                while left > 0 {
                    let take = left.min(waste.len());
                    if stream.read_exact(&mut waste[..take]).is_err() {
                        return;
                    }
                    left -= take;
                }
                Vec::new()
            };
            if id == 0 && matches!(kind, h2::T_HEADERS | h2::T_DATA | h2::T_CONT | h2::T_RST) {
                goaway(&mut stream, h2::E_PROTOCOL, last_id);
                return;
            }
            if let Some(owner) = continuation {
                if kind != h2::T_CONT || id != owner {
                    goaway(&mut stream, h2::E_PROTOCOL, last_id);
                    return;
                }
            } else if kind == h2::T_CONT {
                goaway(&mut stream, h2::E_PROTOCOL, last_id);
                return;
            }
            if kind == h2::T_SETTINGS && id != 0 {
                goaway(&mut stream, h2::E_PROTOCOL, last_id);
                return;
            }
            match kind {
                h2::T_SETTINGS => {
                    if flags & h2::F_ACK == 0 {
                        if !flow.settings(&body) {
                            goaway(&mut stream, h2::E_FLOW, last_id);
                            return;
                        }
                        if !h2::write_frame(&mut stream, h2::T_SETTINGS, h2::F_ACK, 0, &[]) {
                            return;
                        }
                    }
                }
                h2::T_WINDOW => {
                    if id != 0 && flow.idle(id) {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    }
                    let increment = (body.len() == 4).then(|| {
                        i64::from(u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7fff_ffff)
                    });
                    if !increment.is_some_and(|increment| flow.window(id, increment)) {
                        if id == 0 {
                            goaway(&mut stream, h2::E_PROTOCOL, last_id);
                            return;
                        }
                        if !reset(&mut stream, id, h2::E_PROTOCOL) {
                            return;
                        }
                        calls.remove(&id);
                        responses.remove(&id);
                        flow.close(id);
                    }
                }
                h2::T_PING => {
                    if flags & h2::F_ACK == 0
                        && !h2::write_frame(&mut stream, h2::T_PING, h2::F_ACK, 0, &body)
                    {
                        return;
                    }
                }
                h2::T_HEADERS => {
                    let Some(block) = header_body(&body, flags) else {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    };
                    if id.is_multiple_of(2) {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    }
                    if responses.contains_key(&id) {
                        if let Err(code) = absorb_headers(
                            &mut decoder,
                            &mut discard,
                            id,
                            block,
                            flags & h2::F_END_HEADERS != 0,
                            false,
                        ) {
                            goaway(&mut stream, code, last_id);
                            return;
                        }
                        if flags & h2::F_END_HEADERS == 0 {
                            continuation = Some(id);
                        }
                        continue;
                    }
                    if flow.cancelled(id) {
                        if let Err(code) = absorb_headers(
                            &mut decoder,
                            &mut discard,
                            id,
                            block,
                            flags & h2::F_END_HEADERS != 0,
                            false,
                        ) {
                            goaway(&mut stream, code, last_id);
                            return;
                        }
                        if flags & h2::F_END_HEADERS == 0 {
                            continuation = Some(id);
                        }
                        continue;
                    }
                    if calls.get(&id).is_some_and(|call| call.end_headers) {
                        let end = flags & h2::F_END_HEADERS != 0;
                        let end_stream = flags & h2::F_END != 0;
                        if let Some(call) = calls.get_mut(&id) {
                            call.end_stream |= end_stream;
                        }
                        let invalid = match absorb_headers(
                            &mut decoder,
                            &mut discard,
                            id,
                            block,
                            end,
                            true,
                        ) {
                            Ok(invalid) => invalid,
                            Err(code) => {
                                goaway(&mut stream, code, last_id);
                                return;
                            }
                        };
                        if end {
                            if invalid || !end_stream {
                                if !reset(&mut stream, id, h2::E_PROTOCOL) {
                                    return;
                                }
                                calls.remove(&id);
                                responses.remove(&id);
                                flow.close(id);
                            } else {
                                last_id = last_id.max(id);
                                if !self.answer(
                                    id,
                                    &calls.remove(&id).unwrap_or_default(),
                                    &mut stream,
                                    &mut flow,
                                    &mut responses,
                                ) {
                                    return;
                                }
                            }
                        } else {
                            continuation = Some(id);
                        }
                        continue;
                    }
                    if calls.len() + responses.len() >= API_CALLS && !calls.contains_key(&id) {
                        if let Err(code) = absorb_headers(
                            &mut decoder,
                            &mut discard,
                            id,
                            block,
                            flags & h2::F_END_HEADERS != 0,
                            false,
                        ) {
                            goaway(&mut stream, code, last_id);
                            return;
                        }
                        if flags & h2::F_END_HEADERS == 0 {
                            continuation = Some(id);
                        }
                        if !reset(&mut stream, id, h2::E_REFUSED) {
                            return;
                        }
                        flow.refuse(id);
                        continue;
                    }
                    if !flow.open(id) {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    }
                    let held = calls.get(&id).map_or(0, |call| call.headers.len());
                    if held + block.len() > h2::HEAD_CAP {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    }
                    let call = calls.entry(id).or_default();
                    call.headers.extend_from_slice(block);
                    #[cfg(test)]
                    self.header_cap_reached(call.headers.len());
                    call.end_headers = flags & h2::F_END_HEADERS != 0;
                    call.end_stream = flags & h2::F_END != 0;
                    if call.end_headers && !call.read_path(&mut decoder) {
                        goaway(&mut stream, h2::E_COMPRESSION, last_id);
                        return;
                    }
                    if call.end_headers && call.end_stream {
                        last_id = last_id.max(id);
                        if !self.answer(
                            id,
                            &calls.remove(&id).unwrap_or_default(),
                            &mut stream,
                            &mut flow,
                            &mut responses,
                        ) {
                            return;
                        }
                    } else if !call.end_headers {
                        continuation = Some(id);
                    }
                }
                h2::T_CONT => {
                    if discard.is_some() {
                        let trailers = calls.get(&id).is_some_and(|call| call.end_headers);
                        let invalid = match absorb_headers(
                            &mut decoder,
                            &mut discard,
                            id,
                            &body,
                            flags & h2::F_END_HEADERS != 0,
                            trailers,
                        ) {
                            Ok(invalid) => invalid,
                            Err(code) => {
                                goaway(&mut stream, code, last_id);
                                return;
                            }
                        };
                        if flags & h2::F_END_HEADERS != 0 {
                            continuation = None;
                            if trailers {
                                if let Some(call) = calls.remove(&id) {
                                    if invalid || !call.end_stream {
                                        if !reset(&mut stream, id, h2::E_PROTOCOL) {
                                            return;
                                        }
                                        responses.remove(&id);
                                        flow.close(id);
                                    } else {
                                        last_id = last_id.max(id);
                                        if !self.answer(
                                            id,
                                            &call,
                                            &mut stream,
                                            &mut flow,
                                            &mut responses,
                                        ) {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(call) = calls.get_mut(&id) {
                        if call.headers.len() + body.len() > h2::HEAD_CAP {
                            goaway(&mut stream, h2::E_PROTOCOL, last_id);
                            return;
                        }
                        call.headers.extend_from_slice(&body);
                        #[cfg(test)]
                        self.header_cap_reached(call.headers.len());
                        if flags & h2::F_END_HEADERS != 0 {
                            call.end_headers = true;
                            if !call.read_path(&mut decoder) {
                                goaway(&mut stream, h2::E_COMPRESSION, last_id);
                                return;
                            }
                            continuation = None;
                            if call.end_stream {
                                last_id = last_id.max(id);
                                if !self.answer(
                                    id,
                                    &calls.remove(&id).unwrap_or_default(),
                                    &mut stream,
                                    &mut flow,
                                    &mut responses,
                                ) {
                                    return;
                                }
                            }
                        }
                    }
                }
                h2::T_DATA => {
                    let Some(payload) = data_body(&body, flags) else {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    };
                    if flow.cancelled(id) || flow.is_ended(id) {
                        if !flow.take_recv(id, body.len()) {
                            goaway(&mut stream, h2::E_FLOW, last_id);
                            return;
                        }
                        if !reset(&mut stream, id, h2::E_CLOSED) {
                            return;
                        }
                        if !window_update(&mut stream, 0, body.len()) {
                            return;
                        }
                        flow.give_recv(id, body.len());
                        responses.remove(&id);
                        flow.close(id);
                        continue;
                    }
                    if !flow.take_recv(id, body.len()) {
                        goaway(&mut stream, h2::E_FLOW, last_id);
                        return;
                    }
                    let held: usize = calls.values().map(|call| call.body.len()).sum();
                    let Some(call) = calls.get_mut(&id) else {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    };
                    if call.body.len() + payload.len() > WIRE_MAX || held + payload.len() > API_HELD
                    {
                        goaway(&mut stream, h2::E_REFUSED, last_id);
                        return;
                    }
                    call.body.extend_from_slice(payload);
                    if !window_update(&mut stream, 0, body.len())
                        || !window_update(&mut stream, id, body.len())
                    {
                        return;
                    }
                    flow.give_recv(id, body.len());
                    if flags & h2::F_END != 0 {
                        last_id = last_id.max(id);
                        if !self.answer(
                            id,
                            &calls.remove(&id).unwrap_or_default(),
                            &mut stream,
                            &mut flow,
                            &mut responses,
                        ) {
                            return;
                        }
                    }
                }
                h2::T_RST => {
                    if body.len() != 4 {
                        goaway(&mut stream, h2::E_FRAME_SIZE, last_id);
                        return;
                    }
                    if flow.idle(id) {
                        goaway(&mut stream, h2::E_PROTOCOL, last_id);
                        return;
                    }
                    calls.remove(&id);
                    responses.remove(&id);
                    flow.close(id);
                }
                h2::T_GOAWAY => return,
                _ => {}
            }
            if !flush_responses(&mut stream, &mut flow, &mut responses) {
                return;
            }
        }
    }

    fn answer(
        &self,
        id: u32,
        call: &Call,
        stream: &mut Connection,
        flow: &mut Flow,
        responses: &mut HashMap<u32, Response>,
    ) -> bool {
        flow.end_request(id);
        let Some(request) = grpc_message(&call.body) else {
            let head = [(":status", "200"), ("content-type", "application/grpc")];
            let block = h2::block_encode(&head);
            if !h2::write_frame(stream, h2::T_HEADERS, h2::F_END_HEADERS, id, &block) {
                return false;
            }
            let trailers = h2::block_encode(&[
                ("grpc-status", "13"),
                ("grpc-message", "malformed unary request"),
            ]);
            if !h2::write_frame(
                stream,
                h2::T_HEADERS,
                h2::F_END_HEADERS | h2::F_END,
                id,
                &trailers,
            ) {
                return false;
            }
            flow.close(id);
            return true;
        };
        match self.dispatch(&call.path, request) {
            Ok(answer) => {
                let head = [(":status", "200"), ("content-type", "application/grpc")];
                let block = h2::block_encode(&head);
                if !h2::write_frame(stream, h2::T_HEADERS, h2::F_END_HEADERS, id, &block) {
                    return false;
                }
                let mut framed = Vec::with_capacity(answer.len() + 5);
                framed.push(0);
                framed.extend_from_slice(&(answer.len() as u32).to_be_bytes());
                framed.extend_from_slice(&answer);
                let buffered: usize = responses
                    .values()
                    .map(|response| response.framed.capacity())
                    .sum();
                if buffered.saturating_add(framed.capacity()) > API_HELD {
                    let trailers = h2::block_encode(&[
                        ("grpc-status", "8"),
                        ("grpc-message", "response budget exhausted"),
                    ]);
                    if !h2::write_frame(
                        stream,
                        h2::T_HEADERS,
                        h2::F_END_HEADERS | h2::F_END,
                        id,
                        &trailers,
                    ) {
                        return false;
                    }
                    flow.close(id);
                    return true;
                }
                let trailers = h2::block_encode(&[("grpc-status", "0")]);
                responses.insert(
                    id,
                    Response {
                        framed,
                        at: 0,
                        trailers,
                    },
                );
                flush_response(stream, id, flow, responses)
            }
            Err((status, message)) => {
                let code = status.to_string();
                let message = percent(&message);
                let head = [(":status", "200"), ("content-type", "application/grpc")];
                let block = h2::block_encode(&head);
                if !h2::write_frame(stream, h2::T_HEADERS, h2::F_END_HEADERS, id, &block) {
                    return false;
                }
                let trailers = h2::block_encode(&[
                    ("grpc-status", code.as_str()),
                    ("grpc-message", message.as_str()),
                ]);
                if !h2::write_frame(
                    stream,
                    h2::T_HEADERS,
                    h2::F_END_HEADERS | h2::F_END,
                    id,
                    &trailers,
                ) {
                    return false;
                }
                flow.close(id);
                true
            }
        }
    }

    fn dispatch(&self, path: &str, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let (service, method) = path.rsplit_once('/').unwrap_or(("", path));
        if service == "/xray.app.log.command.LoggerService" {
            if method == "RestartLogger" && self.config.logger {
                return crate::accesslog::restart()
                    .map(|()| Vec::new())
                    .map_err(|error| (13, error));
            }
            return Err((12, format!("{path} is not a method this server carries")));
        }
        if service == "/xray.core.app.observatory.command.ObservatoryService" {
            if method == "GetOutboundStatus" && self.config.observatory {
                return Ok(self.get_outbound_status());
            }
            return Err((12, format!("{path} is not a method this server carries")));
        }
        if service == "/xray.app.router.command.RoutingService"
            || service == "/v2ray.core.app.router.command.RoutingService"
        {
            if self.config.routing {
                return self.routing_call(method, request, path);
            }
            return Err((12, format!("{path} is not a method this server carries")));
        }
        let handler = service == "/xray.app.proxyman.command.HandlerService";
        let stats = service == "/xray.app.stats.command.StatsService";
        match (method, handler, stats) {
            ("RemoveInbound", true, _) if self.config.handler => self.remove_inbound(request),
            ("ListInbounds", true, _) if self.config.handler => self.list_inbounds(request),
            ("ListOutbounds", true, _) if self.config.handler => self.list_outbounds(),
            ("AlterInbound", true, _) if self.config.handler => self.alter_inbound(request),
            ("GetInboundUsers", true, _) if self.config.handler => self.get_users(request, false),
            ("GetInboundUsersCount", true, _) if self.config.handler => {
                self.get_users(request, true)
            }
            ("AddInbound", true, _) if self.config.handler => self.add_inbound(request),
            ("AddOutbound", true, _) if self.config.handler => self.add_outbound(request),
            ("RemoveOutbound", true, _) if self.config.handler => self.remove_outbound(request),
            ("AlterOutbound", true, _) if self.config.handler => Self::alter_outbound(request),
            ("GetStats", _, true) if self.config.stats => Self::get_stats(request),
            ("QueryStats", _, true) if self.config.stats => Ok(Self::query_stats(request)),
            ("GetSysStats", _, true) if self.config.stats => Ok(self.sys_stats()),
            ("GetStatsOnline", _, true) if self.config.stats => Self::get_stats_online(request),
            ("GetStatsOnlineIpList", _, true) if self.config.stats => {
                Self::get_stats_online_ip_list(request)
            }
            ("GetAllOnlineUsers", _, true) if self.config.stats => Ok(Self::get_all_online_users()),
            ("GetUsersStats", _, true) if self.config.stats => Ok(Self::get_users_stats(request)),
            _ => Err((12, format!("{path} is not a method this server carries"))),
        }
    }

    fn get_outbound_status(&self) -> Vec<u8> {
        let mut status = Vec::new();
        if let Some(Some(observatory)) = self.observatory.get() {
            for observed in observatory.snapshot().iter() {
                field_bytes(&mut status, 1, &outbound_status(observed));
            }
        }
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &status);
        out
    }

    fn routing_call(
        &self,
        method: &str,
        request: &[u8],
        path: &str,
    ) -> Result<Vec<u8>, (u32, String)> {
        match method {
            "ListRule" => self.list_rules(),
            "AddRule" => self.add_rule(request),
            "RemoveRule" => self.remove_rule(request),
            "TestRoute" => self.test_route(request),
            "GetBalancerInfo" => self.get_balancer_info(request),
            "OverrideBalancerTarget" => self.override_balancer_target(request),
            // The reference registers this service without a statistics channel, so it always says so.
            "SubscribeRoutingStats" => Err((2, "Routing statistics not enabled.".to_owned())),
            _ => Err((12, format!("{path} is not a method this server carries"))),
        }
    }

    fn list_rules(&self) -> Result<Vec<u8>, (u32, String)> {
        let mut out = Vec::new();
        for rule in self.runtime()?.listed_rules() {
            let mut item = Vec::new();
            if !rule.balancer {
                field_str(&mut item, 1, &rule.target);
            }
            if let Some(tag) = &rule.tag {
                field_str(&mut item, 2, tag);
            }
            field_bytes(&mut out, 1, &item);
        }
        Ok(out)
    }

    /// Append or replace the live rule table; the reference answers a bare status, so does this.
    fn add_rule(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let (rules, append) =
            crate::xray_pb::add_rule_request(request).map_err(|reason| (2, reason))?;
        self.runtime()?
            .add_rules(&rules, append)
            .map_err(|reason| (2, reason))?;
        Ok(Vec::new())
    }

    /// Drop every rule carrying the request's ruleTag.
    fn remove_rule(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let tag = request_str(request, 1).unwrap_or_default();
        if tag.is_empty() {
            return Err((2, "empty tag name!".to_owned()));
        }
        self.runtime()?
            .remove_rules(&tag)
            .map_err(|reason| (2, reason))?;
        Ok(Vec::new())
    }

    fn test_route(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let Some(raw) = request_bytes(request, 1) else {
            return Err((2, "Invalid routing request.".to_owned()));
        };
        let context = RoutingContext::parse(raw)
            .map_err(|reason| (3, format!("routing context: {reason}")))?;
        let selectors = request_strs(request, 2);
        let pairs: Vec<(String, String)> = context
            .attrs
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    std::str::from_utf8(name).ok()?.to_owned(),
                    std::str::from_utf8(value).ok()?.to_owned(),
                ))
            })
            .collect();
        let attributes = (!pairs.is_empty()).then(|| crate::router::Attributes::from_pairs(&pairs));
        let probe = context
            .probe(attributes.as_ref())
            .map_err(|reason| (3, format!("routing context: {reason}")))?;
        let Some(tag) = self
            .runtime()?
            .tested_route(&probe)
            .map_err(|reason| (2, reason))?
        else {
            return Err((2, "no clue".to_owned()));
        };
        Ok(context.answered(&selectors, &tag))
    }

    fn get_balancer_info(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let tag = request_str(request, 1).unwrap_or_default();
        let (forced, principle) = self
            .runtime()?
            .balancer_info(&tag)
            .map_err(|reason| (2, reason.to_owned()))?;
        let mut override_info = Vec::new();
        if !forced.is_empty() {
            field_str(&mut override_info, 2, &forced);
        }
        let mut target = Vec::new();
        for tag in &principle {
            field_str(&mut target, 1, tag);
        }
        let mut balancer = Vec::new();
        field_bytes(&mut balancer, 5, &override_info);
        field_bytes(&mut balancer, 6, &target);
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &balancer);
        Ok(out)
    }

    fn override_balancer_target(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let tag = request_str(request, 1).unwrap_or_default();
        let target = request_str(request, 2).unwrap_or_default();
        self.runtime()?
            .override_balancer(&tag, &target)
            .map_err(|reason| (2, reason))?;
        Ok(Vec::new())
    }

    fn get_stats(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let name = request_str(request, 1).unwrap_or_default();
        let reset = request_varint(request, 2).unwrap_or(0) != 0;
        let value =
            crate::stats::get(&name, reset).ok_or_else(|| (5, format!("{name} not found.")))?;
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &stat(&name, value));
        Ok(out)
    }

    fn get_stats_online(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let name = request_str(request, 1).unwrap_or_default();
        let value =
            crate::stats::online_count(&name).ok_or_else(|| (5, format!("{name} not found.")))?;
        let mut out = Vec::new();
        field_bytes(&mut out, 1, &stat(&name, value.cast_signed()));
        Ok(out)
    }

    fn get_stats_online_ip_list(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let name = request_str(request, 1).unwrap_or_default();
        let ips =
            crate::stats::online_ips(&name).ok_or_else(|| (5, format!("{name} not found.")))?;
        let mut out = Vec::new();
        field_str(&mut out, 1, &name);
        for (ip, last_seen) in ips {
            let mut entry = Vec::new();
            field_str(&mut entry, 1, &ip);
            field_varint(&mut entry, 2, last_seen.cast_unsigned());
            field_bytes(&mut out, 2, &entry);
        }
        Ok(out)
    }

    fn get_all_online_users() -> Vec<u8> {
        let mut out = Vec::new();
        for user in crate::stats::online_users() {
            field_str(&mut out, 1, &user);
        }
        out
    }

    fn get_users_stats(request: &[u8]) -> Vec<u8> {
        let include_traffic = request_varint(request, 1).unwrap_or(0) != 0;
        let reset = request_varint(request, 2).unwrap_or(0) != 0;
        let mut out = Vec::new();
        for user in crate::stats::online_user_stats() {
            let mut row = Vec::new();
            field_str(&mut row, 1, &user.email);
            for (ip, last_seen) in &user.ips {
                let mut entry = Vec::new();
                field_str(&mut entry, 1, ip);
                field_varint(&mut entry, 2, last_seen.cast_unsigned());
                field_bytes(&mut row, 2, &entry);
            }
            if include_traffic {
                let uplink =
                    crate::stats::get(&format!("user>>>{}>>>traffic>>>uplink", user.email), reset)
                        .unwrap_or(0);
                let downlink = crate::stats::get(
                    &format!("user>>>{}>>>traffic>>>downlink", user.email),
                    reset,
                )
                .unwrap_or(0);
                let mut traffic = Vec::new();
                field_varint(&mut traffic, 1, uplink.cast_unsigned());
                field_varint(&mut traffic, 2, downlink.cast_unsigned());
                field_bytes(&mut row, 3, &traffic);
            }
            field_bytes(&mut out, 1, &row);
        }
        out
    }

    fn query_stats(request: &[u8]) -> Vec<u8> {
        let pattern = request_str(request, 1).unwrap_or_default();
        let reset = request_varint(request, 2).unwrap_or(0) != 0;
        let mut out = Vec::new();
        for (name, value) in crate::stats::query(&pattern, reset) {
            field_bytes(&mut out, 1, &stat(&name, value));
        }
        out
    }

    fn sys_stats(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in 1..=9 {
            field_varint(&mut out, field, 0);
        }
        field_varint(&mut out, 10, self.start.elapsed().as_secs());
        out
    }

    fn remove_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        if tag.is_empty() {
            return Err((2, "empty handler tag".to_owned()));
        }
        let stops = {
            let Ok(state) = self.state.lock() else {
                return Err((13, "commander state is unavailable".into()));
            };
            let Some(entry) = state.inbounds.iter().find(|entry| entry.tag == tag) else {
                return Err((2, format!("inbound `{tag}` not found")));
            };
            if entry.stops.is_empty() {
                return Err((
                    12,
                    format!(
                        "inbound `{tag}` ({}) has no listener this tree can stop",
                        entry.protocol
                    ),
                ));
            }
            entry.stops.clone()
        };
        for (stop, address) in &stops {
            stop.stop();
            crate::proxy::wake_listener(stop, address);
        }
        for (stop, address) in &stops {
            if !stop.wait_closed() {
                return Err((
                    13,
                    format!("inbound `{tag}` listener at {address} did not close"),
                ));
            }
        }
        if let Ok(mut state) = self.state.lock() {
            state.inbounds.retain(|entry| entry.tag != tag);
        }
        if let Ok(runtime) = self.runtime() {
            runtime.forget_server_inbound(&tag);
        }
        Ok(Vec::new())
    }

    fn list_inbounds(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let only_tags = request_varint(request, 1).unwrap_or(0) != 0;
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let mut out = Vec::new();
        for entry in &state.inbounds {
            let raw = if only_tags {
                inbound_config(&entry.tag, true)
            } else if let Some(raw) = &entry.raw {
                raw.clone()
            } else {
                inbound_config(&entry.tag, false)
            };
            field_bytes(&mut out, 1, &raw);
        }
        Ok(out)
    }

    fn list_outbounds(&self) -> Result<Vec<u8>, (u32, String)> {
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let mut out = Vec::new();
        for entry in &state.outbounds {
            field_bytes(&mut out, 1, &entry.raw);
        }
        Ok(out)
    }

    fn add_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let raw = request_bytes(request, 1)
            .ok_or_else(|| (3, "AddInbound carries no handler".to_owned()))?;
        let tag = crate::xray_pb::handler_tag(raw);
        let inbounds =
            crate::xray_pb::inbound(raw).map_err(|error| (3, format!("AddInbound: {error}")))?;
        let ports: Vec<String> = inbounds
            .iter()
            .filter_map(|inbound| inbound.get("port").and_then(crate::json::Json::as_port))
            .map(|port| port.to_string())
            .collect();
        let Some(crate::json::Json::Obj(mut pairs)) = inbounds.first().cloned() else {
            return Err((3, "AddInbound names no inbound".to_owned()));
        };
        if ports.is_empty() {
            return Err((3, "AddInbound names no inbound".to_owned()));
        }
        for (key, value) in &mut pairs {
            if key == "port" {
                *value = crate::json::Json::Str(ports.join(","));
            }
        }
        let runtime = Arc::clone(self.runtime()?);
        {
            let state = self
                .state
                .lock()
                .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
            if !tag.is_empty() && state.inbounds.iter().any(|entry| entry.tag == tag) {
                return Err((2, format!("existing tag found: {tag}")));
            }
        }
        let root = crate::json::Json::Obj(vec![(
            "inbounds".to_owned(),
            crate::json::Json::Arr(vec![crate::json::Json::Obj(pairs)]),
        )]);
        let seed = crate::xray_pb::Seed {
            inbounds: vec![(tag.clone(), raw.to_vec())],
            ..Default::default()
        };
        let served = crate::proxy::serve_dynamic_inbounds(&runtime, &root, &seed, self);
        if served == 0 {
            return Err((2, format!("inbound `{tag}` could not be served")));
        }
        Ok(Vec::new())
    }

    fn add_outbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let raw = request_bytes(request, 1)
            .ok_or_else(|| (3, "AddOutbound carries no handler".to_owned()))?;
        let tag = crate::xray_pb::handler_tag(raw);
        if !tag.is_empty() && self.routed() && tag == self.config.tag {
            return Err((2, format!("existing tag found: {tag}")));
        }
        let runtime = Arc::clone(self.runtime()?);
        let mut state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        if !tag.is_empty() && state.outbounds.iter().any(|entry| entry.tag == tag) {
            return Err((2, format!("existing tag found: {tag}")));
        }
        if !tag.is_empty() {
            runtime
                .add_outbound(&tag, raw)
                .map_err(|error| (2, error))?;
        }
        state.outbounds.push(Outbound {
            tag,
            raw: raw.to_vec(),
        });
        Ok(Vec::new())
    }

    fn remove_outbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        if tag.is_empty() {
            return Err((2, "empty handler tag".to_owned()));
        }
        let runtime = Arc::clone(self.runtime()?);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
            let Some(index) = state.outbounds.iter().position(|entry| entry.tag == tag) else {
                if self.routed() && tag == self.config.tag {
                    runtime.remove_outbound(&tag);
                }
                return Ok(Vec::new());
            };
            state.outbounds.remove(index);
        }
        runtime.remove_outbound(&tag);
        Ok(Vec::new())
    }

    fn alter_outbound(request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let operation = request_typed(request, 2)
            .ok_or_else(|| (3, "AlterOutbound carries no operation".to_owned()))?;
        match operation.0.as_str() {
            "xray.app.proxyman.command.AddUserOperation"
            | "xray.app.proxyman.command.RemoveUserOperation" => {
                Err((2, "not an outbound operation".to_owned()))
            }
            _ => Err((2, "unknown operation".to_owned())),
        }
    }

    fn alter_inbound(&self, request: &[u8]) -> Result<Vec<u8>, (u32, String)> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let tag = request_str(request, 1).unwrap_or_default();
        let operation = request_typed(request, 2)
            .ok_or_else(|| (3, "AlterInbound carries no operation".to_owned()))?;
        let add = match operation.0.as_str() {
            "xray.app.proxyman.command.AddUserOperation" => true,
            "xray.app.proxyman.command.RemoveUserOperation" => false,
            _ => return Err((2, "unknown operation".to_owned())),
        };
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let entry = state
            .inbounds
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or_else(|| (2, format!("inbound `{tag}` not found")))?;
        let users = entry.users.as_ref().ok_or_else(|| {
            (
                2,
                format!(
                    "inbound `{tag}` ({}) does not carry users here",
                    entry.protocol
                ),
            )
        })?;
        if add {
            let user = request_bytes(operation.1, 1)
                .ok_or_else(|| (3, "AddUserOperation carries no user".to_owned()))?;
            let account =
                request_typed(user, 3).ok_or_else(|| (3, "user carries no account".to_owned()))?;
            if account.0 != "xray.proxy.vmess.Account" {
                return Err((2, format!("account `{}` is not carried here", account.0)));
            }
            let id = request_str(account.1, 1)
                .and_then(|id| crate::config::uuid_bytes(&id))
                .ok_or_else(|| (3, "vmess account id is not a uuid".to_owned()))?;
            let email = request_str(user, 2).unwrap_or_default();
            let level = request_varint(user, 1).unwrap_or(0) as u32;
            let no_termination =
                request_str(account.1, 4).is_some_and(|text| text.contains("NoTerminationSignal"));
            if !users.add(vmess::User {
                level,
                email,
                id,
                no_termination,
            }) {
                return Err((2, "user already exists".to_owned()));
            }
            Ok(Vec::new())
        } else {
            let email = request_str(operation.1, 1).unwrap_or_default();
            if !users.remove_email(&email) {
                return Err((2, format!("user `{email}` not found")));
            }
            Ok(Vec::new())
        }
    }

    fn get_users(&self, request: &[u8], count: bool) -> Result<Vec<u8>, (u32, String)> {
        let tag = request_str(request, 1).unwrap_or_default();
        let state = self
            .state
            .lock()
            .map_err(|_| (13, "commander state is unavailable".to_owned()))?;
        let entry = state
            .inbounds
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or_else(|| (2, format!("inbound `{tag}` not found")))?;
        let Some(users) = entry.users.as_ref() else {
            return Err((
                2,
                format!("inbound `{tag}` ({}) is not a UserManager", entry.protocol),
            ));
        };
        let listed = users.list();
        if count {
            let mut out = Vec::new();
            field_varint(&mut out, 1, listed.len() as u64);
            return Ok(out);
        }
        let email = request_str(request, 2).unwrap_or_default();
        let mut out = Vec::new();
        for user in listed
            .iter()
            .filter(|user| email.is_empty() || user.email == email)
        {
            field_bytes(&mut out, 1, &vmess_user(user));
        }
        Ok(out)
    }
}

#[derive(Default)]
struct Call {
    path: String,
    headers: Vec<u8>,
    end_headers: bool,
    end_stream: bool,
    body: Vec<u8>,
}

impl Call {
    fn read_path(&mut self, decoder: &mut h2::Decoder) -> bool {
        let mut path = String::new();
        let block = std::mem::take(&mut self.headers);
        if decoder
            .decode(&block, &mut |name, value| {
                if name == b":path" {
                    path = String::from_utf8_lossy(value).into_owned();
                }
            })
            .is_none()
        {
            return false;
        }
        self.path = path;
        true
    }
}

/// The connection's own SETTINGS: the open-call cap and the frame ceiling, so a peer learns both before it dials a call.
fn settings() -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..2].copy_from_slice(&h2::S_MAX_CONCURRENT.to_be_bytes());
    out[2..6].copy_from_slice(&(API_CALLS as u32).to_be_bytes());
    out[6..8].copy_from_slice(&h2::S_MAX_FRAME.to_be_bytes());
    out[8..].copy_from_slice(&(WIRE_MAX as u32).to_be_bytes());
    out
}

const MAX_WINDOW: i64 = 0x7fff_ffff;

/// The part of a response still unsent because its stream or connection window had no room: the
/// frame loop keeps serving other streams and resumes this one on the next `WINDOW_UPDATE`.
struct Response {
    framed: Vec<u8>,
    at: usize,
    trailers: Vec<u8>,
}

/// The peer's send windows, from its `SETTINGS` and `WINDOW_UPDATE` frames: a response waits for room rather than overrunning the default 65,535.
struct Flow {
    connection: i64,
    initial: i64,
    streams: HashMap<u32, i64>,
    recv_connection: i64,
    recv_streams: HashMap<u32, i64>,
    ended: HashSet<u32>,
    opened: u32,
}

impl Flow {
    fn new() -> Self {
        Self {
            connection: 65_535,
            initial: 65_535,
            streams: HashMap::new(),
            recv_connection: 65_535,
            recv_streams: HashMap::new(),
            ended: HashSet::new(),
            opened: 0,
        }
    }

    fn open(&mut self, id: u32) -> bool {
        if id == 0 || id.is_multiple_of(2) {
            return false;
        }
        if id > self.opened {
            self.streams.entry(id).or_insert(self.initial);
            self.recv_streams.entry(id).or_insert(65_535);
            self.opened = id;
        }
        true
    }

    fn idle(&self, id: u32) -> bool {
        id != 0 && (id.is_multiple_of(2) || id > self.opened)
    }

    fn refuse(&mut self, id: u32) {
        self.opened = self.opened.max(id);
    }

    fn close(&mut self, id: u32) {
        self.streams.remove(&id);
        self.recv_streams.remove(&id);
        self.ended.remove(&id);
    }

    fn end_request(&mut self, id: u32) {
        self.ended.insert(id);
    }

    fn is_ended(&self, id: u32) -> bool {
        self.ended.contains(&id)
    }

    fn take_recv(&mut self, id: u32, bytes: usize) -> bool {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.recv_connection = self.recv_connection.saturating_sub(bytes);
        let stream = self.recv_streams.get_mut(&id).is_none_or(|window| {
            *window = window.saturating_sub(bytes);
            *window >= 0
        });
        self.recv_connection >= 0 && stream
    }

    fn give_recv(&mut self, id: u32, bytes: usize) {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.recv_connection = self.recv_connection.saturating_add(bytes);
        if let Some(window) = self.recv_streams.get_mut(&id) {
            *window = window.saturating_add(bytes);
        }
    }

    fn cancelled(&self, id: u32) -> bool {
        id != 0 && id <= self.opened && !self.streams.contains_key(&id)
    }

    fn window(&mut self, id: u32, increment: i64) -> bool {
        if increment == 0 {
            return false;
        }
        if id == 0 {
            let next = self.connection.saturating_add(increment);
            if next > MAX_WINDOW {
                return false;
            }
            self.connection = next;
            return true;
        }
        let Some(window) = self.streams.get_mut(&id) else {
            return true;
        };
        let next = window.saturating_add(increment);
        if next > MAX_WINDOW {
            return false;
        }
        *window = next;
        true
    }

    fn settings(&mut self, body: &[u8]) -> bool {
        if !body.len().is_multiple_of(6) {
            return false;
        }
        let mut at = 0usize;
        while at + 6 <= body.len() {
            let entry = &body[at..at + 6];
            at += 6;
            if u16::from_be_bytes([entry[0], entry[1]]) == h2::S_WINDOW {
                let value = i64::from(u32::from_be_bytes(entry[2..6].try_into().unwrap()));
                if value > MAX_WINDOW {
                    return false;
                }
                let change = value - self.initial;
                if self
                    .streams
                    .values()
                    .any(|window| window.saturating_add(change) > MAX_WINDOW)
                {
                    return false;
                }
                self.initial = value;
                for window in self.streams.values_mut() {
                    *window = window.saturating_add(change);
                }
            }
        }
        true
    }

    fn available(&self, id: u32) -> i64 {
        self.connection
            .min(self.streams.get(&id).copied().unwrap_or(0))
    }
}

fn flush_responses(
    stream: &mut Connection,
    flow: &mut Flow,
    responses: &mut HashMap<u32, Response>,
) -> bool {
    for id in responses.keys().copied().collect::<Vec<_>>() {
        if !flush_response(stream, id, flow, responses) {
            return false;
        }
    }
    true
}

fn flush_response(
    stream: &mut Connection,
    id: u32,
    flow: &mut Flow,
    responses: &mut HashMap<u32, Response>,
) -> bool {
    let Some(response) = responses.get_mut(&id) else {
        return true;
    };
    while response.at < response.framed.len() {
        let room = flow.available(id);
        if room <= 0 {
            return true;
        }
        let remaining = i64::try_from(response.framed.len() - response.at).unwrap_or(i64::MAX);
        let take = usize::try_from(
            room.min(remaining)
                .min(i64::try_from(H2_MAX_FRAME).unwrap_or(i64::MAX)),
        )
        .unwrap_or(0);
        if take == 0 {
            return true;
        }
        if !h2::write_frame(
            stream,
            h2::T_DATA,
            0,
            id,
            &response.framed[response.at..response.at + take],
        ) {
            return false;
        }
        response.at += take;
        let taken = i64::try_from(take).unwrap_or(i64::MAX);
        flow.connection -= taken;
        if let Some(window) = flow.streams.get_mut(&id) {
            *window -= taken;
        }
    }
    if !h2::write_frame(
        stream,
        h2::T_HEADERS,
        h2::F_END_HEADERS | h2::F_END,
        id,
        &response.trailers,
    ) {
        return false;
    }
    flow.close(id);
    responses.remove(&id);
    true
}

fn reset(stream: &mut Connection, id: u32, code: u32) -> bool {
    h2::write_frame(stream, h2::T_RST, 0, id, &code.to_be_bytes())
}

/// Refuse a peer that exceeded a bound: the GOAWAY names the reason before the connection closes.
fn goaway(stream: &mut Connection, code: u32, last: u32) {
    let mut frame = [0u8; 8];
    frame[..4].copy_from_slice(&last.to_be_bytes());
    frame[4..].copy_from_slice(&code.to_be_bytes());
    let _ = h2::write_frame(stream, h2::T_GOAWAY, 0, 0, &frame);
}

fn window_update(stream: &mut Connection, id: u32, increment: usize) -> bool {
    increment == 0
        || h2::write_frame(
            stream,
            h2::T_WINDOW,
            0,
            id,
            &(increment as u32).to_be_bytes(),
        )
}

/// Feeds a header block the call map will not answer into the connection's HPACK decoder, so an
/// indexed field on a later stream still resolves: a closed stream still carries compression state.
fn absorb_headers(
    decoder: &mut h2::Decoder,
    discard: &mut Option<(u32, Vec<u8>)>,
    id: u32,
    block: &[u8],
    end: bool,
    trailers: bool,
) -> Result<bool, u32> {
    let mut invalid = false;
    if end && discard.is_none() {
        if block.len() > h2::HEAD_CAP {
            return Err(h2::E_PROTOCOL);
        }
        decoder
            .decode(block, &mut |name, value| {
                invalid |= trailers && !trailer_field(name, value);
            })
            .ok_or(h2::E_COMPRESSION)?;
        return Ok(invalid);
    }
    let (held_id, mut held) = discard.take().unwrap_or_else(|| (id, Vec::new()));
    if held_id != id || held.len() + block.len() > h2::HEAD_CAP {
        return Err(h2::E_PROTOCOL);
    }
    held.extend_from_slice(block);
    if end {
        decoder
            .decode(&held, &mut |name, value| {
                invalid |= trailers && !trailer_field(name, value);
            })
            .ok_or(h2::E_COMPRESSION)?;
    } else {
        *discard = Some((id, held));
    }
    Ok(invalid)
}

fn trailer_field(name: &[u8], value: &[u8]) -> bool {
    let token = |byte: &u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    };
    !name.is_empty()
        && name.iter().all(token)
        && !matches!(
            name,
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade"
        )
        && (name != b"te" || value.eq_ignore_ascii_case(b"trailers"))
        && !value
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        && !value
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        && !value
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
}

fn data_body(body: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & h2::F_PADDED == 0 {
        return Some(body);
    }
    let (&pad, rest) = body.split_first()?;
    let pad = usize::from(pad);
    (pad <= rest.len()).then(|| &rest[..rest.len() - pad])
}

fn header_body(body: &[u8], flags: u8) -> Option<&[u8]> {
    let mut rest = body;
    if flags & h2::F_PADDED != 0 {
        let (&pad, tail) = rest.split_first()?;
        rest = tail.get(..tail.len().checked_sub(usize::from(pad))?)?;
    }
    if flags & h2::F_PRIORITY != 0 {
        rest = rest.get(5..)?;
    }
    Some(rest)
}

fn grpc_message(body: &[u8]) -> Option<&[u8]> {
    let header = body.get(..5)?;
    if header[0] != 0 {
        return None;
    }
    let len = u32::from_be_bytes(header[1..5].try_into().ok()?) as usize;
    (body.len() == 5 + len).then(|| &body[5..])
}

fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{byte:02X}"));
        }
    }
    out
}

/// The handler config this tree can synthesize for a JSON inbound: its tag, and nothing else.
fn inbound_config(tag: &str, _only_tags: bool) -> Vec<u8> {
    let mut out = Vec::new();
    field_str(&mut out, 1, tag);
    out
}

/// One `xray.core.app.observatory.OutboundStatus`: the reading a balancer already picked from.
fn outbound_status(observed: &crate::router::Observed) -> Vec<u8> {
    let mut out = Vec::new();
    if observed.alive {
        field_varint(&mut out, 1, 1);
    }
    if observed.delay_ms != 0 {
        field_varint(&mut out, 2, observed.delay_ms as u64);
    }
    if !observed.last_error.is_empty() {
        field_str(&mut out, 3, &observed.last_error);
    }
    if !observed.tag.is_empty() {
        field_str(&mut out, 4, &observed.tag);
    }
    if observed.last_seen != 0 {
        field_varint(&mut out, 5, observed.last_seen as u64);
    }
    if observed.last_try != 0 {
        field_varint(&mut out, 6, observed.last_try as u64);
    }
    if let Some(health) = observed.health {
        let mut ping = Vec::new();
        for (field, value) in [
            (1, health.all),
            (2, health.fail),
            (3, health.deviation),
            (4, health.average),
        ] {
            if value != 0 {
                field_varint(&mut ping, field, value as u64);
            }
        }
        field_bytes(&mut out, 7, &ping);
    }
    out
}

/// One `xray.app.stats.command.Stat`: the name the counter registered and its total.
fn stat(name: &str, value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    field_str(&mut out, 1, name);
    field_varint(&mut out, 2, value as u64);
    out
}

fn vmess_user(user: &vmess::User) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(&mut out, 1, u64::from(user.level));
    field_str(&mut out, 2, &user.email);
    let mut account = Vec::new();
    field_str(&mut account, 1, &uuid_string(user.id));
    let mut typed = Vec::new();
    field_str(&mut typed, 1, "xray.proxy.vmess.Account");
    field_bytes(&mut typed, 2, &account);
    field_bytes(&mut out, 3, &typed);
    out
}

fn uuid_string(id: [u8; 16]) -> String {
    let mut hex = String::with_capacity(32);
    for byte in id {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---- RoutingService ----

/// The most source x local x target address choices a `TestRoute` context may name.
const MAX_TESTED_FLOWS: usize = 1024;

/// One `TestRoute` context as it arrived. The bytes are kept as they came so the answer echoes
/// exactly what the request carried, and the flows a rule table reads are built from them.
#[derive(Default)]
struct RoutingContext {
    inbound: Option<Vec<u8>>,
    network: u64,
    source_ips: Vec<Vec<u8>>,
    target_ips: Vec<Vec<u8>>,
    source_port: u64,
    target_port: u64,
    domain: Option<Vec<u8>>,
    protocol: Option<Vec<u8>>,
    user: Option<Vec<u8>>,
    attrs: Vec<(Vec<u8>, Vec<u8>)>,
    local_ips: Vec<Vec<u8>>,
    local_port: u64,
    vless_route: u64,
}

impl RoutingContext {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut context = Self::default();
        let mut reader = Pb::new(bytes);
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, Value::Bytes(raw)) => context.inbound = Some(raw.to_vec()),
                (2, Value::Varint(network)) => context.network = network,
                (3, Value::Bytes(raw)) => context.source_ips.push(raw.to_vec()),
                (4, Value::Bytes(raw)) => context.target_ips.push(raw.to_vec()),
                (5, Value::Varint(port)) => context.source_port = port,
                (6, Value::Varint(port)) => context.target_port = port,
                (7, Value::Bytes(raw)) => context.domain = Some(raw.to_vec()),
                (8, Value::Bytes(raw)) => context.protocol = Some(raw.to_vec()),
                (9, Value::Bytes(raw)) => context.user = Some(raw.to_vec()),
                (10, Value::Bytes(entry)) => context.attrs.push((
                    request_bytes(entry, 1).unwrap_or_default().to_vec(),
                    request_bytes(entry, 2).unwrap_or_default().to_vec(),
                )),
                (13, Value::Bytes(raw)) => context.local_ips.push(raw.to_vec()),
                (14, Value::Varint(port)) => context.local_port = port,
                (15, Value::Varint(route)) => context.vless_route = route,
                _ => {}
            }
        }
        Ok(context)
    }

    /// The context the table reads: xray reads each address list as any-of, so every choice of
    /// source, target and local address is kept as a list and the earliest matching rule decides.
    /// A port is kept apart from its address, so a context naming one without the other still routes.
    fn probe<'a>(
        &'a self,
        attrs: Option<&'a crate::router::Attributes<'a>>,
    ) -> Result<crate::router::Probe<'a>, String> {
        let text =
            |raw: &'a Option<Vec<u8>>| raw.as_deref().and_then(|raw| std::str::from_utf8(raw).ok());
        let addresses = |raw: &[Vec<u8>]| {
            let mut out: Vec<Option<std::net::IpAddr>> =
                raw.iter().filter_map(|bytes| ip(bytes)).map(Some).collect();
            if out.is_empty() {
                out.push(None);
            }
            out
        };
        let targets = addresses(&self.target_ips);
        let sources = addresses(&self.source_ips);
        let locals = addresses(&self.local_ips);
        let combinations = sources
            .len()
            .checked_mul(locals.len())
            .and_then(|count| count.checked_mul(targets.len()));
        if combinations.is_none_or(|count| count > MAX_TESTED_FLOWS) {
            return Err(format!(
                "a tested context names more than {MAX_TESTED_FLOWS} address combinations"
            ));
        }
        Ok(crate::router::Probe {
            network: match self.network {
                2 => crate::router::Network::Tcp,
                3 => crate::router::Network::Udp,
                raw => crate::router::Network::Other(raw as u8),
            },
            domain: text(&self.domain),
            port: Some(self.target_port as u16),
            inbound_tag: text(&self.inbound),
            protocol: text(&self.protocol),
            user: text(&self.user),
            attrs,
            targets,
            sources,
            source_port: self.source_port as u16,
            locals,
            local_port: self.local_port as u16,
            vless_route: self.vless_route as u16,
        })
    }

    /// The answer, echoing the fields the request's selectors name plus the picked outbound. The
    /// reference's selectors are prefixes of the field names, and none of them names an address a
    /// flow's outbound group would carry, so that field is always absent.
    fn answered(&self, selectors: &[String], outbound: &str) -> Vec<u8> {
        let wanted = |name: &str| {
            selectors.is_empty()
                || selectors
                    .iter()
                    .any(|selector| name.starts_with(selector.as_str()))
        };
        let mut out = Vec::new();
        if wanted("inbound") {
            if let Some(inbound) = self.inbound.as_deref().filter(|raw| !raw.is_empty()) {
                field_bytes(&mut out, 1, inbound);
            }
        }
        if wanted("network") && self.network != 0 {
            field_varint(&mut out, 2, self.network);
        }
        if wanted("ip_source") {
            for ip in &self.source_ips {
                field_bytes(&mut out, 3, ip);
            }
        }
        if wanted("ip_target") {
            for ip in &self.target_ips {
                field_bytes(&mut out, 4, ip);
            }
        }
        if wanted("port_source") && self.source_port != 0 {
            field_varint(&mut out, 5, self.source_port);
        }
        if wanted("port_target") && self.target_port != 0 {
            field_varint(&mut out, 6, self.target_port);
        }
        if wanted("domain") {
            if let Some(domain) = self.domain.as_deref().filter(|raw| !raw.is_empty()) {
                field_bytes(&mut out, 7, domain);
            }
        }
        if wanted("protocol") {
            if let Some(protocol) = self.protocol.as_deref().filter(|raw| !raw.is_empty()) {
                field_bytes(&mut out, 8, protocol);
            }
        }
        if wanted("user") {
            if let Some(user) = self.user.as_deref().filter(|raw| !raw.is_empty()) {
                field_bytes(&mut out, 9, user);
            }
        }
        if wanted("attributes") {
            for (name, value) in &self.attrs {
                let mut entry = Vec::new();
                if !name.is_empty() {
                    field_bytes(&mut entry, 1, name);
                }
                if !value.is_empty() {
                    field_bytes(&mut entry, 2, value);
                }
                field_bytes(&mut out, 10, &entry);
            }
        }
        if wanted("outbound") && !outbound.is_empty() {
            field_str(&mut out, 12, outbound);
        }
        if wanted("ip_local") {
            for ip in &self.local_ips {
                field_bytes(&mut out, 13, ip);
            }
        }
        if wanted("port_local") && self.local_port != 0 {
            field_varint(&mut out, 14, self.local_port);
        }
        out
    }
}

fn ip(raw: &[u8]) -> Option<std::net::IpAddr> {
    match raw.len() {
        4 => <[u8; 4]>::try_from(raw).ok().map(std::net::IpAddr::from),
        16 => <[u8; 16]>::try_from(raw).ok().map(std::net::IpAddr::from),
        _ => None,
    }
}

fn request_strs(bytes: &[u8], field: u64) -> Vec<String> {
    let mut out = Vec::new();
    let mut reader = Pb::new(bytes);
    while let Ok(Some((number, value))) = reader.next() {
        if number == field {
            if let Value::Bytes(raw) = value {
                if let Ok(text) = std::str::from_utf8(raw) {
                    out.push(text.to_owned());
                }
            }
        }
    }
    out
}

// ---- protobuf wire ----

#[derive(Debug)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct Pb<'a> {
    rest: &'a [u8],
}

impl<'a> Pb<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, String> {
        loop {
            if self.rest.is_empty() {
                return Ok(None);
            }
            let (key, rest) =
                varint(self.rest).ok_or_else(|| "protobuf: truncated key".to_owned())?;
            self.rest = rest;
            let field = key >> 3;
            let wire = (key & 7) as u8;
            match wire {
                0 => {
                    let (value, rest) =
                        varint(self.rest).ok_or_else(|| "protobuf: truncated varint".to_owned())?;
                    self.rest = rest;
                    return Ok(Some((field, Value::Varint(value))));
                }
                2 => {
                    let (len, rest) =
                        varint(self.rest).ok_or_else(|| "protobuf: truncated length".to_owned())?;
                    let len = usize::try_from(len)
                        .map_err(|_| "protobuf: length overflows".to_owned())?;
                    let (body, rest) = rest
                        .split_at_checked(len)
                        .ok_or_else(|| "protobuf: truncated body".to_owned())?;
                    self.rest = rest;
                    return Ok(Some((field, Value::Bytes(body))));
                }
                1 => {
                    let (_, rest) = self
                        .rest
                        .split_at_checked(8)
                        .ok_or_else(|| "protobuf: truncated fixed64".to_owned())?;
                    self.rest = rest;
                }
                5 => {
                    let (_, rest) = self
                        .rest
                        .split_at_checked(4)
                        .ok_or_else(|| "protobuf: truncated fixed32".to_owned())?;
                    self.rest = rest;
                }
                other => return Err(format!("protobuf: wire type {other}")),
            }
        }
    }
}

fn varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[index + 1..]));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    put_varint(out, field << 3);
    put_varint(out, value);
}

fn field_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, field << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn field_str(out: &mut Vec<u8>, field: u64, text: &str) {
    field_bytes(out, field, text.as_bytes());
}

fn request_varint(bytes: &[u8], field: u64) -> Option<u64> {
    let mut reader = Pb::new(bytes);
    while let Ok(Some((number, value))) = reader.next() {
        if number == field {
            if let Value::Varint(value) = value {
                return Some(value);
            }
        }
    }
    None
}

fn request_bytes(bytes: &[u8], field: u64) -> Option<&[u8]> {
    let mut reader = Pb::new(bytes);
    while let Ok(Some((number, value))) = reader.next() {
        if number == field {
            if let Value::Bytes(value) = value {
                return Some(value);
            }
        }
    }
    None
}

fn request_str(bytes: &[u8], field: u64) -> Option<String> {
    request_bytes(bytes, field).and_then(|raw| std::str::from_utf8(raw).ok().map(str::to_owned))
}

#[cfg(test)]
fn all_bytes(bytes: &[u8], field: u64) -> impl Iterator<Item = &[u8]> {
    let mut reader = Pb::new(bytes);
    std::iter::from_fn(move || loop {
        match reader.next() {
            Ok(Some((number, Value::Bytes(raw)))) if number == field => return Some(raw),
            Ok(Some(_)) => {}
            _ => return None,
        }
    })
}

fn request_typed(bytes: &[u8], field: u64) -> Option<(String, &[u8])> {
    typed(request_bytes(bytes, field)?).ok()
}

fn typed(bytes: &[u8]) -> Result<(String, &[u8]), String> {
    let name = request_str(bytes, 1).ok_or_else(|| "typed message has no name".to_owned())?;
    let value = request_bytes(bytes, 2).unwrap_or(&[]);
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    fn request(path: &str, message: &[u8]) -> Vec<u8> {
        let mut out = h2::MAGIC.to_vec();
        out.extend_from_slice(&h2::frame_head(0, h2::T_SETTINGS, 0, 0));
        let headers = h2::block_encode(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        out.extend_from_slice(&h2::frame_head(
            headers.len(),
            h2::T_HEADERS,
            h2::F_END_HEADERS,
            1,
        ));
        out.extend_from_slice(&headers);
        let mut body = vec![0];
        body.extend_from_slice(&(message.len() as u32).to_be_bytes());
        body.extend_from_slice(message);
        out.extend_from_slice(&h2::frame_head(body.len(), h2::T_DATA, h2::F_END, 1));
        out.extend_from_slice(&body);
        out
    }

    fn reply(mut stream: Connection, id: u32) -> (Vec<u8>, Vec<(String, String)>) {
        let mut decoder = h2::Decoder::default();
        let mut raw = Vec::new();
        let mut trailers = Vec::new();
        while let Some((len, kind, flags, stream_id)) = h2::read_head(&mut stream) {
            let mut body = vec![0u8; len];
            if stream.read_exact(&mut body).is_err() {
                break;
            }
            match kind {
                h2::T_DATA if stream_id == id => raw.extend_from_slice(&body),
                h2::T_HEADERS if stream_id == id && flags & h2::F_END != 0 => {
                    decoder.decode(&body, &mut |name, value| {
                        trailers.push((
                            String::from_utf8_lossy(name).into_owned(),
                            String::from_utf8_lossy(value).into_owned(),
                        ));
                    });
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(raw.first(), Some(&0), "gRPC compression flag");
        let n = u32::from_be_bytes(
            raw.get(1..5)
                .expect("gRPC length")
                .try_into()
                .expect("four bytes"),
        ) as usize;
        assert_eq!(raw.len(), 5 + n, "one gRPC envelope and no trailing bytes");
        (raw[5..].to_vec(), trailers)
    }

    fn zero_sized_api_connection(preface: bool) -> bool {
        let api = Api::new(ApiConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let (done, waited) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            api.serve_stream_with_idle(Connection::from(stream), Duration::from_millis(50));
            done.send(()).expect("reports");
        });
        let mut idle = Connection::connect(address).expect("connects");
        if preface {
            idle.write_all(h2::MAGIC).expect("writes the preface");
        }
        waited.recv_timeout(Duration::from_secs(2)).is_ok()
    }

    #[test]
    fn an_idle_api_connection_before_the_preface_returns_its_worker() {
        assert!(
            zero_sized_api_connection(false),
            "an idle connection outlived its bound"
        );
    }

    #[test]
    fn an_idle_api_connection_after_the_preface_returns_its_worker() {
        assert!(
            zero_sized_api_connection(true),
            "a preface-only connection outlived its bound"
        );
    }

    fn api_connection(idle: Duration) -> (Connection, std::sync::mpsc::Receiver<()>) {
        let api = Api::new(ApiConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let (done, waited) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            api.serve_stream_with_idle(Connection::from(stream), idle);
            done.send(()).expect("reports");
        });
        let mut client = Connection::connect(address).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        client.write_all(h2::MAGIC).expect("writes the preface");
        (client, waited)
    }

    fn handler_connection(idle: Duration) -> (Connection, std::sync::mpsc::Receiver<()>) {
        let api = Api::new(ApiConfig {
            handler: true,
            ..ApiConfig::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let (done, waited) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            api.serve_stream_with_idle(Connection::from(stream), idle);
            done.send(()).expect("reports");
        });
        let mut client = Connection::connect(address).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        client.write_all(h2::MAGIC).expect("writes the preface");
        (client, waited)
    }

    fn call_headers(client: &mut Connection, id: u32, path: &str) {
        let block = h2::block_encode(&[(":path", path)]);
        client
            .write_all(&h2::frame_head(
                block.len(),
                h2::T_HEADERS,
                h2::F_END_HEADERS,
                id,
            ))
            .expect("writes the call head");
        client.write_all(&block).expect("writes the block");
    }

    fn send_trailers(client: &mut Connection, id: u32, block: &[u8], split: bool) {
        let envelope = [0u8; 5];
        client
            .write_all(&h2::frame_head(envelope.len(), h2::T_DATA, 0, id))
            .expect("writes the request envelope head");
        client
            .write_all(&envelope)
            .expect("writes the request envelope");
        if split {
            let (head, tail) = block.split_at(1);
            client
                .write_all(&h2::frame_head(head.len(), h2::T_HEADERS, h2::F_END, id))
                .expect("writes the trailer head");
            client.write_all(head).expect("writes the trailer prefix");
            client
                .write_all(&h2::frame_head(
                    tail.len(),
                    h2::T_CONT,
                    h2::F_END_HEADERS,
                    id,
                ))
                .expect("writes the continuation head");
            client.write_all(tail).expect("writes the continuation");
        } else {
            client
                .write_all(&h2::frame_head(
                    block.len(),
                    h2::T_HEADERS,
                    h2::F_END_HEADERS | h2::F_END,
                    id,
                ))
                .expect("writes the trailer head");
            client.write_all(block).expect("writes the trailer");
        }
    }

    fn send_body(client: &mut Connection, id: u32, body: &[u8]) {
        for chunk in body.chunks(65_535) {
            client
                .write_all(&h2::frame_head(chunk.len(), h2::T_DATA, 0, id))
                .expect("writes the body head");
            client.write_all(chunk).expect("writes the body");
            for want in [0, id] {
                let (len, kind, _, frame) = h2::read_head(client).expect("window update");
                let mut payload = vec![0u8; len];
                client.read_exact(&mut payload).expect("window body");
                assert_eq!((kind, frame), (h2::T_WINDOW, want));
            }
        }
    }

    fn rst_code(client: &mut Connection) -> u32 {
        loop {
            let (len, kind, _, _) = h2::read_head(client).expect("rst");
            let mut body = vec![0u8; len];
            client.read_exact(&mut body).expect("frame body");
            if kind == h2::T_WINDOW {
                continue;
            }
            assert_eq!(kind, h2::T_RST);
            return u32::from_be_bytes(body[..4].try_into().expect("code"));
        }
    }

    type HeaderCapConnection = (
        Connection,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Receiver<()>,
    );

    fn api_connection_watching_header_cap(idle: Duration) -> HeaderCapConnection {
        let api = Api::new(ApiConfig::default());
        let (cap, cap_reached) = std::sync::mpsc::channel();
        api.watch_header_cap(cap);
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let (done, waited) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            api.serve_stream_with_idle(Connection::from(stream), idle);
            done.send(()).expect("reports");
        });
        let mut client = Connection::connect(address).expect("connects");
        client.write_all(h2::MAGIC).expect("writes the preface");
        (client, waited, cap_reached)
    }

    fn served_settings(client: &mut Connection) -> Vec<u8> {
        let (len, kind, flags, _) = h2::read_head(client).expect("settings");
        assert_eq!((kind, flags), (h2::T_SETTINGS, 0));
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).expect("settings body");
        body
    }

    fn goaway_code(client: &mut Connection) -> u32 {
        loop {
            let (len, kind, _, _) = h2::read_head(client).expect("goaway");
            let mut body = vec![0u8; len];
            client.read_exact(&mut body).expect("frame body");
            if kind == h2::T_WINDOW {
                continue;
            }
            assert_eq!(kind, h2::T_GOAWAY);
            return u32::from_be_bytes(body[4..8].try_into().expect("code"));
        }
    }

    fn call_head(client: &mut Connection, id: u32) {
        let block = h2::block_encode(&[(":path", "/HandlerService/List")]);
        client
            .write_all(&h2::frame_head(
                block.len(),
                h2::T_HEADERS,
                h2::F_END_HEADERS,
                id,
            ))
            .expect("writes the call head");
        client.write_all(&block).expect("writes the block");
    }

    /// The cap a peer is held to is the one it was told: the setting the connection opens with is the
    /// number of open calls the same connection is allowed.
    #[test]
    fn the_api_advertises_the_open_call_cap_it_enforces() {
        let (mut client, waited) = api_connection(Duration::from_millis(200));
        let mut expected = h2::S_MAX_CONCURRENT.to_be_bytes().to_vec();
        expected.extend_from_slice(&(API_CALLS as u32).to_be_bytes());
        expected.extend_from_slice(&h2::S_MAX_FRAME.to_be_bytes());
        expected.extend_from_slice(&(WIRE_MAX as u32).to_be_bytes());
        assert_eq!(served_settings(&mut client), expected);
        drop(client);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    /// A frame head alone is refused: the body is never read, so a 17 MiB DATA frame pins nothing.
    #[test]
    fn a_frame_longer_than_the_message_cap_is_refused_before_its_body_is_read() {
        let (mut client, waited) = api_connection(Duration::from_millis(200));
        served_settings(&mut client);
        client
            .write_all(&h2::frame_head(
                CALL_MAX + CALL_ENVELOPE + 1,
                h2::T_DATA,
                0,
                1,
            ))
            .expect("writes the head");
        assert_eq!(goaway_code(&mut client), h2::E_FRAME_SIZE);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn more_open_calls_than_the_advertised_cap_are_refused() {
        let (mut client, waited) = handler_connection(Duration::from_millis(500));
        served_settings(&mut client);
        for call in 0..API_CALLS {
            call_headers(
                &mut client,
                1 + 2 * call as u32,
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
            );
        }
        call_headers(
            &mut client,
            1 + 2 * API_CALLS as u32,
            "/xray.app.proxyman.command.HandlerService/ListInbounds",
        );
        assert_eq!(rst_code(&mut client), h2::E_REFUSED);
        let envelope = [0u8; 5];
        client
            .write_all(&h2::frame_head(envelope.len(), h2::T_DATA, h2::F_END, 1))
            .expect("writes the accepted call's body");
        client
            .write_all(&envelope)
            .expect("writes the accepted call's envelope");
        let (_, trailers) = reply(client, 1);
        assert!(trailers
            .iter()
            .any(|(name, value)| name == "grpc-status" && value == "0"));
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_header_block_past_the_cap_is_refused() {
        let (mut client, waited, cap_reached) =
            api_connection_watching_header_cap(Duration::from_millis(500));
        served_settings(&mut client);
        let block = vec![0u8; h2::HEAD_CAP];
        for (index, chunk) in block.chunks(16 * 1024).enumerate() {
            let kind = if index == 0 {
                h2::T_HEADERS
            } else {
                h2::T_CONT
            };
            client
                .write_all(&h2::frame_head(chunk.len(), kind, 0, 1))
                .expect("writes the frame head");
            client.write_all(chunk).expect("writes the frame bytes");
        }
        cap_reached
            .recv_timeout(Duration::from_secs(2))
            .expect("accepts the exact-cap block");
        client
            .write_all(&h2::frame_head(1, h2::T_CONT, 0, 1))
            .expect("writes the continuation head");
        client
            .write_all(&[0u8])
            .expect("writes the byte that crosses the cap");
        assert_eq!(goaway_code(&mut client), h2::E_PROTOCOL);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_consumed_data_frame_restores_both_receive_windows() {
        let (mut client, waited) = api_connection(Duration::from_millis(500));
        served_settings(&mut client);
        call_head(&mut client, 1);
        let body = vec![0u8; 1024];
        client
            .write_all(&h2::frame_head(body.len(), h2::T_DATA, 0, 1))
            .expect("writes a body frame");
        client.write_all(&body).expect("writes its bytes");
        for want in [0, 1] {
            let (len, kind, _, id) = h2::read_head(&mut client).expect("window update");
            let mut payload = vec![0u8; len];
            client.read_exact(&mut payload).expect("window body");
            assert_eq!((kind, id), (h2::T_WINDOW, want));
            assert_eq!(
                u32::from_be_bytes(payload.try_into().expect("increment")),
                body.len() as u32
            );
        }
        drop(client);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_data_frame_past_receive_credit_is_refused() {
        let (mut client, waited) = api_connection(Duration::from_millis(500));
        served_settings(&mut client);
        call_head(&mut client, 1);
        let body = vec![0u8; 65_536];
        client
            .write_all(&h2::frame_head(body.len(), h2::T_DATA, 0, 1))
            .expect("writes the body head");
        client.write_all(&body).expect("writes the body");
        assert_eq!(goaway_code(&mut client), h2::E_FLOW);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn trailers_complete_a_call_in_one_block_or_a_continuation() {
        for split in [false, true] {
            let (mut client, waited) = handler_connection(Duration::from_millis(500));
            served_settings(&mut client);
            call_headers(
                &mut client,
                1,
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
            );
            let block = h2::block_encode(&[("x-check", "ok")]);
            send_trailers(&mut client, 1, &block, split);
            let (_, trailers) = reply(client, 1);
            assert!(trailers
                .iter()
                .any(|(name, value)| name == "grpc-status" && value == "0"));
            assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
        }
    }

    #[test]
    fn a_trailer_field_with_nul_resets_and_leaves_the_connection_usable() {
        for split in [false, true] {
            let (mut client, waited) = handler_connection(Duration::from_millis(500));
            served_settings(&mut client);
            call_headers(
                &mut client,
                1,
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
            );
            let invalid = h2::block_encode(&[("x-check", "bad\0value")]);
            send_trailers(&mut client, 1, &invalid, split);
            assert_eq!(rst_code(&mut client), h2::E_PROTOCOL);
            call_headers(
                &mut client,
                3,
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
            );
            let block = h2::block_encode(&[("x-check", "ok")]);
            send_trailers(&mut client, 3, &block, false);
            let (_, trailers) = reply(client, 3);
            assert!(trailers
                .iter()
                .any(|(name, value)| name == "grpc-status" && value == "0"));
            assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
        }
    }

    #[test]
    fn a_call_body_past_the_message_cap_is_refused() {
        let (mut client, waited) = api_connection(Duration::from_millis(500));
        served_settings(&mut client);
        call_head(&mut client, 1);
        let chunk = vec![0u8; 16 * 1024];
        for _ in 0..CALL_MAX / chunk.len() {
            client
                .write_all(&h2::frame_head(chunk.len(), h2::T_DATA, 0, 1))
                .expect("writes a body frame");
            client.write_all(&chunk).expect("writes its bytes");
        }
        let overrun = [0u8; CALL_ENVELOPE + 1];
        client
            .write_all(&h2::frame_head(overrun.len(), h2::T_DATA, 0, 1))
            .expect("writes the body that overruns");
        client.write_all(&overrun).expect("writes its bytes");
        assert_eq!(goaway_code(&mut client), h2::E_REFUSED);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    /// A reset stream is gone: its entry must not hold one of the advertised open-call slots.
    #[test]
    fn a_reset_call_releases_its_open_call_slot() {
        let (mut client, waited) = api_connection(Duration::from_millis(500));
        served_settings(&mut client);
        for call in 0..API_CALLS {
            let id = 1 + 2 * call as u32;
            call_head(&mut client, id);
            client
                .write_all(&h2::frame_head(4, h2::T_RST, 0, id))
                .expect("writes the reset head");
            client
                .write_all(&[0, 0, 0, 0])
                .expect("writes the reset code");
        }
        call_head(&mut client, 1 + 2 * API_CALLS as u32);
        client
            .write_all(&h2::frame_head(8, h2::T_PING, 0, 0))
            .expect("writes the ping");
        client.write_all(b"12345678").expect("writes the ping body");
        let (len, kind, flags, _) = h2::read_head(&mut client).expect("reads the ack");
        assert_eq!((len, kind, flags), (8, h2::T_PING, h2::F_ACK));
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).expect("reads the ping body");
        assert_eq!(body, b"12345678");
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    /// The product of the two caps is not the budget: without a shared bound, a hundred open calls
    /// near the message cap would pin four hundred megabytes on one admitted connection.
    #[test]
    fn open_calls_share_one_body_budget() {
        let (mut client, waited) = api_connection(Duration::from_millis(500));
        served_settings(&mut client);
        call_head(&mut client, 1);
        call_head(&mut client, 3);
        let chunk = vec![0u8; CALL_MAX + CALL_ENVELOPE];
        for id in [1, 3] {
            send_body(&mut client, id, &chunk);
        }
        client
            .write_all(&h2::frame_head(1, h2::T_DATA, 0, 1))
            .expect("writes the byte past the budget");
        client.write_all(&[0]).expect("writes the byte");
        assert_eq!(goaway_code(&mut client), h2::E_REFUSED);
        assert!(waited.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn the_handler_service_lists_the_config_it_was_seeded_with() {
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        let inbound = vec![0x0a, 0x01, b'd'];
        api.register_inbound(
            "d",
            Some(inbound.clone()),
            "dokodemo-door",
            None,
            Vec::new(),
        );
        api.seed_outbounds(&[("default-outbound".to_owned(), vec![0x0a, 0x02, b'o', b'k'])]);

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let served = std::sync::Arc::clone(&api);
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            served.serve_stream(Connection::from(stream));
        });

        let mut client = Connection::connect(address).expect("connects");
        client
            .write_all(&request(
                "/xray.app.proxyman.command.HandlerService/ListInbounds",
                &[],
            ))
            .expect("writes");
        let (message, trailers) = reply(client, 1);
        assert!(trailers
            .iter()
            .any(|(name, value)| name == "grpc-status" && value == "0"));
        assert_eq!(request_bytes(&message, 1), Some(inbound.as_slice()));
    }

    #[test]
    fn a_user_added_by_alter_inbound_authenticates_the_next_session() {
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        let first = [0x11u8; 16];
        let second = [0x22u8; 16];
        let users = vmess::Users::single(first);
        api.register_inbound(
            "v",
            None,
            "vmess",
            Some(std::sync::Arc::clone(&users)),
            Vec::new(),
        );
        let mut user = Vec::new();
        field_str(&mut user, 2, "test@example.com");
        let mut account = Vec::new();
        field_str(&mut account, 1, &uuid_string(second));
        let mut typed_account = Vec::new();
        field_str(&mut typed_account, 1, "xray.proxy.vmess.Account");
        field_bytes(&mut typed_account, 2, &account);
        field_bytes(&mut user, 3, &typed_account);
        let mut operation = Vec::new();
        field_bytes(&mut operation, 1, &user);
        let mut add = Vec::new();
        field_str(&mut add, 1, "v");
        let mut typed_operation = Vec::new();
        field_str(
            &mut typed_operation,
            1,
            "xray.app.proxyman.command.AddUserOperation",
        );
        field_bytes(&mut typed_operation, 2, &operation);
        field_bytes(&mut add, 2, &typed_operation);
        assert!(api.alter_inbound(&add).is_ok());
        assert!(users.list().iter().any(|user| user.id == second));
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "v");
        let mut operation = Vec::new();
        field_str(&mut operation, 1, "test@example.com");
        let mut typed_operation = Vec::new();
        field_str(
            &mut typed_operation,
            1,
            "xray.app.proxyman.command.RemoveUserOperation",
        );
        field_bytes(&mut typed_operation, 2, &operation);
        field_bytes(&mut remove, 2, &typed_operation);
        assert!(api.alter_inbound(&remove).is_ok());
        assert!(!users.list().iter().any(|user| user.id == second));
    }

    #[test]
    fn the_stats_service_reads_back_and_resets_a_counter() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true}},
                "inbounds":[{"tag":"test"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        crate::stats::inbound(Some("test")).read(11);
        let mut request = Vec::new();
        field_str(&mut request, 1, "inbound>>>test>>>traffic>>>uplink");
        field_varint(&mut request, 2, 1);
        let answer = Api::get_stats(&request).expect("reads the counter");
        let stat = request_bytes(&answer, 1).expect("one stat");
        assert_eq!(
            request_str(stat, 1),
            Some("inbound>>>test>>>traffic>>>uplink".to_owned())
        );
        assert_eq!(request_varint(stat, 2), Some(11));
        let answer = Api::get_stats(&request).expect("reads the reset counter");
        let stat = request_bytes(&answer, 1).expect("one stat");
        assert_eq!(request_varint(stat, 2), Some(0));
        crate::stats::clear();
    }

    #[test]
    fn the_stats_service_answers_the_online_map_and_user_stats() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true,
                "statsUserDownlink":true,"statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        let name = "user>>>alice@example>>>online";
        let lease =
            crate::stats::online("alice@example", 1, Some("192.0.2.10".parse().expect("ip")))
                .expect("the level tracks online users");
        let meter = crate::stats::user_traffic("alice@example", 1);
        meter.read(3);
        meter.write(7);

        let mut request = Vec::new();
        field_str(&mut request, 1, name);
        let answer = Api::get_stats_online(&request).expect("reads the map");
        let stat = request_bytes(&answer, 1).expect("one stat");
        assert_eq!(request_str(stat, 1), Some(name.to_owned()));
        assert_eq!(request_varint(stat, 2), Some(1));

        let answer = Api::get_stats_online_ip_list(&request).expect("lists the sources");
        assert_eq!(request_str(&answer, 1), Some(name.to_owned()));
        let entry = request_bytes(&answer, 2).expect("one source");
        assert_eq!(request_str(entry, 1), Some("192.0.2.10".to_owned()));
        assert!(request_varint(entry, 2).is_some_and(|seen| seen > 0));

        let answer = Api::get_all_online_users();
        assert_eq!(request_strs(&answer, 1), vec![name.to_owned()]);

        let mut request = Vec::new();
        field_varint(&mut request, 1, 1);
        let answer = Api::get_users_stats(&request);
        let row = request_bytes(&answer, 1).expect("one user");
        assert_eq!(request_str(row, 1), Some("alice@example".to_owned()));
        let ip = request_bytes(row, 2).expect("one source");
        assert_eq!(request_str(ip, 1), Some("192.0.2.10".to_owned()));
        let traffic = request_bytes(row, 3).expect("the traffic block");
        assert_eq!(request_varint(traffic, 1), Some(3));
        assert_eq!(request_varint(traffic, 2), Some(7));

        let mut request = Vec::new();
        field_varint(&mut request, 1, 1);
        field_varint(&mut request, 2, 1);
        let answer = Api::get_users_stats(&request);
        let row = request_bytes(&answer, 1).expect("one user");
        let traffic = request_bytes(row, 3).expect("the traffic block");
        assert_eq!(
            request_varint(traffic, 1),
            Some(3),
            "the reference returns the value it reset"
        );
        assert_eq!(request_varint(traffic, 2), Some(7));
        let answer = Api::get_users_stats(&[0x08, 0x01]);
        let row = request_bytes(&answer, 1).expect("one user");
        let traffic = request_bytes(row, 3).expect("the traffic block");
        assert_eq!(request_varint(traffic, 1), Some(0));
        assert_eq!(request_varint(traffic, 2), Some(0));
        drop(lease);
        crate::stats::clear();
    }

    fn freedom_outbound(tag: &str) -> Vec<u8> {
        let mut typed = Vec::new();
        field_str(&mut typed, 1, "xray.proxy.freedom.Config");
        let mut out = Vec::new();
        field_str(&mut out, 1, tag);
        field_bytes(&mut out, 3, &typed);
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        field_bytes(&mut out, field, value);
        out
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        field_varint(&mut out, field, value);
        out
    }

    fn message(fields: &[Vec<u8>]) -> Vec<u8> {
        fields.concat()
    }

    fn typed(name: &str, value: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, name.as_bytes()), bytes_field(2, value)])
    }

    fn dokodemo_inbound(ports: &[u16]) -> Vec<u8> {
        let ranges: Vec<Vec<u8>> = ports
            .iter()
            .map(|port| {
                message(&[
                    varint_field(1, u64::from(*port)),
                    varint_field(2, u64::from(*port)),
                ])
            })
            .collect();
        let list = message(
            &ranges
                .iter()
                .map(|range| bytes_field(1, range))
                .collect::<Vec<_>>(),
        );
        let receiver = message(&[
            bytes_field(1, &list),
            bytes_field(2, &bytes_field(1, &[127, 0, 0, 1])),
        ]);
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, u64::from(ports[0])),
            varint_field(7, 2),
        ]);
        let mut out = Vec::new();
        field_str(&mut out, 1, "d");
        field_bytes(
            &mut out,
            2,
            &typed("xray.app.proxyman.ReceiverConfig", &receiver),
        );
        field_bytes(&mut out, 3, &typed("xray.proxy.dokodemo.Config", &settings));
        out
    }

    fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        listener.local_addr().expect("addr").port()
    }

    fn wait_for_port(port: u16, open: bool) {
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() == open {
                return;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!(
            "port {port} never became {}",
            if open { "open" } else { "closed" }
        );
    }

    #[test]
    fn add_outbound_lists_and_remove_outbound_drops_it() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        api.set_runtime(std::sync::Arc::new(crate::proxy::test_runtime(&root)));
        let raw = freedom_outbound("new");
        let mut add = Vec::new();
        field_bytes(&mut add, 1, &raw);
        assert!(api.add_outbound(&add).is_ok());
        assert_eq!(
            api.add_outbound(&add),
            Err((2, "existing tag found: new".to_owned()))
        );
        let listed = api.list_outbounds().expect("lists");
        assert_eq!(request_bytes(&listed, 1), Some(raw.as_slice()));
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "new");
        assert!(api.remove_outbound(&remove).is_ok());
        assert_eq!(api.list_outbounds().expect("lists"), [] as [u8; 0]);
        assert!(api.remove_outbound(&remove).is_ok());
        assert_eq!(
            api.remove_outbound(&[]),
            Err((2, "empty handler tag".to_owned()))
        );
    }

    #[test]
    fn add_inbound_serves_and_remove_inbound_stops_it() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        api.set_runtime(std::sync::Arc::new(crate::proxy::test_runtime(&root)));
        let first = free_port();
        let second = loop {
            let port = free_port();
            if port != first {
                break port;
            }
        };
        let raw = dokodemo_inbound(&[first, second]);
        let mut add = Vec::new();
        field_bytes(&mut add, 1, &raw);
        assert!(api.add_inbound(&add).is_ok());
        wait_for_port(first, true);
        wait_for_port(second, true);
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "d");
        assert!(api.remove_inbound(&remove).is_ok());
        wait_for_port(first, false);
        wait_for_port(second, false);
    }

    fn free_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds a datagram port");
        socket.local_addr().expect("addr").port()
    }

    fn pem_lines(pem: &str) -> String {
        pem.lines()
            .map(|line| format!("\"{line}\""))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// A dynamic add serves each h3 carrier with the handler's stop flag, so a remove frees the
    /// QUIC port and the next add on that port binds again.
    #[test]
    fn xhttp_h3_inbounds_stop_with_their_handler() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        let runtime = std::sync::Arc::new(crate::proxy::test_runtime(&root));
        api.set_runtime(std::sync::Arc::clone(&runtime));
        let minted = rcgen::generate_simple_self_signed(vec!["h3.test".to_owned()]).expect("mints");
        let certificate = pem_lines(&minted.cert.pem());
        let key = pem_lines(&minted.signing_key.serialize_pem());
        let settings = [
            (
                "vless-h3",
                "vless",
                r#"{"clients":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}],"decryption":"none"}"#,
                "/vless-h3",
            ),
            (
                "trojan-h3",
                "trojan",
                r#"{"clients":[{"password":"trojan-pass"}]}"#,
                "/trojan-h3",
            ),
            (
                "ss-h3",
                "shadowsocks",
                r#"{"method":"chacha20-ietf-poly1305","password":"ss-pass","network":"tcp"}"#,
                "/ss-h3",
            ),
        ];
        for (tag, protocol, settings, path) in settings {
            let port = free_udp_port();
            let inbound = format!(
                r#"{{"tag":"{tag}","protocol":"{protocol}","listen":"127.0.0.1","port":{port},"settings":{settings},"streamSettings":{{"network":"xhttp","security":"tls","tlsSettings":{{"alpn":["h3"],"certificates":[{{"certificate":[{certificate}],"key":[{key}]}}]}},"xhttpSettings":{{"path":"{path}"}}}}}}"#
            );
            let config = crate::json::parse(&format!(
                r#"{{"outbounds":[{{"tag":"default","protocol":"freedom"}}],"routing":{{}},"inbounds":[{inbound}]}}"#
            ))
            .expect("parses the h3 inbound");
            assert_eq!(
                crate::proxy::serve_dynamic_inbounds(
                    &runtime,
                    &config,
                    &crate::xray_pb::Seed::default(),
                    &api,
                ),
                1,
                "{tag} did not serve"
            );
            assert!(
                std::net::UdpSocket::bind(("127.0.0.1", port)).is_err(),
                "{tag} did not bind its QUIC port"
            );
            let mut remove = Vec::new();
            field_str(&mut remove, 1, tag);
            assert!(api.remove_inbound(&remove).is_ok(), "{tag} did not stop");
            drop(
                std::net::UdpSocket::bind(("127.0.0.1", port))
                    .unwrap_or_else(|error| panic!("{tag} left its QUIC port bound: {error}")),
            );
            assert_eq!(
                crate::proxy::serve_dynamic_inbounds(
                    &runtime,
                    &config,
                    &crate::xray_pb::Seed::default(),
                    &api,
                ),
                1,
                "{tag} could not bind the port again"
            );
            assert!(api.remove_inbound(&remove).is_ok());
        }
    }

    /// A TUIC inbound is a QUIC listener like the h3 carriers, so remove frees its port and the
    /// next add binds it again.
    #[test]
    fn tuic_inbounds_stop_with_their_handler() {
        let root = crate::json::parse(
            r#"{"outbounds":[{"tag":"default","protocol":"freedom"}],"routing":{}}"#,
        )
        .expect("parses");
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: true,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        let runtime = std::sync::Arc::new(crate::proxy::test_runtime(&root));
        api.set_runtime(std::sync::Arc::clone(&runtime));
        let minted =
            rcgen::generate_simple_self_signed(vec!["tuic.test".to_owned()]).expect("mints");
        let certificate = pem_lines(&minted.cert.pem());
        let key = pem_lines(&minted.signing_key.serialize_pem());
        let port = free_udp_port();
        let inbound = format!(
            r#"{{"tag":"tuic","protocol":"tuic","listen":"127.0.0.1","port":{port},"settings":{{"users":[{{"uuid":"00112233-4455-6677-8899-aabbccddeeff","password":"secret"}}]}},"streamSettings":{{"security":"tls","tlsSettings":{{"alpn":["h3"],"certificates":[{{"certificate":[{certificate}],"key":[{key}]}}]}}}}}}"#
        );
        let config = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"tag":"default","protocol":"freedom"}}],"routing":{{}},"inbounds":[{inbound}]}}"#
        ))
        .expect("parses the tuic inbound");
        assert_eq!(
            crate::proxy::serve_dynamic_inbounds(
                &runtime,
                &config,
                &crate::xray_pb::Seed::default(),
                &api,
            ),
            1
        );
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_err());
        let mut remove = Vec::new();
        field_str(&mut remove, 1, "tuic");
        assert!(api.remove_inbound(&remove).is_ok());
        drop(
            std::net::UdpSocket::bind(("127.0.0.1", port))
                .unwrap_or_else(|error| panic!("tuic left its QUIC port bound: {error}")),
        );
        assert_eq!(
            crate::proxy::serve_dynamic_inbounds(
                &runtime,
                &config,
                &crate::xray_pb::Seed::default(),
                &api,
            ),
            1
        );
        assert!(api.remove_inbound(&remove).is_ok());
    }

    #[test]
    fn alter_outbound_reports_what_the_reference_reports() {
        let mut operation = Vec::new();
        field_str(
            &mut operation,
            1,
            "xray.app.proxyman.command.AddUserOperation",
        );
        let mut request = Vec::new();
        field_str(&mut request, 1, "any");
        field_bytes(&mut request, 2, &operation);
        assert_eq!(
            Api::alter_outbound(&request),
            Err((2, "not an outbound operation".to_owned()))
        );
        let mut operation = Vec::new();
        field_str(&mut operation, 1, "xray.app.proxyman.command.Unknown");
        let mut request = Vec::new();
        field_str(&mut request, 1, "any");
        field_bytes(&mut request, 2, &operation);
        assert_eq!(
            Api::alter_outbound(&request),
            Err((2, "unknown operation".to_owned()))
        );
    }

    #[test]
    fn the_logger_service_answers_only_when_the_config_lists_it() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(r#"{"api":{"tag":"api","services":["loggerService"]}}"#)
            .expect("parses");
        assert!(
            ApiConfig::from_json(&root).expect("api block").logger,
            "the service name is case-insensitive"
        );
        let path = "/xray.app.log.command.LoggerService/RestartLogger";
        let unselected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        assert_eq!(
            unselected
                .dispatch(path, &[])
                .expect_err("service is not selected"),
            (12, format!("{path} is not a method this server carries"))
        );
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: true,
            observatory: false,
            routing: false,
        });
        assert_eq!(
            selected.dispatch(path, &[]).expect("answers the call"),
            Vec::<u8>::new()
        );
        assert_eq!(
            selected
                .dispatch("/xray.app.log.command.LoggerService/Unknown", &[])
                .expect_err("unknown method"),
            (
                12,
                "/xray.app.log.command.LoggerService/Unknown is not a method this server carries"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_protobuf_service_uses_the_pinned_observatory_name() {
        let service = typed("xray.core.app.observatory.command.Config", &[]);
        let mut config = Vec::new();
        field_bytes(&mut config, 2, &service);
        assert!(
            ApiConfig::from_proto(&config).expect("parses").observatory,
            "the pinned protobuf name selects the observatory"
        );
    }

    #[test]
    fn the_observatory_service_serializes_the_live_snapshot() {
        let root = crate::json::parse(r#"{"api":{"tag":"api","services":["observatoryService"]}}"#)
            .expect("parses");
        assert!(
            ApiConfig::from_json(&root).expect("api block").observatory,
            "the service name is case-insensitive"
        );
        let path = "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus";
        let unselected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        assert_eq!(
            unselected
                .dispatch(path, &[])
                .expect_err("service is not selected"),
            (12, format!("{path} is not a method this server carries"))
        );
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: true,
            routing: false,
        });
        let observed = crate::router::Observed {
            tag: "edge".to_owned(),
            alive: true,
            delay_ms: 12,
            health: Some(crate::router::HealthPing {
                all: 5,
                fail: 1,
                deviation: 2,
                average: 12,
            }),
            last_error: "an earlier timeout".to_owned(),
            last_seen: 100,
            last_try: 101,
        };
        selected.set_observatory(Some(crate::observatory::Observatory::seeded(&[observed])));
        let answer = selected.dispatch(path, &[]).expect("answers the call");
        let status = request_bytes(&answer, 1).expect("status");
        let entry = request_bytes(status, 1).expect("one outbound");
        assert_eq!(request_varint(entry, 1), Some(1), "alive");
        assert_eq!(request_varint(entry, 2), Some(12), "delay in ms");
        assert_eq!(
            request_str(entry, 3).as_deref(),
            Some("an earlier timeout"),
            "the last error"
        );
        assert_eq!(request_str(entry, 4).as_deref(), Some("edge"), "tag");
        assert_eq!(request_varint(entry, 5), Some(100), "last seen");
        assert_eq!(request_varint(entry, 6), Some(101), "last try");
        let health = request_bytes(entry, 7).expect("health ping");
        assert_eq!(request_varint(health, 1), Some(5), "all");
        assert_eq!(request_varint(health, 2), Some(1), "fail");
        assert_eq!(request_varint(health, 3), Some(2), "deviation");
        assert_eq!(request_varint(health, 4), Some(12), "average");
    }

    #[test]
    fn a_selected_service_without_an_observatory_answers_an_empty_result() {
        let selected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: true,
            routing: false,
        });
        assert_eq!(
            selected
                .dispatch(
                    "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus",
                    &[]
                )
                .expect("an empty result is still an answer"),
            vec![0x0a, 0x00]
        );
    }

    #[test]
    fn a_missing_counter_is_not_found() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let mut request = Vec::new();
        field_str(&mut request, 1, "user>>>nobody>>>traffic>>>uplink");
        assert_eq!(
            Api::get_stats(&request),
            Err((5, "user>>>nobody>>>traffic>>>uplink not found.".to_owned()))
        );
        crate::stats::clear();
    }

    const ROUTED: &str = r#"{
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "edge-a", "protocol": "freedom"},
            {"tag": "edge-b", "protocol": "freedom"}
        ],
        "routing": {
            "rules": [
                {"type": "field", "ruleTag": "web", "domain": ["example.com"], "outboundTag": "edge-a"},
                {"type": "field", "ruleTag": "pool", "network": "tcp", "balancerTag": "pool"},
                {"type": "field", "ruleTag": "udp", "network": "udp", "outboundTag": "direct"}
            ],
            "balancers": [{"tag": "pool", "selector": ["edge-"],
                           "strategy": {"type": "random", "settings": {}}}]
        }
    }"#;

    const SERVER_ROUTED: &str = r#"{
        "inbounds": [
            {"tag": "server", "protocol": "vless", "port": 443,
             "settings": {"clients": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}}
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "edge-a", "protocol": "freedom"},
            {"tag": "edge-b", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"}
        ],
        "routing": {
            "rules": [
                {"type": "field", "ruleTag": "pool", "network": "tcp", "balancerTag": "pool"}
            ],
            "balancers": [{"tag": "pool", "selector": ["edge-"],
                           "strategy": {"type": "random", "settings": {}}}]
        }
    }"#;

    fn routing_api(root: &crate::json::Json) -> Arc<Api> {
        let api = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
            routing: true,
        });
        api.set_runtime(std::sync::Arc::new(crate::proxy::test_runtime(root)));
        api
    }

    /// One `xray.app.router.RoutingRule` a typed router Config carries: an outbound, a ruleTag and
    /// one `domain:` entry.
    fn router_rule(outbound: &str, rule_tag: &str, domain: &str) -> Vec<u8> {
        let domain = message(&[varint_field(1, 2), bytes_field(2, domain.as_bytes())]);
        let rule = message(&[bytes_field(2, &domain)]);
        message(&[
            bytes_field(1, outbound.as_bytes()),
            bytes_field(2, &rule),
            bytes_field(19, rule_tag.as_bytes()),
        ])
    }

    fn add_rule_request(rules: &[Vec<u8>], append: bool) -> Vec<u8> {
        let mut config = Vec::new();
        for rule in rules {
            config.extend(bytes_field(2, rule));
        }
        let mut request = bytes_field(1, &typed("xray.app.router.Config", &config));
        if append {
            request.extend(varint_field(2, 1));
        }
        request
    }

    fn remove_rule_request(rule_tag: &str) -> Vec<u8> {
        let mut request = Vec::new();
        field_str(&mut request, 1, rule_tag);
        request
    }

    fn listed(api: &Api) -> Vec<(Option<String>, Option<String>)> {
        let answer = api
            .dispatch("/xray.app.router.command.RoutingService/ListRule", &[])
            .expect("lists");
        all_bytes(&answer, 1)
            .map(|item| (request_str(item, 1), request_str(item, 2)))
            .collect()
    }

    fn routed_tag(api: &Api, domain: &str) -> Option<String> {
        let request = test_route_request(&routed_context(2, domain), &["outbound"]);
        api.dispatch(
            "/xray.app.router.command.RoutingService/TestRoute",
            &request,
        )
        .ok()
        .and_then(|answer| request_str(&answer, 12))
    }

    fn test_route_request(context: &[u8], selectors: &[&str]) -> Vec<u8> {
        let mut request = Vec::new();
        field_bytes(&mut request, 1, context);
        for selector in selectors {
            field_str(&mut request, 2, selector);
        }
        request
    }

    fn routed_context(network: u64, domain: &str) -> Vec<u8> {
        let mut context = Vec::new();
        field_str(&mut context, 1, "socks-in");
        if network != 0 {
            field_varint(&mut context, 2, network);
        }
        field_varint(&mut context, 6, 443);
        field_str(&mut context, 7, domain);
        context
    }

    #[test]
    fn the_routing_service_answers_only_when_the_config_lists_it() {
        let root = crate::json::parse(r#"{"api":{"tag":"api","services":["routingService"]}}"#)
            .expect("parses");
        assert!(
            ApiConfig::from_json(&root).expect("api block").routing,
            "the service name is case-insensitive"
        );
        let mut config = Vec::new();
        field_bytes(
            &mut config,
            2,
            &typed("xray.app.router.command.Config", &[]),
        );
        assert!(
            ApiConfig::from_proto(&config).expect("parses").routing,
            "the pinned protobuf name selects routing"
        );
        let path = "/xray.app.router.command.RoutingService/ListRule";
        let unselected = Api::new(ApiConfig {
            tag: "api".to_owned(),
            listen: None,
            handler: false,
            stats: false,
            logger: false,
            observatory: false,
            routing: false,
        });
        assert_eq!(
            unselected
                .dispatch(path, &[])
                .expect_err("service is not selected"),
            (12, format!("{path} is not a method this server carries"))
        );
        let routed = crate::json::parse(ROUTED).expect("parses");
        let selected = routing_api(&routed);
        assert!(selected.dispatch(path, &[]).is_ok());
        assert!(
            selected
                .dispatch(
                    "/v2ray.core.app.router.command.RoutingService/ListRule",
                    &[]
                )
                .is_ok(),
            "the alias path answers too"
        );
    }

    #[test]
    fn list_rule_names_each_rules_target_and_rule_tag() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        let answer = api
            .dispatch("/xray.app.router.command.RoutingService/ListRule", &[])
            .expect("lists");
        let items: Vec<&[u8]> = all_bytes(&answer, 1).collect();
        assert_eq!(items.len(), 3, "one item per configured rule");
        assert_eq!(request_str(items[0], 1).as_deref(), Some("edge-a"));
        assert_eq!(request_str(items[0], 2).as_deref(), Some("web"));
        assert_eq!(
            request_bytes(items[1], 1),
            None,
            "a balancer rule names no outbound, as the reference's one-of leaves it empty"
        );
        assert_eq!(request_str(items[1], 2).as_deref(), Some("pool"));
        assert_eq!(request_str(items[2], 1).as_deref(), Some("direct"));
        assert_eq!(request_str(items[2], 2).as_deref(), Some("udp"));
    }

    /// A table whose rules reach both outbounds and no network or port selector shadows the
    /// appended rule, which is then the first match for the domain the test asks about.
    const ADDABLE: &str = r#"{
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "edge-b", "protocol": "freedom"}
        ],
        "routing": {"rules": [
            {"type": "field", "ruleTag": "web", "domain": ["full:example.com"], "outboundTag": "direct"},
            {"type": "field", "ruleTag": "seed", "domain": ["full:seed.test"], "outboundTag": "edge-b"}
        ]}
    }"#;

    #[test]
    fn add_rule_appends_a_rule_the_live_table_answers_with() {
        let root = crate::json::parse(ADDABLE).expect("parses");
        let api = routing_api(&root);
        let path = "/xray.app.router.command.RoutingService/AddRule";
        api.dispatch(
            path,
            &add_rule_request(&[router_rule("edge-b", "added", "blocked.test")], true),
        )
        .expect("appends");

        let rules = listed(&api);
        assert_eq!(
            rules.len(),
            3,
            "the appended rule joins the two configured ones"
        );
        assert_eq!(
            rules[2],
            (Some("edge-b".to_owned()), Some("added".to_owned()))
        );
        assert_eq!(
            routed_tag(&api, "blocked.test").as_deref(),
            Some("edge-b"),
            "a flow reaches the rule the call added"
        );

        api.dispatch(
            "/xray.app.router.command.RoutingService/RemoveRule",
            &remove_rule_request("added"),
        )
        .expect("removes");
        assert_eq!(listed(&api).len(), 2);
        assert_eq!(
            routed_tag(&api, "blocked.test"),
            None,
            "the removed rule no longer answers"
        );
    }

    #[test]
    fn add_rule_without_append_replaces_the_whole_table() {
        let root = crate::json::parse(ADDABLE).expect("parses");
        let api = routing_api(&root);
        api.dispatch(
            "/xray.app.router.command.RoutingService/AddRule",
            &add_rule_request(&[router_rule("edge-b", "only", "blocked.test")], false),
        )
        .expect("replaces");

        assert_eq!(
            listed(&api),
            vec![(Some("edge-b".to_owned()), Some("only".to_owned()))],
            "the reference's shouldAppend=false drops every old rule"
        );
        assert_eq!(routed_tag(&api, "example.com"), None);
        assert_eq!(routed_tag(&api, "blocked.test").as_deref(), Some("edge-b"));
    }

    #[test]
    fn add_rule_refuses_a_rule_tag_the_table_already_carries() {
        let root = crate::json::parse(ADDABLE).expect("parses");
        let api = routing_api(&root);
        assert_eq!(
            api.dispatch(
                "/xray.app.router.command.RoutingService/AddRule",
                &add_rule_request(&[router_rule("edge-b", "web", "blocked.test")], true),
            ),
            Err((2, "duplicate ruleTag `web`".to_owned()))
        );
    }

    #[test]
    fn add_rule_refuses_a_config_that_is_not_a_router() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        let request = bytes_field(1, &typed("xray.app.dns.Config", &[]));
        assert_eq!(
            api.dispatch("/xray.app.router.command.RoutingService/AddRule", &request),
            Err((2, "AddRule: config type error".to_owned()))
        );
    }

    #[test]
    fn remove_rule_refuses_an_empty_tag() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        assert_eq!(
            api.dispatch(
                "/xray.app.router.command.RoutingService/RemoveRule",
                &remove_rule_request(""),
            ),
            Err((2, "empty tag name!".to_owned()))
        );
    }

    #[test]
    fn test_route_reads_the_rule_table_and_echoes_the_context() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        let path = "/xray.app.router.command.RoutingService/TestRoute";
        let request = test_route_request(&routed_context(2, "example.com"), &[]);
        let answer = api.dispatch(path, &request).expect("answers the call");
        assert_eq!(request_str(&answer, 1).as_deref(), Some("socks-in"));
        assert_eq!(request_varint(&answer, 2), Some(2), "tcp");
        assert_eq!(request_varint(&answer, 6), Some(443), "the target port");
        assert_eq!(request_str(&answer, 7).as_deref(), Some("example.com"));
        assert_eq!(request_str(&answer, 12).as_deref(), Some("edge-a"));

        let selected =
            test_route_request(&routed_context(2, "example.com"), &["domain", "outbound"]);
        let answer = api.dispatch(path, &selected).expect("answers the call");
        assert_eq!(request_str(&answer, 7).as_deref(), Some("example.com"));
        assert_eq!(request_str(&answer, 12).as_deref(), Some("edge-a"));
        assert_eq!(request_str(&answer, 1), None, "a selector drops inbound");
        assert_eq!(request_varint(&answer, 6), None, "and the port");
        assert_eq!(request_varint(&answer, 2), None, "and the network");

        let balanced = test_route_request(&routed_context(2, "nowhere.test"), &["outbound"]);
        let answer = api
            .dispatch(path, &balanced)
            .expect("a balancer rule picks");
        let picked = request_str(&answer, 12).expect("the picked tag");
        assert!(
            picked == "edge-a" || picked == "edge-b",
            "the balancer picks one of its candidates, not the rule's own tag"
        );
        assert_eq!(request_str(&answer, 7), None, "the selector drops domain");

        let no_clue = test_route_request(&routed_context(0, "nowhere.test"), &[]);
        assert_eq!(
            api.dispatch(path, &no_clue),
            Err((2, "no clue".to_owned())),
            "the default outbound is the caller's fallback, never the answer"
        );
        assert_eq!(
            api.dispatch(path, &[]),
            Err((2, "Invalid routing request.".to_owned()))
        );
    }

    #[test]
    fn test_route_reads_a_multi_address_context_as_any_of() {
        let root = crate::json::parse(
            r#"{
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "edge", "protocol": "freedom"}
                ],
                "routing": {"rules": [
                    {"type": "field", "ruleTag": "ip", "ip": ["203.0.113.5"], "outboundTag": "edge"}
                ]}
            }"#,
        )
        .expect("parses");
        let api = routing_api(&root);
        let mut context = Vec::new();
        field_bytes(&mut context, 4, &[198, 51, 100, 1]);
        field_bytes(&mut context, 4, &[203, 0, 113, 5]);
        field_varint(&mut context, 6, 443);
        let answer = api
            .dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&context, &["outbound"]),
            )
            .expect("answers the call");
        assert_eq!(
            request_str(&answer, 12).as_deref(),
            Some("edge"),
            "the address list is any-of, so the second target reaches the ip rule"
        );
    }

    #[test]
    fn test_route_rejects_an_unbounded_address_cross_product() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        let mut context = Vec::new();
        for _ in 0..33 {
            field_bytes(&mut context, 3, &[198, 51, 100, 1]);
            field_bytes(&mut context, 4, &[203, 0, 113, 5]);
            field_bytes(&mut context, 13, &[192, 0, 2, 1]);
        }
        assert_eq!(
            api.dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&context, &["outbound"]),
            ),
            Err((
                3,
                "routing context: a tested context names more than 1024 address combinations"
                    .to_owned()
            ))
        );
        let mut at_cap = Vec::new();
        for _ in 0..32 {
            field_bytes(&mut at_cap, 3, &[198, 51, 100, 1]);
            field_bytes(&mut at_cap, 13, &[192, 0, 2, 1]);
        }
        assert_eq!(
            api.dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&at_cap, &["outbound"]),
            ),
            Err((2, "no clue".to_owned())),
            "1024 combinations is the cap, not one past it"
        );
    }

    #[test]
    fn test_route_reads_a_source_port_named_without_an_address() {
        let root = crate::json::parse(
            r#"{
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "edge", "protocol": "freedom"}
                ],
                "routing": {"rules": [
                    {"type": "field", "ruleTag": "sp", "sourcePort": "9999", "outboundTag": "edge"}
                ]}
            }"#,
        )
        .expect("parses");
        let api = routing_api(&root);
        let mut context = Vec::new();
        field_varint(&mut context, 5, 9999);
        let answer = api
            .dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&context, &["outbound"]),
            )
            .expect("a port without an address is a context the reference routes");
        assert_eq!(request_str(&answer, 12).as_deref(), Some("edge"));
    }

    #[test]
    fn test_route_reads_the_vless_route_id_the_context_carries() {
        let root = crate::json::parse(
            r#"{
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "edge", "protocol": "freedom"}
                ],
                "routing": {"rules": [
                    {"type": "field", "ruleTag": "vr", "vlessRoute": "5", "outboundTag": "edge"}
                ]}
            }"#,
        )
        .expect("parses");
        let api = routing_api(&root);
        let mut context = Vec::new();
        field_varint(&mut context, 15, 5);
        let answer = api
            .dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&context, &["outbound"]),
            )
            .expect("the tested route id is part of the context");
        assert_eq!(request_str(&answer, 12).as_deref(), Some("edge"));
    }

    /// A receiver that answers `replies` requests with `204` and hands back what it read, head and
    /// body together, so a test reads the exact bytes the notifier wrote.
    fn webhook_receiver(replies: usize) -> (u16, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("arms");
                let mut raw = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    use std::io::Read as _;
                    let read = stream.read(&mut buf).expect("reads");
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..read]);
                    let Some(head) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                        continue;
                    };
                    let length: usize = String::from_utf8_lossy(&raw[..head])
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= head + 4 + length {
                        break;
                    }
                }
                send.send(String::from_utf8_lossy(&raw).into_owned()).ok();
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .expect("replies");
            }
        });
        (port, receive)
    }

    #[test]
    fn test_route_fires_the_matched_rules_webhook() {
        let (port, receive) = webhook_receiver(1);
        let root = crate::json::parse(&format!(
            r#"{{
                "outbounds": [{{"tag": "direct", "protocol": "freedom"}}],
                "routing": {{"rules": [
                    {{"type": "field", "ruleTag": "hook", "domain": ["example.test"],
                      "outboundTag": "direct",
                      "webhook": {{"url": "http://127.0.0.1:{port}/hook"}}}}
                ]}}
            }}"#
        ))
        .expect("parses");
        let api = routing_api(&root);
        let context = routed_context(2, "example.test");
        let answer = api
            .dispatch(
                "/xray.app.router.command.RoutingService/TestRoute",
                &test_route_request(&context, &["outbound"]),
            )
            .expect("answers the call");
        assert_eq!(request_str(&answer, 12).as_deref(), Some("direct"));
        let posted = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the tested route fires the rule's webhook");
        assert!(
            posted.starts_with(&format!(
                "POST /hook HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
            )),
            "{posted}"
        );
        for field in [
            "\"level\":null",
            "\"network\":\"tcp\"",
            "\"destination\":\"example.test:443\"",
            "\"originalTarget\":null",
            "\"routeTarget\":null",
            "\"inboundTag\":\"socks-in\"",
            "\"inboundName\":null",
            "\"outboundTag\":\"direct\"",
        ] {
            assert!(posted.contains(field), "{field} is missing from {posted}");
        }
    }

    #[test]
    fn get_balancer_info_reports_the_override_and_the_principle_target() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        let path = "/xray.app.router.command.RoutingService";
        let mut request = Vec::new();
        field_str(&mut request, 1, "pool");
        let answer = api
            .dispatch(&format!("{path}/GetBalancerInfo"), &request)
            .expect("answers");
        let balancer = request_bytes(&answer, 1).expect("the balancer message");
        let override_info = request_bytes(balancer, 5).expect("override info is always present");
        assert_eq!(
            request_str(override_info, 2),
            None,
            "no override is an empty target"
        );
        let principle = request_bytes(balancer, 6).expect("principle target");
        assert_eq!(
            all_bytes(principle, 1)
                .map(|tag| String::from_utf8_lossy(tag).into_owned())
                .collect::<Vec<_>>(),
            vec!["edge-a".to_owned(), "edge-b".to_owned()],
            "a random strategy draws from every candidate"
        );
        let mut unknown = Vec::new();
        field_str(&mut unknown, 1, "nobody");
        assert_eq!(
            api.dispatch(&format!("{path}/GetBalancerInfo"), &unknown),
            Err((2, "cannot find tag".to_owned()))
        );
        let mut force = Vec::new();
        field_str(&mut force, 1, "pool");
        field_str(&mut force, 2, "edge-b");
        assert_eq!(
            api.dispatch(&format!("{path}/OverrideBalancerTarget"), &force),
            Ok(Vec::new())
        );
        let answer = api
            .dispatch(&format!("{path}/GetBalancerInfo"), &request)
            .expect("answers");
        let override_info =
            request_bytes(request_bytes(&answer, 1).expect("balancer"), 5).expect("override info");
        assert_eq!(request_str(override_info, 2).as_deref(), Some("edge-b"));
        let test = test_route_request(&routed_context(2, "nowhere.test"), &["outbound"]);
        let answer = api
            .dispatch(&format!("{path}/TestRoute"), &test)
            .expect("answers");
        assert_eq!(
            request_str(&answer, 12).as_deref(),
            Some("edge-b"),
            "the override decides the pick the strategy would have made"
        );
        assert_eq!(
            api.dispatch(&format!("{path}/OverrideBalancerTarget"), &unknown),
            Err((2, "cannot find tag".to_owned()))
        );
    }

    #[test]
    fn overriding_a_server_balancer_to_a_non_direct_target_is_refused_and_reverted() {
        let root = crate::json::parse(SERVER_ROUTED).expect("parses");
        let api = routing_api(&root);
        let path = "/xray.app.router.command.RoutingService";
        let force = |target: &str| {
            let mut request = Vec::new();
            field_str(&mut request, 1, "pool");
            field_str(&mut request, 2, target);
            request
        };
        assert_eq!(
            api.dispatch(&format!("{path}/OverrideBalancerTarget"), &force("edge-b")),
            Ok(Vec::new()),
            "a direct target a server inbound can reach is still allowed"
        );
        let refusal = api
            .dispatch(&format!("{path}/OverrideBalancerTarget"), &force("blocked"))
            .expect_err("a non-direct target on a server route is refused");
        assert_eq!(refusal.0, 2);
        assert!(refusal.1.contains("pool"), "{}", refusal.1);

        let mut request = Vec::new();
        field_str(&mut request, 1, "pool");
        let answer = api
            .dispatch(&format!("{path}/GetBalancerInfo"), &request)
            .expect("answers");
        let override_info =
            request_bytes(request_bytes(&answer, 1).expect("balancer"), 5).expect("override info");
        assert_eq!(
            request_str(override_info, 2).as_deref(),
            Some("edge-b"),
            "the refused target is reverted to the previous one"
        );
    }

    #[test]
    fn subscribe_routing_stats_says_it_is_not_enabled() {
        let root = crate::json::parse(ROUTED).expect("parses");
        let api = routing_api(&root);
        assert_eq!(
            api.dispatch(
                "/xray.app.router.command.RoutingService/SubscribeRoutingStats",
                &[]
            ),
            Err((2, "Routing statistics not enabled.".to_owned())),
            "the reference registers this service without a statistics channel"
        );
    }
}

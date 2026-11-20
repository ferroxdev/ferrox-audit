use crate::json::Json;
use crate::stats;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) listen: Option<String>,
    pub(crate) tag: Option<String>,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);
static TAGGED: Mutex<Option<SocketAddr>> = Mutex::new(None);
static OBSERVATORY: Mutex<Option<std::sync::Arc<crate::observatory::Observatory>>> =
    Mutex::new(None);

fn lock() -> std::sync::MutexGuard<'static, Option<Config>> {
    CONFIG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read the top-level `metrics` object: one listener address and the outbound tag the reference
/// gives its internal metrics inbound.
pub(crate) fn parse(root: &Json) -> Result<Config, String> {
    let Some(section) = root.get("metrics") else {
        return Ok(Config::default());
    };
    let Json::Obj(pairs) = section else {
        return Err("`metrics` is not an object".to_owned());
    };
    let mut config = Config::default();
    for (key, value) in pairs {
        match key.as_str() {
            "listen" => {
                config.listen = value
                    .as_str()
                    .filter(|listen| !listen.is_empty())
                    .map(str::to_owned);
            }
            "tag" => {
                config.tag = value
                    .as_str()
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned);
            }
            _ => {}
        }
    }
    Ok(config)
}

/// Install the metrics app and open its listener before the inbounds do, so a bind failure stops
/// startup rather than surfacing on the first scrape.
pub(crate) fn install(root: &Json) -> Result<Config, String> {
    set_observatory(None);
    let config = parse(root)?;
    let listener = config.listen.as_deref().map(bind).transpose()?;
    let tagged = if config.tag.is_some() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("cannot listen for metrics tag: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("cannot read metrics tag address: {error}"))?;
        Some((listener, address))
    } else {
        None
    };
    if let Some(listener) = listener {
        thread::Builder::new()
            .name("ferrox-metrics".to_owned())
            .spawn(move || serve(&listener))
            .map_err(|error| format!("cannot start metrics listener: {error}"))?;
    }
    if let Some((listener, address)) = tagged {
        thread::Builder::new()
            .name("ferrox-metrics-tag".to_owned())
            .spawn(move || serve(&listener))
            .map_err(|error| format!("cannot start metrics tag listener: {error}"))?;
        *TAGGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(address);
    } else {
        *TAGGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
    *lock() = Some(config.clone());
    Ok(config)
}

/// The tag the reference registers as an outbound handler, when the config names one.
pub(crate) fn tag() -> Option<String> {
    lock().as_ref().and_then(|config| config.tag.clone())
}

/// The probe loop whose latest reading the reference publishes beside the expvar counters.
pub(crate) fn set_observatory(
    observatory: Option<std::sync::Arc<crate::observatory::Observatory>>,
) {
    *OBSERVATORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = observatory;
}

/// The loopback lane a route to [`tag`] dials.
pub(crate) fn tagged_address() -> Option<SocketAddr> {
    *TAGGED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bind(listen: &str) -> Result<TcpListener, String> {
    let address = if listen.starts_with(':') {
        format!("0.0.0.0{listen}")
    } else {
        listen.to_owned()
    };
    TcpListener::bind(&address)
        .map_err(|error| format!("cannot listen for metrics on `{listen}`: {error}"))
}

/// A scrape is short and bounded; a peer past this many concurrent sockets is refused rather than given another thread.
const METRICS_WORKERS: usize = 8;
const METRICS_STACK: usize = 128 * 1024;
const METRICS_IDLE: Duration = Duration::from_secs(5);
static METRICS_SLOTS: crate::limit::Slots = crate::limit::Slots::new(METRICS_WORKERS);
static METRICS_REFUSED: AtomicBool = AtomicBool::new(false);

fn serve(listener: &TcpListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Some(slot) = METRICS_SLOTS.acquire() else {
            if !METRICS_REFUSED.swap(true, Ordering::Relaxed) {
                eprintln!("metrics: {METRICS_WORKERS} scrapes are busy; refusing more");
            }
            continue;
        };
        let worker = thread::Builder::new()
            .name("ferrox-metrics-scrape".to_owned())
            .stack_size(METRICS_STACK)
            .spawn(move || {
                let _slot = slot;
                answer(stream);
            });
        if let Err(error) = worker {
            eprintln!("metrics: cannot start a scrape worker: {error}");
        }
    }
}

fn answer(mut stream: TcpStream) {
    if stream.set_read_timeout(Some(METRICS_IDLE)).is_err()
        || stream.set_write_timeout(Some(METRICS_IDLE)).is_err()
    {
        return;
    }
    let mut request = [0u8; 4096];
    let mut read = 0;
    let deadline = Instant::now() + METRICS_IDLE;
    while read < request.len() && !request[..read].windows(4).any(|end| end == b"\r\n\r\n") {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match stream.read(&mut request[read..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => read += n,
        }
    }
    let head = String::from_utf8_lossy(&request[..read]);
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, content_type, body) = match path {
        "/debug/vars" => ("200 OK", "application/json", expvar()),
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", prometheus()),
        path if path.starts_with("/debug/pprof/") => (
            "501 Not Implemented",
            "text/plain; charset=utf-8",
            "runtime profiles are not available\n".to_owned(),
        ),
        _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn expvar() -> String {
    let snapshot = stats::snapshot();
    let mut rows = Vec::new();
    for (tag, traffic) in &snapshot.inbound {
        rows.push((
            format!("inbound>>>{tag}>>>traffic>>>uplink"),
            traffic.uplink,
        ));
        rows.push((
            format!("inbound>>>{tag}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (tag, traffic) in &snapshot.outbound {
        rows.push((
            format!("outbound>>>{tag}>>>traffic>>>uplink"),
            traffic.uplink,
        ));
        rows.push((
            format!("outbound>>>{tag}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (email, traffic) in &snapshot.user {
        rows.push((format!("user>>>{email}>>>traffic>>>uplink"), traffic.uplink));
        rows.push((
            format!("user>>>{email}>>>traffic>>>downlink"),
            traffic.downlink,
        ));
    }
    for (email, count) in &snapshot.online {
        rows.push((format!("user>>>{email}>>>online"), count.cast_signed()));
    }
    let mut out = String::from("{");
    for (index, (name, value)) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(&mut out, name);
        out.push(':');
        out.push_str(&value.to_string());
    }
    if !rows.is_empty() {
        out.push(',');
    }
    out.push_str("\"stats\":");
    out.push_str(&stats_tree(&snapshot));
    out.push_str(",\"observatory\":");
    out.push_str(&observatory_tree());
    out.push('}');
    out
}

fn observatory_tree() -> String {
    let observatory = OBSERVATORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(observatory) = observatory else {
        return "null".to_owned();
    };
    let snapshot = observatory.snapshot();
    let mut out = String::from("{");
    for (index, observed) in snapshot.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(&mut out, &observed.tag);
        out.push(':');
        observed_tree(&mut out, observed);
    }
    out.push('}');
    out
}

fn observed_tree(out: &mut String, observed: &crate::router::Observed) {
    out.push('{');
    let mut first = true;
    if observed.alive {
        field_start(out, &mut first, "alive");
        out.push_str("true");
    }
    if observed.delay_ms != 0 {
        field_start(out, &mut first, "delay");
        out.push_str(&observed.delay_ms.to_string());
    }
    if !observed.last_error.is_empty() {
        field_start(out, &mut first, "last_error_reason");
        write_string(out, &observed.last_error);
    }
    if !observed.tag.is_empty() {
        field_start(out, &mut first, "outbound_tag");
        write_string(out, &observed.tag);
    }
    if observed.last_seen != 0 {
        field_start(out, &mut first, "last_seen_time");
        out.push_str(&observed.last_seen.to_string());
    }
    if observed.last_try != 0 {
        field_start(out, &mut first, "last_try_time");
        out.push_str(&observed.last_try.to_string());
    }
    if let Some(health) = observed.health {
        field_start(out, &mut first, "health_ping");
        out.push('{');
        let mut ping_first = true;
        for (name, value) in [
            ("all", health.all),
            ("fail", health.fail),
            ("deviation", health.deviation),
            ("average", health.average),
        ] {
            if value != 0 {
                field_start(out, &mut ping_first, name);
                out.push_str(&value.to_string());
            }
        }
        out.push('}');
    }
    out.push('}');
}

fn field_start(out: &mut String, first: &mut bool, name: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    write_string(out, name);
    out.push(':');
}

fn write_string(out: &mut String, value: &str) {
    let mut key = String::new();
    crate::json::write(&Json::Str(value.to_owned()), &mut key);
    out.push_str(&key);
}

fn stats_tree(snapshot: &stats::Snapshot) -> String {
    let mut out = String::from("{\"inbound\":");
    traffic_tree(&mut out, &snapshot.inbound);
    out.push_str(",\"outbound\":");
    traffic_tree(&mut out, &snapshot.outbound);
    out.push_str(",\"user\":");
    traffic_tree(&mut out, &snapshot.user);
    out.push('}');
    out
}

fn traffic_tree(out: &mut String, rows: &std::collections::BTreeMap<String, stats::Traffic>) {
    out.push('{');
    for (index, (tag, traffic)) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, tag);
        out.push_str(":{\"uplink\":");
        out.push_str(&traffic.uplink.to_string());
        out.push_str(",\"downlink\":");
        out.push_str(&traffic.downlink.to_string());
        out.push('}');
    }
    out.push('}');
}

fn prometheus() -> String {
    let snapshot = stats::snapshot();
    let mut out = String::new();
    for (tag, traffic) in &snapshot.inbound {
        let _ = writeln!(
            out,
            "ferrox_inbound_traffic_uplink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_inbound_traffic_downlink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.downlink
        );
    }
    for (tag, traffic) in &snapshot.outbound {
        let _ = writeln!(
            out,
            "ferrox_outbound_traffic_uplink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_outbound_traffic_downlink{{tag=\"{}\"}} {}",
            escape(tag),
            traffic.downlink
        );
    }
    for (email, traffic) in &snapshot.user {
        let _ = writeln!(
            out,
            "ferrox_user_traffic_uplink{{email=\"{}\"}} {}",
            escape(email),
            traffic.uplink
        );
        let _ = writeln!(
            out,
            "ferrox_user_traffic_downlink{{email=\"{}\"}} {}",
            escape(email),
            traffic.downlink
        );
    }
    for (email, count) in &snapshot.online {
        let _ = writeln!(
            out,
            "ferrox_user_online{{email=\"{}\"}} {}",
            escape(email),
            count
        );
    }
    out
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_listen_and_tag_are_read() {
        let root = crate::json::parse(r#"{"metrics":{"listen":"127.0.0.1:8080","tag":"metrics"}}"#)
            .expect("parses");
        assert_eq!(
            parse(&root).expect("metrics parses"),
            Config {
                listen: Some("127.0.0.1:8080".to_owned()),
                tag: Some("metrics".to_owned()),
            }
        );
    }

    #[test]
    fn a_metrics_section_that_is_not_an_object_is_refused() {
        let root = crate::json::parse(r#"{"metrics":[]}"#).expect("parses");
        assert!(parse(&root)
            .expect_err("metrics is an object")
            .contains("metrics"));
    }

    #[test]
    fn a_tag_opens_a_loopback_lane_that_answers_its_own_handler() {
        let _guard = crate::stats::test_lock();
        let root = crate::json::parse(r#"{"metrics":{"tag":"metrics"}}"#).expect("parses");
        install(&root).expect("metrics installs");
        assert_eq!(tag().as_deref(), Some("metrics"));
        let address = tagged_address().expect("a tagged lane");
        let mut stream = TcpStream::connect(address).expect("connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        stream
            .write_all(b"GET /debug/vars HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("writes");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("reads");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("application/json"));
        install(&crate::json::parse("{}").expect("parses")).expect("clears the tag");
        assert!(tagged_address().is_none());
    }

    #[test]
    fn the_prometheus_body_carries_a_registered_inbound_counter() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true}},
                "inbounds":[{"tag":"in"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        crate::stats::inbound(Some("in")).read(12);
        let body = prometheus();
        assert!(body.contains(r#"ferrox_inbound_traffic_uplink{tag="in"} 12"#));
        crate::stats::clear();
    }

    #[test]
    fn an_expvar_body_with_no_counters_is_valid_json() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        set_observatory(None);
        let body = expvar();
        assert!(body.starts_with(r#"{"stats":"#), "{body}");
        crate::json::parse(&body).expect("the empty tree parses");
        crate::stats::clear();
    }

    #[test]
    fn the_expvar_body_carries_the_reference_stats_tree() {
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true}},
                "inbounds":[{"tag":"in"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        crate::stats::install(&root).expect("stats installs");
        crate::stats::inbound(Some("in")).read(12);
        let body = expvar();
        assert!(
            body.contains(
                r#""stats":{"inbound":{"in":{"uplink":12,"downlink":0}},"outbound":{},"user":{}}"#
            ),
            "{body}"
        );
        assert!(body.ends_with(r#""observatory":null}"#), "{body}");
        crate::stats::clear();
    }

    #[test]
    fn the_expvar_body_carries_the_live_observatory_status() {
        let _guard = crate::stats::test_lock();
        set_observatory(Some(crate::observatory::Observatory::seeded(&[
            crate::router::Observed {
                tag: "proxy".to_owned(),
                alive: true,
                delay_ms: 42,
                health: Some(crate::router::HealthPing {
                    all: 10,
                    fail: 1,
                    deviation: 2,
                    average: 3,
                }),
                last_error: String::new(),
                last_seen: 1_700_000_000,
                last_try: 1_700_000_001,
            },
        ])));
        let body = expvar();
        assert!(
            body.contains(
                r#""observatory":{"proxy":{"alive":true,"delay":42,"outbound_tag":"proxy","last_seen_time":1700000000,"last_try_time":1700000001,"health_ping":{"all":10,"fail":1,"deviation":2,"average":3}}}"#
            ),
            "{body}"
        );
        set_observatory(None);
    }

    #[test]
    fn prometheus_names_escape_a_quote() {
        assert_eq!(escape("a\"b"), "a\\\"b");
    }
}

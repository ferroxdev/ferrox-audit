use crate::conn::{parse_target, Connection, Listener};
use std::collections::{HashMap, HashSet};
#[cfg(windows)]
use std::io::IoSliceMut;
use std::io::{IoSlice, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use lane_pool::Next;

use crate::budgets::{
    self, ACCOUNT_ATTEMPTS, CARRIER_DEAD_SECS, RELAY_HANDOFF_SPINS, RELAY_IDLE, RELAY_LOCK_TRIES,
    RELAY_MOVING_READS, RELAY_POLL, SESSION_POLL,
};
use crate::config::{
    inbound_carrier, inbound_reality_config, inbound_tls_identity, outbound_carrier,
    outbound_reality, outbound_tls, server_fallbacks, stream_security, tls_ca_roots, trojan_key,
    uuid_bytes, vless_security_supported, Carrier, Fallback, FallbackNetwork,
};
use crate::json::Json;
use ferrox_core::failure::{Failure, Kind, Ladder, Rung, Stage};
#[cfg(test)]
use ferrox_core::tls::RecordAlignment as _;
use ferrox_core::tls::{Edges, Stream, TlsProvider as _};
use ferrox_core::vless::{Flow, Target};

pub(crate) fn print_version() {
    println!("ferrox-app {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

/// Published edges as JSON rows on stdout: the catalogue is public, so the list needs no config, account or lane. `--ping` adds the handshake time, and a null is an edge that did not answer.
pub(crate) fn print_foxy_edges(ping: bool) {
    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let readings = ping.then(|| crate::foxy_latency::readings(&edges));
    for (index, edge) in edges.iter().enumerate() {
        if let Some(readings) = &readings {
            println!(
                "{}",
                foxy_edge_row(edge, readings.get(index).copied().flatten())
            );
        } else {
            println!(
                "{{\"host\":\"{}\",\"port\":{},\"city\":\"{}\",\"country\":\"{}\"}}",
                edge.host, edge.port, edge.city, edge.country
            );
        }
    }
}

/// The measured row a pinged listing prints: a number of milliseconds, or the null an unanswered edge earns.
fn foxy_edge_row(edge: &ferrox_core::foxy::Candidate, reading: Option<u64>) -> String {
    let ms = reading.map_or_else(|| "null".to_owned(), |ms| ms.to_string());
    format!(
        "{{\"host\":\"{}\",\"port\":{},\"city\":\"{}\",\"country\":\"{}\",\"ms\":{ms}}}",
        edge.host, edge.port, edge.city, edge.country
    )
}

pub(crate) fn serve_json(label: &str, body: &str, test: bool) -> ! {
    let root = crate::json::parse(body)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root, None, test)
}

/// Xray's own wire form; the pinned scenario suite spawns this binary with `-config=stdin: -format=pb`.
pub(crate) fn serve_protobuf(label: &str, bytes: &[u8], test: bool) -> ! {
    let (root, seed) = crate::xray_pb::to_json_seeded(bytes)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    serve_root(label, &root, Some(&seed), test)
}

/// The listen addresses an inbound names: every port its `port` field expands, on the
/// `listen` host, or the `unix` path standing in for both. An empty answer is an inbound
/// naming no socket, which the caller skips; a datagram carrier keeps the IP address by
/// the same rule.
fn inbound_addresses(inbound: &Json) -> Vec<String> {
    #[cfg(unix)]
    {
        let unix_path = inbound
            .get("unix")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty());
        if let Some(path) = unix_path {
            return vec![format!("unix:{path}")];
        }
    }
    let Some(field) = inbound.get("port") else {
        return Vec::new();
    };
    let ports = inbound_ports(field);
    if ports.is_empty() {
        return Vec::new();
    }
    let host = inbound
        .get("listen")
        .and_then(Json::as_str)
        .filter(|listen| !listen.is_empty())
        .unwrap_or("0.0.0.0");
    ports
        .into_iter()
        .map(|port| format!("{host}:{port}"))
        .collect()
}

/// The ports a `port` field names, in the forms the reference `PortList` accepts: a JSON
/// number, a plain or `"env:NAME"`-sourced decimal string, an `"a-b"` range expanded to
/// every port in it, and comma-separated combinations of those.
fn inbound_ports(field: &Json) -> Vec<u16> {
    if let Some(port) = field.as_port() {
        return vec![port];
    }
    let Some(spec) = field.as_str() else {
        return Vec::new();
    };
    let mut ports = Vec::new();
    for piece in spec.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let env_value = piece
            .strip_prefix("env:")
            .and_then(|name| std::env::var(name).ok());
        if piece.starts_with("env:") && env_value.is_none() {
            eprintln!(
                "env `{}` in the port list is unset, so its piece names no port",
                &piece[4..]
            );
            continue;
        }
        let piece = env_value.as_deref().unwrap_or(piece);
        let (from, to) = piece.split_once('-').unwrap_or((piece, piece));
        let (Ok(from), Ok(to)) = (from.parse::<u16>(), to.parse::<u16>()) else {
            eprintln!("port piece `{piece}` is not a port the reference names; piece skipped");
            continue;
        };
        if from > to {
            eprintln!("port range `{piece}` descends, piece skipped");
            continue;
        }
        ports.extend(from..=to);
    }
    ports
}

/// The address and port dokodemo-door rewrites every flow to, each half optional so the
/// flow's own local address can fill what the config omits.
#[derive(Clone, Debug, Default)]
struct DokodemoRewrite {
    host: Option<String>,
    port: Option<u16>,
}

impl DokodemoRewrite {
    fn from_config(inbound: &Json) -> Self {
        let Some(settings) = inbound.get("settings") else {
            return Self::default();
        };
        let host = settings
            .get("address")
            .or_else(|| settings.get("rewriteAddress"))
            .and_then(Json::as_str)
            .map(str::to_owned);
        let port = settings
            .get("port")
            .and_then(Json::as_port)
            .filter(|port| *port != 0)
            .or_else(|| settings.get("rewritePort").and_then(Json::as_port))
            .filter(|port| *port != 0);
        Self { host, port }
    }

    /// The target a followed flow falls back to: only what the config spelled, with no
    /// local address to complete it, because the reference fills from the flow alone.
    fn configured(&self) -> Option<Destination> {
        let host = self.host.as_deref()?;
        Some(dokodemo_destination(host, self.port.unwrap_or(0)))
    }

    /// The target a non-followed flow asks for: the config's half, or the flow's own
    /// address half, completed by a `portMap` entry for the flow's local port.
    fn resolved(
        &self,
        local: Option<SocketAddr>,
        port_map: &HashMap<String, DokodemoPortMapEntry>,
    ) -> Destination {
        let host = self
            .host
            .as_deref()
            .unwrap_or_else(|| dokodemo_default_host(local));
        let port = self
            .port
            .or_else(|| local.map(|local| local.port()))
            .unwrap_or(0);
        let mut dest = dokodemo_destination(host, port);
        let key = local
            .map(|local| local.port().to_string())
            .unwrap_or_default();
        if let Some(entry) = port_map.get(&key) {
            if let Some(host) = entry.host.as_deref() {
                dest = dokodemo_destination(host, dest.port());
            }
            if let Some(port) = entry.port {
                dest = dokodemo_with_port(&dest, port);
            }
        }
        dest
    }
}

/// xray's fallback when the config names no address: the loopback of the flow's family,
/// or `localhost` when the local address did not parse.
fn dokodemo_default_host(local: Option<SocketAddr>) -> &'static str {
    match local {
        Some(local) if local.ip().to_canonical().is_ipv4() => "127.0.0.1",
        Some(_) => "::1",
        None => "localhost",
    }
}

/// One host and port in xray's own spelling, with a bracketed IPv6 literal unwrapped.
fn dokodemo_destination(host: &str, port: u16) -> Destination {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => Destination::Address(SocketAddr::new(ip, port)),
        Err(_) => Destination::Name(host.to_owned(), port),
    }
}

fn dokodemo_with_port(dest: &Destination, port: u16) -> Destination {
    match dest {
        Destination::Name(host, _) => Destination::Name(host.clone(), port),
        Destination::Address(address) => Destination::Address(SocketAddr::new(address.ip(), port)),
    }
}

/// The networks dokodemo-door is told to carry; the reference defaults an absent list to
/// tcp and lets `network` alone override its older `allowedNetwork` spelling.
fn dokodemo_networks(inbound: &Json) -> Vec<&str> {
    let Some(settings) = inbound.get("settings") else {
        return vec!["tcp"];
    };
    let named = match settings.get("network") {
        Some(Json::Null) | None => settings.get("allowedNetwork"),
        named => named,
    };
    match named {
        Some(Json::Arr(items)) => items.iter().filter_map(Json::as_str).collect(),
        Some(Json::Str(network)) => network.split(',').collect(),
        _ => vec!["tcp"],
    }
}

fn dokodemo_has(networks: &[&str], network: &str) -> bool {
    networks
        .iter()
        .any(|named| named.eq_ignore_ascii_case(network))
}

/// The reference carries `userLevel` on the inbound's user; the door applies it as the
/// accepted stream's policy level.
fn dokodemo_user_level(inbound: &Json) -> u32 {
    inbound
        .get("settings")
        .and_then(|settings| settings.get("userLevel"))
        .and_then(Json::as_u32)
        .unwrap_or(0)
}

#[allow(clippy::too_many_lines)]
fn serve_root(label: &str, root: &Json, seed: Option<&crate::xray_pb::Seed>, test: bool) -> ! {
    // Sized before the first lane, so every flow from here reads the ceiling its role named.
    if dials_a_proxy(root) {
        lane_pool::mark_proxy_peer();
    }
    // Armed before the first inbound opens, so every flow from here reads the budget the operator named.
    crate::budgets::apply_config(
        &crate::config::budgets(root)
            .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}"))),
    );
    crate::dnsapp::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    crate::policy::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    if let Some(policy) = seed.and_then(|seed| seed.policy.clone()) {
        crate::policy::install_config(policy);
    }
    crate::stats::install(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    let geodata = install_file_apps(root, test)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    install_default_outbound_tag(root);
    let freedom = has_protocol(root, "outbounds", "freedom");
    let configured = find_outbound_with(root, test)
        .unwrap_or_else(|reason| exit(&format!("bad config {label}: {reason}")));
    // A loopback outbound names its inbound by tag, so it resolves only when no concrete dial won.
    let loopback = find_loopback_outbound(root);
    let outbound = match configured.clone() {
        Some(Outbound::Freedom(_)) | None if loopback.is_some() => {
            let tag = loopback.expect("guarded by is_some");
            Some(
                resolve_loopback(root, &tag, freedom).unwrap_or_else(|reason| {
                    exit(&format!("bad config {label}: loopback {reason}"))
                }),
            )
        }
        selected => selected,
    };
    if let Some(Outbound::Freedom(freedom)) = &outbound {
        let _ = DIRECT_FREEDOM.set(Arc::clone(freedom));
    }
    // Named only when no outbound was built, so the reason behind an exit that names nothing is on its own line first.
    let refused = outbound.is_none().then(|| diagnose_outbounds(root));
    let portals =
        reverse_portals(root).unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    let routing = routing_for(root)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")))
        .or_else(|| {
            geodata
                .as_ref()
                .filter(|geodata| !geodata.outbound().is_empty())
                .map(|_| crate::router::Routing::empty())
        });
    let observatory = start_observatory(root, test)
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    crate::metrics::set_observatory(observatory.clone());
    let api_config = match seed.and_then(|seed| seed.api.clone()) {
        Some(config) => Some(config),
        None => crate::commander::ApiConfig::from_json(root),
    };
    let api = api_config.map(crate::commander::Api::new);
    if let Some(api) = api.as_ref() {
        match seed {
            Some(seed) => api.seed_outbounds(&seed.outbounds),
            None => api.seed_json_outbounds(root),
        }
    }
    let route = routing.map(|routing| {
        route_shared_with_api(
            root,
            routing,
            &portals,
            observatory.clone(),
            api.as_ref(),
            configured.as_ref(),
            geodata.as_ref().map(crate::geodata::Config::outbound),
        )
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")))
    });
    if let Some(observatory) = &observatory {
        crate::observatory::spawn(root, observatory, route.as_ref())
            .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    }
    if let Some(api) = api.as_ref() {
        wire_api(
            api,
            observatory,
            Runtime::new(
                outbound.clone(),
                route.clone(),
                freedom,
                Arc::clone(&portals),
            ),
            test,
        )
        .unwrap_or_else(|error| exit(&format!("bad config {label}: {error}")));
    }
    if !test {
        if let Some(geodata) = geodata {
            crate::geodata::start(geodata, route.clone(), outbound.clone(), root.clone());
        }
        install_dns_route(route.clone(), outbound.as_ref());
        start_bridges(root, outbound.as_ref(), route.as_ref());
    }
    let inbounds = serve_inbounds_counted(
        label,
        root,
        outbound.as_ref(),
        route.as_ref(),
        true,
        freedom,
        &portals,
        api.as_deref(),
        seed,
        test,
        false,
    );
    if inbounds == 0 {
        match refused.as_deref().unwrap_or(&[]).first() {
            Some(reason) => exit(&format!("bad config {label}: {reason}")),
            None => exit(&format!("no servable inbound in {label}")),
        }
    }
    if test {
        println!("Configuration OK.");
        std::process::exit(0);
    }
    if ["XRAY_VLESS_FULL_BINARY", "XRAY_HYSTERIA_BINARY"]
        .iter()
        .any(|seam| std::env::var_os(seam).is_some())
    {
        // The startup record both pinned interop harnesses scan the server log for; not this binary's name.
        println!("ferrox-app serving; harness readiness token: core: Xray 26.11.9 started");
    }
    loop {
        thread::park();
        report_dial_failures();
    }
}

/// The observatory a config names; `-test` proves both blocks parse without starting either probe loop.
fn start_observatory(
    root: &Json,
    test: bool,
) -> Result<Option<Arc<crate::observatory::Observatory>>, String> {
    if test {
        crate::observatory::validate(root).map(|()| None)
    } else {
        crate::observatory::configure(root)
    }
}

/// The file-backed apps and the `geodata` block: `-test` parses them without opening or creating anything the reference also leaves alone.
fn install_file_apps(root: &Json, test: bool) -> Result<Option<crate::geodata::Config>, String> {
    let geodata = crate::geodata::parse(root, &crate::router::asset_dirs())?;
    if test {
        crate::metrics::parse(root)?;
        crate::accesslog::parse(root)?;
    } else {
        crate::metrics::install(root)?;
        crate::accesslog::install(root)?;
    }
    Ok(geodata)
}

/// Attach the runtime a management call drives, then listen for it; `-test` skips the listener.
fn wire_api(
    api: &Arc<crate::commander::Api>,
    observatory: Option<Arc<crate::observatory::Observatory>>,
    runtime: Runtime,
    test: bool,
) -> Result<(), String> {
    api.set_observatory(observatory);
    api.set_runtime(Arc::new(runtime));
    if !test {
        api.serve_listen()?;
    }
    Ok(())
}

/// One inbound's lane: a route plan when the config carries rules, else the single configured outbound.
fn routed_out(
    outbound: Option<&Outbound>,
    route: Option<&Arc<RouteShared>>,
    inbound: &Json,
    source_known: bool,
) -> Option<Outbound> {
    match route {
        Some(shared) => Some(Outbound::Route(Arc::new(RoutePlan::new(
            Arc::clone(shared),
            inbound_tag(inbound),
            inbound_name(inbound),
            source_known,
        )))),
        None => outbound.cloned(),
    }
}

/// Opens every inbound the config names, proving each server inbound's rules at startup, and reports
/// how many opened and whether a hysteria inbound wants the readiness token.
fn inbound_sniffing(inbound: &Json, label: &str) -> Option<Arc<crate::sniff::Sniffing>> {
    crate::sniff::parse(inbound.get("sniffing")).unwrap_or_else(|error| {
        exit(&format!(
            "bad config {label}: inbound {} sniffing {error}",
            inbound_tag(inbound).as_deref().unwrap_or("<untagged>")
        ))
    })
}

fn refuse_source(
    route: Option<&Arc<RouteShared>>,
    inbound: &Json,
    label: &str,
    kind: &str,
    prove: bool,
) -> bool {
    let Some(shared) = route else {
        return false;
    };
    let tag = inbound_tag(inbound);
    let Some(selector) = shared
        .routing
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .source_refusal(tag.as_deref())
    else {
        return false;
    };
    let message = format!(
        "bad config {label}: {} inbound {} names `{selector}`, which a {kind} flow cannot answer",
        canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or("")),
        tag.as_deref().unwrap_or("<untagged>")
    );
    if prove {
        exit(&message);
    }
    eprintln!("{message}");
    true
}

/// Whether this inbound's xHTTP carrier is the QUIC one, decided the way the listener decides it:
/// xHTTP, TLS with a loadable identity, and an ALPN list of exactly `h3`. Only then does the
/// dispatcher register a stop the listener will actually signal.
fn inbound_is_xhttp_h3(inbound: &Json) -> bool {
    if !matches!(inbound_carrier(inbound), Carrier::Xhttp { .. })
        || crate::config::stream_security(inbound) != "tls"
        || crate::config::inbound_tls_identity(inbound).is_none()
    {
        return false;
    }
    let alpn = inbound
        .get("streamSettings")
        .and_then(|stream| stream.get("tlsSettings"))
        .and_then(|tls| tls.get("alpn"));
    let names: Vec<&str> = match alpn {
        Some(Json::Str(single)) if !single.is_empty() => vec![single],
        Some(Json::Arr(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .filter(|name| !name.is_empty())
            .collect(),
        _ => return false,
    };
    names.as_slice() == ["h3"]
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn serve_inbounds_counted(
    label: &str,
    root: &Json,
    outbound: Option<&Outbound>,
    route: Option<&Arc<RouteShared>>,
    prove: bool,
    freedom: bool,
    portals: &crate::reverse::Portals,
    api: Option<&crate::commander::Api>,
    seed: Option<&crate::xray_pb::Seed>,
    test: bool,
    fallible: bool,
) -> usize {
    let routed =
        |inbound: &Json, source_known: bool| routed_out(outbound, route, inbound, source_known);
    let mut inbounds = 0;
    let configured = configured_emails(root);
    if let Some(list) = root.get("inbounds").and_then(Json::as_arr) {
        for inbound in list {
            let protocol =
                canonical_protocol(inbound.get("protocol").and_then(Json::as_str).unwrap_or(""));
            // The reference expands a port list and datagram carrier to one listener per port.
            let Some(addresses) = serve_addresses(inbound, protocol) else {
                continue;
            };
            // `-test` takes an ephemeral loopback port so the one a running instance holds is never touched.
            let listening = test.then(|| {
                addresses
                    .iter()
                    .map(|address| {
                        if address.is_empty() {
                            String::new()
                        } else {
                            "127.0.0.1:0".to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
            });
            let bind = listening.as_ref().unwrap_or(&addresses);
            if !inbound_served(protocol) {
                refuse_inbound(protocol, label, inbound);
                continue;
            }
            if prove {
                if let Some(shared) = route {
                    prove_server_route(shared, inbound, label);
                }
            }
            register_inbound_sniffing(inbound, label, &addresses);
            let handler_stop = api.map(|_| Arc::new(Stop::new()));
            let handler_tag = inbound_tag(inbound);
            let handler_raw = seed.and_then(|seed| {
                let tag = handler_tag.as_deref().unwrap_or_default();
                seed.inbounds
                    .iter()
                    .find(|(candidate, _)| candidate == tag)
                    .map(|(_, raw)| raw.clone())
            });
            let mut handler_stops: Vec<(Arc<Stop>, String)> = Vec::new();
            let vmess_users = (protocol == "vmess").then(|| {
                let make = || inbound_vmess_users(inbound);
                let users = match (route, handler_tag.as_deref()) {
                    (Some(shared), Some(tag)) => shared.vmess_users(tag, make),
                    _ => make(),
                };
                if let Some(shared) = route {
                    shared.restrict_user_portals(handler_tag.as_deref(), &users);
                }
                users
            });
            let before = inbounds;
            let h3_stop = if inbound_is_xhttp_h3(inbound) {
                handler_stop.as_ref()
            } else {
                None
            };
            for address in bind {
                match protocol {
                    "vless" => {
                        if serve_vless_inbound(
                            address,
                            inbound,
                            freedom,
                            label,
                            portals,
                            handler_stop.as_ref(),
                        ) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "trojan" => {
                        if serve_trojan_inbound(address, inbound, freedom, handler_stop.as_ref()) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "vmess" => {
                        let users = vmess_users.as_ref().expect("a vmess table");
                        if serve_vmess_inbound_users(
                            address,
                            inbound,
                            freedom,
                            handler_stop.as_ref().map(Arc::clone),
                            users,
                        ) {
                            if let Some(stop) = &handler_stop {
                                if !matches!(
                                    inbound_carrier(inbound),
                                    Carrier::Kcp(_)
                                        | Carrier::Xdrive { .. }
                                        | Carrier::Quic
                                        | Carrier::Hysteria(_)
                                ) {
                                    handler_stops.push((Arc::clone(stop), address.clone()));
                                }
                            }
                            inbounds += 1;
                        }
                    }
                    "shadowsocks" => {
                        if serve_shadowsocks_inbound(
                            address,
                            inbound,
                            freedom,
                            &configured,
                            handler_stop.as_ref(),
                        ) {
                            if let Some(stop) = h3_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "hysteria" => {
                        if serve_hysteria_inbound(address, inbound, freedom, label) {
                            inbounds += 1;
                        }
                    }
                    "tuic" => {
                        if crate::tuic::serve_inbound(
                            address,
                            inbound,
                            label,
                            freedom,
                            handler_stop.clone(),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "anytls" => {
                        if crate::anytls::serve_inbound(
                            address,
                            inbound,
                            label,
                            freedom,
                            handler_stop.clone(),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "socks" | "http" | "mixed" => {
                        let Some(out) = routed(inbound, true) else {
                            eprintln!(
                                "inbound `{protocol}` in {label} names no outbound to carry it"
                            );
                            continue;
                        };
                        // A front with no tcp carrier has no chain to arm, so the inbound is refused rather than served unmasked.
                        if crate::config::has_tcp_mask(inbound.get("streamSettings")) {
                            eprintln!("inbound `{protocol}` in {label} asks for a finalmask tcp chain it cannot arm");
                            continue;
                        }
                        let accounts = Arc::new(if protocol == "http" {
                            http_accounts(inbound)
                        } else {
                            socks_accounts(inbound)
                        });
                        let role = match protocol {
                            "http" => Role::Http { out, accounts },
                            "socks" => Role::Socks { out, accounts },
                            _ => Role::Mixed { out, accounts },
                        };
                        spawn_role(address, inbound_role(inbound, role), inbound_tag(inbound));
                        inbounds += 1;
                    }
                    "dokodemo-door" => {
                        if let Some(out) = routed(inbound, true) {
                            let (armed, tcp) = serve_dokodemo(
                                address,
                                inbound,
                                &out,
                                label,
                                handler_stop.as_ref(),
                                fallible,
                            );
                            inbounds += armed;
                            if tcp && !dokodemo_has(&dokodemo_networks(inbound), "udp") {
                                if let Some(stop) = &handler_stop {
                                    handler_stops.push((Arc::clone(stop), address.clone()));
                                }
                            }
                        }
                    }
                    "hc" => {
                        if serve_hc_inbound(address, inbound) {
                            inbounds += 1;
                        }
                    }
                    "blackhole" => {
                        if serve_blackhole_inbound(
                            address,
                            inbound,
                            label,
                            handler_stop.as_ref().map(Arc::clone),
                        ) {
                            if let Some(stop) = &handler_stop {
                                handler_stops.push((Arc::clone(stop), address.clone()));
                            }
                            inbounds += 1;
                        }
                    }
                    "tun" => {
                        // A tun flow has no source or local address, so a reaching rule that names one is refused here.
                        if refuse_source(route, inbound, label, "tun", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        let spec = match tun_spec(inbound) {
                            Ok(spec) => spec,
                            Err(error) => {
                                eprintln!("tun inbound: {error}");
                                continue;
                            }
                        };
                        // `-test` proves the device spec without opening an interface the reference also leaves closed.
                        if test {
                            #[cfg(not(target_os = "linux"))]
                            if tun_stack(inbound) == "system" {
                                eprintln!("tun inbound: the system tun stack is Linux-only");
                                continue;
                            }
                            inbounds += 1;
                        } else if serve_tun_inbound(&spec, inbound, &out, address) {
                            inbounds += 1;
                        }
                    }
                    "wireguard" => {
                        if refuse_source(route, inbound, label, "tunnel", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        match crate::wg::serve_inbound(inbound, &out, address) {
                            Ok(_) => inbounds += 1,
                            Err(reason) => eprintln!("wireguard inbound {address}: {reason}"),
                        }
                    }
                    "masque" => {
                        if refuse_source(route, inbound, label, "MASQUE", prove) {
                            continue;
                        }
                        let Some(out) = routed(inbound, false) else {
                            continue;
                        };
                        match crate::masque::serve_inbound(inbound, &out, address) {
                            Ok(_) => inbounds += 1,
                            Err(reason) => eprintln!("masque inbound {address}: {reason}"),
                        }
                    }
                    _ => eprintln!("unsupported inbound protocol `{protocol}` in {label}"),
                }
            }
            if !prove && inbounds > before {
                if let Some(networks) = server_networks(inbound) {
                    if let Some(shared) = route {
                        shared.record_server_inbound(
                            handler_tag.clone(),
                            &networks,
                            portal_inbound(protoc
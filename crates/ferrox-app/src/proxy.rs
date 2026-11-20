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
            .or_else(|| settings.get("rewritePort").and_th
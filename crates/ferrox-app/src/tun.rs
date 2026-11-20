//! The native TUN device inbound: opens a virtual interface, reads IP packets, turns each TCP
//! flow into a proxy dial through `serve_connect` and each UDP flow into a datagram dial through
//! a SOCKS5 UDP association — the same two entries every other front reaches, no second dialer.
//!
//! Byte-identity: a TUN carries no wire byte-stream to diff, so this row's identity claim is
//! the (target, payload) dial-set differential — the set of (destination, payload) pairs the
//! inbound produces from a given packet stream must match the pinned reference. Proven by
//! the loopback test set; the oracle lives in `scripts/tun-oracle`.
//!
//! Platform opens: the `tun-rs` builder on Linux and macOS, or an inherited descriptor
//! (`FERROX_TUN_FD`). The privileged opens are compile-checked only — no CI runner holds
//! `CAP_NET_ADMIN` — while the inherited-fd path runs fully in tests.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, UdpSocket};
#[cfg(any(not(unix), test))]
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};
use std::sync::{mpsc, Arc, Mutex};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::budgets;
use crate::conn::Connection;
use ferrox_core::foxy::connectip::{
    icmp_echo_reply, ipv4_checksum, ipv4_head, ipv6_head, pseudo_header_checksum, tcp_checksum,
    udp_datagram, udp_head, UdpDatagram, IPV4_HEADER, IPV6_HEADER, PROTOCOL_UDP, UDP_HEADER,
};

const DEFAULT_MTU: usize = 1500;
/// The largest IP packet a device can carry.
const MAX_PACKET: usize = u16::MAX as usize;
/// The head of a framed datagram: the RSV/FRAG prefix and the widest address (IPv6 plus its port). The payload stays the device's buffer and is handed to the socket by pointer.
const FRAME_CAP: usize = 3 + 1 + 16 + 2;
const TCP_PROTO: u8 = 6;
const ICMP_PROTO: u8 = 1;
const ICMPV6_PROTO: u8 = 58;
/// An ICMP echo request is type 8 (128 over IPv6); its answer flips that to 0 (129) and carries the message back.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// A path-MTU report carries no usable MTU below the version's smallest link, and no TCP segment is worth less than this.
const IPV4_SMALLEST_MTU: u32 = 576;
const IPV6_SMALLEST_MTU: u32 = 1280;
const SMALLEST_MSS: u32 = 48;
#[cfg(all(test, unix))]
const ICMP_ECHO_REPLY: u8 = 0;
#[cfg(test)]
const ICMPV6_ECHO_REPLY: u8 = 129;
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

const VIRTIO_NET_HDR_LEN: usize = 10;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const UTUN_HEADER_LEN: usize = 4;
const UTUN_AF_INET: u8 = 2;
const UTUN_AF_INET6: u8 = 30;

/// How a descriptor frames a packet: raw IP, the macOS utun family word, or the Linux virtio header that carries GSO and checksum offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // the variants are platform-specific; each build constructs only its own
enum Framing {
    Raw,
    Utun,
    Virtio,
}

impl Framing {
    const fn header_len(self) -> usize {
        match self {
            Self::Raw => 0,
            Self::Utun => UTUN_HEADER_LEN,
            Self::Virtio => VIRTIO_NET_HDR_LEN,
        }
    }
}

pub(crate) fn is_device(protocol: &str) -> bool {
    matches!(protocol, "tun" | "utun" | "wintun" | "tun2socks")
}

const DEFAULT_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
const DEFAULT_PREFIX: u8 = 15;
const DEFAULT_PREFIX_V6: u8 = 64;
const MAX_QUEUES: usize = 4;

pub(crate) struct Spec {
    name: String,
    mtu: usize,
    /// Every address the config names, the first being the one `address()` and `prefix()` hand a single-address caller.
    addresses: Vec<(IpAddr, u8)>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    queues: usize,
    udp_idle: std::time::Duration,
    endpoint_independent_nat: bool,
    gso: bool,
}

impl Spec {
    pub(crate) fn new(name: Option<&str>, mtu: Option<usize>) -> Self {
        Self::with(name, mtu, None, None, None)
    }

    pub(crate) fn with(
        name: Option<&str>,
        mtu: Option<usize>,
        address: Option<IpAddr>,
        prefix: Option<u8>,
        queues: Option<usize>,
    ) -> Self {
        let address = address.unwrap_or(DEFAULT_ADDRESS);
        let prefix = prefix.unwrap_or_else(|| default_prefix(address));
        // macOS only accepts `utunN`, and the reference lets the system name its own device; elsewhere the stable name keeps a restart on the same interface.
        let name = name.filter(|n| !n.is_empty()).map_or_else(
            || {
                if cfg!(target_os = "macos") {
                    String::new()
                } else {
                    "ferrox0".to_owned()
                }
            },
            str::to_owned,
        );
        Self {
            name,
            mtu: mtu.filter(|m| *m > 0).unwrap_or(DEFAULT_MTU),
            addresses: vec![(address, prefix)],
            queues: queues.unwrap_or_else(default_queues),
            udp_idle: budgets::udp_idle(),
            endpoint_independent_nat: false,
            gso: true,
        }
    }

    /// The datagram idle budget: the reference's `udp_timeout`, or the tree's own when unset.
    pub(crate) fn with_udp_idle(mut self, idle: std::time::Duration) -> Self {
        self.udp_idle = idle;
        self
    }

    /// One datagram leg per client source rather than one per source-and-destination pair.
    pub(crate) fn with_endpoint_independent_nat(mut self, on: bool) -> Self {
        self.endpoint_independent_nat = on;
        self
    }

    /// A `gso: false` config opens the device without the TCP offloads, one packet per read.
    pub(crate) fn with_gso(mut self, on: bool) -> Self {
        self.gso = on;
        self
    }

    pub(crate) fn udp_idle(&self) -> std::time::Duration {
        self.udp_idle
    }

    pub(crate) fn endpoint_independent_nat(&self) -> bool {
        self.endpoint_independent_nat
    }

    /// The rest of the config's addresses: the device gets every one of them, so a config that names a second address is not narrowed.
    pub(crate) fn with_addresses(mut self, addresses: Vec<(IpAddr, u8)>) -> Self {
        if !addresses.is_empty() {
            self.addresses = addresses;
        }
        self
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn gso(&self) -> bool {
        self.gso
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn mtu(&self) -> usize {
        self.mtu
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn address(&self) -> IpAddr {
        self.addresses[0].0
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn prefix(&self) -> u8 {
        self.addresses[0].1
    }

    pub(crate) fn addresses(&self) -> &[(IpAddr, u8)] {
        &self.addresses
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn queues(&self) -> usize {
        self.queues
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.mtu > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tun mtu {} exceeds 65535", self.mtu),
            ));
        }
        for (address, prefix) in &self.addresses {
            let max_prefix = if address.is_ipv6() { 128 } else { 32 };
            if *prefix > max_prefix {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("tun prefix /{prefix} is outside /0../{max_prefix} for {address}"),
                ));
            }
        }
        let max_queues = if cfg!(target_os = "linux") {
            MAX_QUEUES
        } else {
            1
        };
        if self.queues == 0 || self.queues > max_queues {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tun queues {} is outside 1..={max_queues} on this platform",
                    self.queues
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn default_queues() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(MAX_QUEUES))
    } else {
        1
    }
}

/// The prefix a family gets when a config names only the address.
pub(crate) fn default_prefix(address: IpAddr) -> u8 {
    if address.is_ipv6() {
        DEFAULT_PREFIX_V6
    } else {
        DEFAULT_PREFIX
    }
}

/// Split `address[/prefix]` and let an explicit `prefix` fill a missing CIDR.
pub(crate) fn parse_address(
    value: Option<&str>,
    prefix: Option<u32>,
) -> Result<(Option<IpAddr>, Option<u8>), String> {
    let explicit = match prefix {
        Some(prefix) => Some(
            u8::try_from(prefix)
                .map_err(|_| format!("tun prefix /{prefix} is outside /0../128"))?,
        ),
        None => None,
    };
    let Some(value) = value else {
        if let Some(prefix) = explicit {
            if prefix > 32 {
                return Err(format!(
                    "tun prefix /{prefix} is outside /0../32 for the default IPv4 address"
                ));
            }
        }
        return Ok((None, explicit));
    };
    let (address, cidr) = match value.split_once('/') {
        Some((address, prefix)) => (
            address,
            Some(
                prefix
                    .parse::<u8>()
                    .map_err(|_| format!("tun address `{value}` has an invalid prefix"))?,
            ),
        ),
        None => (value, None),
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("tun address `{value}` is not an IP address"))?;
    let prefix = cidr.or(explicit);
    if let Some(prefix) = prefix {
        let max_prefix = if address.is_ipv6() { 128 } else { 32 };
        if prefix > max_prefix {
            return Err(format!(
                "tun prefix /{prefix} is outside /0../{max_prefix} for {address}"
            ));
        }
    }
    Ok((Some(address), prefix))
}

#[derive(Debug, Clone, Copy)]
struct TcpHead<'a> {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &'a [u8],
}

/// The shift a SYN's window-scale option asks for (RFC 7323), or `None` when it carries none; a shift past fourteen is taken as fourteen, because that is the largest scale the option can carry.
fn window_shift(options: &[u8]) -> Option<u8> {
    const END: u8 = 0;
    const NOP: u8 = 1;
    const WINDOW_SCALE: u8 = 3;
    let mut at = 0;
    while at < options.len() {
        match options[at] {
            END => break,
            NOP => at += 1,
            kind => {
                let len = usize::from(*options.get(at + 1)?);
                if len < 2 {
                    return None;
                }
                let end = at.checked_add(len)?;
                if end > options.len() {
                    return None;
                }
                if kind == WINDOW_SCALE && len == 3 {
                    return Some(options[at + 2].min(14));
                }
                at = end;
            }
        }
    }
    None
}

/// A server initial sequence no peer can predict, with the clock as the fallback when the OS has no entropy.
fn initial_sequence(client: u32) -> u32 {
    let mut raw = [0u8; 4];
    if getrandom::fill(&mut raw).is_ok() {
        return u32::from_ne_bytes(raw);
    }
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    client ^ clock.rotate_left(13) ^ std::process::id().rotate_left(7)
}

/// The MSS a SYN offers, or `None` when it carries none or a malformed one.
fn peer_mss(options: &[u8]) -> Option<u32> {
    const END: u8 = 0;
    const NOP: u8 = 1;
    const MSS: u8 = 2;
    let mut at = 0;
    while at < options.len() {
        match options[at] {
            END => break,
            NOP => at += 1,
            kind => {
                let len = usize::from(*options.get(at + 1)?);
                if len < 2 {
                    return None;
                }
                let end = at.checked_add(len)?;
                if end > options.len() {
                    return None;
                }
                if kind == MSS && len == 4 {
                    let mss = u32::from(u16::from_be_bytes([options[at + 2], options[at + 3]]));
                    return (mss != 0).then_some(mss);
                }
                at = end;
            }
        }
    }
    None
}

/// The windows we advertise are scaled by this shift: five turns the sixteen-bit field into two mebibytes, past the band-delay product of the fastest link the bench drives and no further than the upstream socket holds.
const OUR_WINDOW_SHIFT: u8 = 5;

/// The SYN-ACK options: the MSS this device can receive, and — only when the peer's SYN carried a scale — the window scale that lifts both directions past sixty-four kilobytes.
fn syn_ack_options(mss: u32, scale: bool) -> ([u8; 8], usize) {
    let mut options = [0u8; 8];
    options[0] = 2;
    options[1] = 4;
    options[2..4].copy_from_slice(&u16::try_from(mss.max(1)).unwrap_or(u16::MAX).to_be_bytes());
    if scale {
        options[4..8].copy_from_slice(&[1, 3, 3, OUR_WINDOW_SHIFT]);
    }
    let len = if scale { 8 } else { 4 };
    (options, len)
}

fn tcp_head(body: &[u8]) -> Option<(TcpHead<'_>, &[u8])> {
    if body.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([body[0], body[1]]);
    let destination_port = u16::from_be_bytes([body[2], body[3]]);
    let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let ack_num = u32::from_be_bytes(body[8..12].try_into().unwrap());
    let window = u16::from_be_bytes([body[14], body[15]]);
    let data_offset = usize::from(body[12] >> 4) * 4;
    if data_offset < 20 || data_offset > body.len() {
        return None;
    }
    let flags = body[13];
    Some((
        TcpHead {
            source_port,
            destination_port,
            seq,
            ack_num,
            flags,
            window,
            options: &body[20..data_offset],
        },
        &body[data_offset..],
    ))
}

/// Whether an ICMP body is an echo request the handler answers: the version's request type, code 0, and at least the eight-byte header. A reply, another code or a truncated message is refused.
fn is_echo_request(protocol: u8, body: &[u8]) -> bool {
    let request = match protocol {
        ICMP_PROTO => ICMP_ECHO_REQUEST,
        ICMPV6_PROTO => ICMPV6_ECHO_REQUEST,
        _ => return false,
    };
    body.len() >= 8 && body[0] == request && body[1] == 0
}

/// One IP packet read in place, whichever version carried it.
#[derive(Debug, Clone, Copy)]
struct IpHead {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
}

/// Walk an IPv4 or IPv6 packet, including the IPv6 extension headers this handler can skip, and hand back the transport body borrowed from the read buffer.
fn ip_head(packet: &[u8]) -> Option<(IpHead, &[u8])> {
    if let Some((ip, body)) = ipv4_head(packet) {
        if packet[6] & 0x3f != 0 || packet[7] != 0 {
            return None;
        }
        return Some((
            IpHead {
                source: IpAddr::V4(Ipv4Addr::from(ip.source)),
                destination: IpAddr::V4(Ipv4Addr::from(ip.destination)),
                protocol: ip.protocol,
            },
            body,
        ));
    }
    let (ip, body) = ipv6_head(packet)?;
    let (protocol, body) = walk_extensions(ip.next_header, body)?;
    Some((
        IpHead {
            source: IpAddr::V6(Ipv6Addr::from(ip.source)),
            destination: IpAddr::V6(Ipv6Addr::from(ip.destination)),
            protocol,
        },
        body,
    ))
}

/// Skip the IPv6 extension headers this handler can walk, handing back the transport protocol and its slice.
fn walk_extensions(mut protocol: u8, mut body: &[u8]) -> Option<(u8, &[u8])> {
    loop {
        match protocol {
            0 | 43 | 60 => {
                if body.len() < 8 {
                    return None;
                }
                let size = (usize::from(body[1]) + 1) * 8;
                if size > body.len() {
                    return None;
                }
                protocol = body[0];
                body = &body[size..];
            }
            51 => {
                if body.len() < 2 {
                    return None;
                }
                let size = (usize::from(body[1]) + 2) * 4;
                if size < 12 || size > body.len() {
                    return None;
                }
                protocol = body[0];
                body = &body[size..];
            }
            // A fragment is not reassembled here, and an encrypted payload is not this handler's.
            44 | 50 | 59 => return None,
            _ => return Some((protocol, body)),
        }
    }
}

/// The flow a quoted packet names, read from the header plus the eight transport bytes an ICMP error carries. The quote is the packet this handler wrote to the device — remote to client — so its source is the flow's destination, its destination the flow's source, and its two ports reversed. The quoted total length is usually larger than what arrived, so this does not ask the full-packet walk to accept it.
fn quoted_flow(quoted: &[u8]) -> Option<(FlowKey, u32)> {
    let first = *quoted.first()?;
    let (protocol, remote, client, transport) = if first >> 4 == 4 {
        let header = usize::from(first & 0x0f) * 4;
        if header < IPV4_HEADER || header > quoted.len() {
            return None;
        }
        let remote = *quoted.get(12..16)?.first_chunk::<4>()?;
        let client = *quoted.get(16..20)?.first_chunk::<4>()?;
        (
            *quoted.get(9)?,
            IpAddr::V4(Ipv4Addr::from(remote)),
            IpAddr::V4(Ipv4Addr::from(client)),
            quoted.get(header..)?,
        )
    } else if first >> 4 == 6 {
        if quoted.len() < IPV6_HEADER {
            return None;
        }
        let remote = *quoted.get(8..24)?.first_chunk::<16>()?;
        let client = *quoted.get(24..40)?.first_chunk::<16>()?;
        let (protocol, transport) = walk_extensions(*quoted.get(6)?, quoted.get(IPV6_HEADER..)?)?;
        (
            protocol,
            IpAddr::V6(Ipv6Addr::from(remote)),
            IpAddr::V6(Ipv6Addr::from(client)),
            transport,
        )
    } else {
        return None;
    };
    if protocol != TCP_PROTO || transport.len() < 8 {
        return None;
    }
    let seq = u32::from_be_bytes(transport[4..8].try_into().ok()?);
    Some((
        FlowKey {
            source: client,
            source_port: u16::from_be_bytes([transport[2], transport[3]]),
            destination: remote,
            destination_port: u16::from_be_bytes([transport[0], transport[1]]),
        },
        seq,
    ))
}

/// The flow a v4 or v6 ICMP error quotes, when the quoted segment is TCP this handler carried: type 3 over v4, type 1 and packet-too-big type 2 over v6.
fn icmp_error_flow(protocol: u8, body: &[u8]) -> Option<(FlowKey, u32)> {
    let quoted = match (protocol, body.first().copied()) {
        (ICMP_PROTO, Some(3)) | (ICMPV6_PROTO, Some(1 | 2)) => body.get(8..)?,
        _ => return None,
    };
    quoted_flow(quoted)
}

/// The path MTU a packet-too-big message reports: v4 fragmentation-needed (type 3 code 4) or v6 type 2, clamped to the smallest link each version allows.
fn reported_mtu(protocol: u8, body: &[u8]) -> Option<u32> {
    match (protocol, body.first().copied()) {
        (ICMP_PROTO, Some(3)) if body.get(1) == Some(&4) => {
            let mtu = u32::from(u16::from_be_bytes(body.get(6..8)?.try_into().ok()?));
            Some(mtu.max(IPV4_SMALLEST_MTU))
        }
        (ICMPV6_PROTO, Some(2)) => {
            let mtu = u32::from_be_bytes(body.get(4..8)?.try_into().ok()?);
            Some(mtu.max(IPV6_SMALLEST_MTU))
        }
        _ => None,
    }
}

/// The segment size a path MTU leaves after the IP and TCP headers, never below the floor the references believe.
fn path_mss(mtu: u32, ipv6: bool) -> u32 {
    let header = if ipv6 {
        (IPV6_HEADER + 20) as u32
    } else {
        (IPV4_HEADER + 20) as u32
    };
    mtu.saturating_sub(header).max(SMALLEST_MSS)
}

/// How much a response read may take: one segment without offload, the whole buffer when the descriptor can split a GSO packet.
fn read_limit(gso: bool, mss: usize, room: usize) -> usize {
    if gso {
        room
    } else {
        mss.min(room)
    }
}

/// How long a queue waits for an answer that follows its own upload: an echo replies inside this window on this bench's own p50, and past it the response thread's read is the cheaper waiter, so a queue that carries a second flow holds it for less.
const PING_PONG_SPIN: std::time::Duration = std::time::Duration::from_micros(40);

/// Answers in a row that may miss before a flow stops waiting: a conversation answers inside the window every time, where a bulk upload's peer never does, and paying the wait four times once costs a flow less than a millisecond.
const PING_PONG_MISSES: u32 = 4;

/// Emit one segment an upstream read already landed in `buf[body..body + n]` and whose sequence the reader reserved under its gate, returning the cursor it carried. The response thread and the queue's inline serve share it, so the GSO split and the bytes cannot drift apart; bytes a device did not accept are consumed and cannot be re-read, so a refusal is an error both callers end the flow on.
#[allow(clippy::too_many_arguments)]
fn emit_upstream(
    flow: &Flow,
    buf: &mut [u8],
    n: usize,
    seq: u32,
    gso_capable: bool,
    max: usize,
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    write: impl FnOnce(&[u8], bool) -> io::Result<bool>,
) -> io::Result<u32> {
    let head = ip_header_len(src.0, dst.0).ok_or(io::ErrorKind::InvalidInput)?;
    let body = head + 20;
    let gso = gso_capable && n > max;
    let ack = flow.rcv_nxt.load(Relaxed);
    if !render_tcp_headers_ip(
        src,
        dst,
        seq,
        ack,
        FLAG_PSH | FLAG_ACK,
        65535,
        &[],
        n,
        gso,
        &mut buf[..body + n],
    ) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    match write(&buf[..body + n], gso) {
        Ok(true) => Ok(ack),
        Ok(false) => Err(io::ErrorKind::WriteZero.into()),
        Err(error) => Err(error),
    }
}

/// One upstream segment for the response thread, with its sequence already reserved: the dequeue, the reservation and the room the peer's window leaves all sit inside the stream's gate, so a queue serving the same stream cannot take the earlier bytes, number them later, or spend a window this read already counted. A socket with nothing queued parks the thread on its descriptor rather than in the clock, and `None` says the window shut under the park, so the caller waits on the next ack instead.
#[cfg(unix)]
fn read_upstream(
    flow: &Flow,
    gate: &Mutex<()>,
    reader: &mut Connection,
    buf: &mut [u8],
    cap: usize,
    budget: std::time::Duration,
    snd_nxt: &AtomicU32,
) -> io::Result<Option<(usize, u32)>> {
    loop {
        let read = {
            let _gated = gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match flow.send.room_now(snd_nxt) {
                None | Some(0) => Ok(None),
                Some(room) => reader
                    .read_ready(&mut buf[..cap.min(room as usize)])
                    .map(|n| {
                        let seq = snd_nxt.load(Relaxed);
                        Some(if n == 0 {
                            (n, seq)
                        } else {
                            (n, snd_nxt.fetch_add(n as u32, Relaxed))
                        })
                    }),
            }
        };
        match read {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if reader.wait_readable(budget)? {
                    continue;
                }
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            other => return other,
        }
    }
}

/// The same read on a host without a per-call non-blocking one: the queue never serves inline there, so the thread's own blocking read is the only reader and its socket timeout is the clock.
#[cfg(not(unix))]
fn read_upstream(
    _flow: &Flow,
    _gate: &Mutex<()>,
    reader: &mut Connection,
    buf: &mut [u8],
    cap: usize,
    _budget: std::time::Duration,
    snd_nxt: &AtomicU32,
) -> io::Result<Option<(usize, u32)>> {
    let n = reader.read(&mut buf[..cap])?;
    Ok(Some((n, snd_nxt.fetch_add(n as u32, Relaxed))))
}

/// What a queue's inline serve did with a flow's answer: nothing was ready, one segment left and carried this cursor, or the bytes left the stream and the device took neither, which ends the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Served {
    None,
    Ack(u32),
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

/// One datagram flow, keyed the same way as a stream flow: both endpoints, because two clients can pick the same source port towards the same target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

/// A flow a thread has left: its entry goes at the next packet, so the packet path pays nothing for the reap.
enum Ended {
    Stream(FlowKey, u64),
    Datagram(UdpKey, u64),
}

/// A TUN device: a file descriptor carrying IP packets, with the framing its platform puts in front of each one.
pub(crate) struct Device {
    handle: std::fs::File,
    mtu: usize,
    framing: Framing,
    /// The builder enabled `TUN_F_TSO4|TUN_F_TSO6`; an inherited descriptor's `IFF_VNET_HDR` says nothing about that.
    gso: bool,
}

impl Device {
    /// One device per configured queue; every handler reads its own queue and passes the same flow table, so a segment that lands on another queue still finds its flow.
    pub(crate) fn open_all(spec: &Spec) -> io::Result<Vec<Self>> {
        if let Some(handle) = inherited_handle() {
            let framing = inherited_framing(&handle);
            return Ok(vec![Self {
                handle,
                mtu: spec.mtu,
                framing,
                gso: false,
            }]);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::IntoRawFd;
            let (devices, offload) = open_linux(spec, spec.queues().max(1))?;
            let framing = if offload {
                Framing::Virtio
            } else {
                Framing::Raw
            };
            Ok(devices
                .into_iter()
                .map(|device| Self {
                    handle: unsafe { std::fs::File::from_raw_fd(device.into_raw_fd()) },
                    mtu: spec.mtu,
                    framing,
                    gso: offload,
                })
                .collect())
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::IntoRawFd;
            let (device, _, _) = crate::tun_stack::build(spec, false, true)?;
            let handle = unsafe { std::fs::File::from_raw_fd(device.into_raw_fd()) };
            Ok(vec![Self {
                handle,
                mtu: spec.mtu,
                framing: Framing::Utun,
                gso: false,
            }])
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no TUN platform open; set FERROX_TUN_FD for an inherited descriptor",
        ))
    }

    pub(crate) fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let head = self.framing.header_len();
        if head == 0 {
            return self.handle.read(buf);
        }
        #[cfg(unix)]
        {
            let mut header = [0u8; VIRTIO_NET_HDR_LEN];
            let mut iov = [
                libc::iovec {
                    iov_base: header.as_mut_ptr().cast(),
                    iov_len: head,
                },
                libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.len(),
                },
            ];
            loop {
                let n = unsafe { libc::readv(self.handle.as_raw_fd(), iov.as_mut_ptr(), 2) };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                return Ok((n as usize).saturating_sub(head));
            }
        }
        #[cfg(not(unix))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "framed TUN reads need a unix descriptor",
        ))
    }

    /// Whether another packet is already waiting on the device, so a queue with work serves it instead of waiting on one flow's answer: one `poll` with no timeout, and nothing on a host whose descriptor cannot say.
    #[cfg(unix)]
    fn readable_now(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut row = libc::pollfd {
            fd: self.handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one descriptor this handler owns, one element in the array, and the call writes only `revents`.
        unsafe { libc::poll(&raw mut row, 1, 0) > 0 && (row.revents & libc::POLLIN) != 0 }
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<bool> {
        write_framed(&mut self.handle, self.framing, None, packet)
    }

    pub(crate) fn clone_writer(&self) -> io::Result<PacketWriter> {
        Ok(PacketWriter {
            handle: self.handle.try_clone()?,
            framing: self.framing,
            gso: self.gso,
        })
    }

    /// A packet tunnel's descriptor: the reference dups it, closes it on exec, and makes it nonblocking.
    pub(crate) fn from_inherited(fd: i32, mtu: usize) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let duplicated = unsafe { libc::dup(fd) };
            if duplicated < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { libc::fcntl(duplicated, libc::F_SETFD, libc::FD_CLOEXEC) };
            let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(duplicated, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }
            let handle = unsafe { std::fs::File::from_raw_fd(duplicated) };
            Ok(Self {
                framing: inherited_framing(&handle),
                handle,
                mtu,
                gso: false,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (fd, mtu);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "packet tunnel needs a Unix descriptor",
            ))
        }
    }

    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.handle.as_raw_fd()
    }

    #[cfg(not(unix))]
    pub(crate) fn raw_fd(&self) -> i32 {
        -1
    }

    fn mss(&self, remote: IpAddr) -> u32 {
        let header = if remote.is_ipv6() {
            IPV6_HEADER + 20
        } else {
            IPV4_HEADER + 20
        };
        self.mtu.saturating_sub(header).max(1) as u32
    }

    #[cfg(all(test, unix))]
    fn from_handle(handle: std::fs::File, mtu: usize) -> Self {
        Self {
            handle,
            mtu,
            framing: Framing::Raw,
            gso: false,
        }
    }
}

/// A flow's writer: the descriptor clone plus the framing an emit owes it.
pub(crate) struct PacketWriter {
    handle: std::fs::File,
    framing: Framing,
    gso: bool,
}

impl PacketWriter {
    pub(crate) fn write_packet(&mut self, packet: &[u8]) -> io::Result<bool> {
        write_framed(&mut self.handle, self.framing, None, packet)
    }

    fn write_gso(&mut self, packet: &[u8], mss: u16) -> io::Result<bool> {
        write_framed(&mut self.handle, self.framing, Some(mss), packet)
    }

    fn gso(&self) -> bool {
        self.gso
    }
}

/// The virtio header a GSO packet needs: native-endian fields, checksum offload from the TCP header, and the segment size the kernel splits at.
fn virtio_header(packet: &[u8], gso: Option<u16>) -> [u8; VIRTIO_NET_HDR_LEN] {
    let mut header = [0u8; VIRTIO_NET_HDR_LEN];
    let Some(mss) = gso else {
        return header;
    };
    let ip_header = if packet.first().is_some_and(|byte| byte >> 4 == 6) {
        IPV6_HEADER
    } else {
        IPV4_HEADER
    };
    header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header[1] = if ip_header == IPV6_HEADER {
        VIRTIO_NET_HDR_GSO_TCPV6
    } else {
        VIRTIO_NET_HDR_GSO_TCPV4
    };
    header[2..4].copy_from_slice(&(ip_header as u16 + 20).to_ne_bytes());
    header[4..6].copy_from_slice(&mss.to_ne_bytes());
    header[6..8].copy_from_slice(&(ip_header as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&16u16.to_ne_bytes());
    header
}

/// One packet write with the descriptor's framing in front of it, all-or-nothing: a full write is carried, a short or refused write is dropped.
fn write_framed(
    handle: &mut std::fs::File,
    framing: Framing,
    gso: Option<u16>,
    packet: &[u8],
) -> io::Result<bool> {
    match framing {
        Framing::Raw => write_packet_to(handle, packet),
        Framing::Utun => {
            let family = if packet.first().is_some_and(|byte| byte >> 4 == 6) {
                UTUN_AF_INET6
            } else {
                UTUN_AF_INET
            };
            write_pair(handle, &[0, 0, 0, family], packet)
        }
        Framing::Virtio => write_pair(handle, &virtio_header(packet, gso), packet),
    }
}

/// One framed packet in one writev, so the header and payload reach the device as one packet. A short write drops the packet rather than sending its tail as another.
fn write_pair<W: Write>(writer: &mut W, header: &[u8], packet: &[u8]) -> io::Result<bool> {
    let total = header.len() + packet.len();
    let parts = [std::io::IoSlice::new(header), std::io::IoSlice::new(packet)];
    loop {
        match writer.write_vectored(&parts) {
            Ok(written) if written == total => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if crate::tun_stack::refused(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

/// One packet write, all-or-nothing: a full write is carried, a short or refused write is dropped.
fn write_packet_to<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<bool> {
    loop {
        match writer.write(packet) {
            Ok(written) if written == packet.len() => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if crate::tun_stack::refused(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

/// The framing an inherited descriptor already carries, read from the descriptor rather than the environment: a Linux TUN reports its virtio header, and a macOS utun always has its family word.
#[cfg(target_os = "linux")]
fn inherited_framing(handle: &std::fs::File) -> Framing {
    const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
    const IFF_VNET_HDR: libc::c_short = 0x4000;
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = IfReq {
        ifr_name: [0; 16],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    if unsafe { libc::ioctl(handle.as_raw_fd(), TUNGETIFF as _, &mut req) } < 0 {
        return Framing::Raw;
    }
    if req.ifr_flags & IFF_VNET_HDR != 0 {
        Framing::Virtio
    } else {
        Framing::Raw
    }
}

#[cfg(target_os = "macos")]
fn inherited_framing(_handle: &std::fs::File) -> Framing {
    Framing::Utun
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inherited_framing(_handle: &std::fs::File) -> Framing {
    Framing::Raw
}

fn inherited_handle() -> Option<std::fs::File> {
    let fd_str = std::env::var_os("FERROX_TUN_FD")?;
    let fd: i32 = fd_str.to_str()?.parse().ok()?;
    if fd < 3 {
        return None;
    }
    #[cfg(unix)]
    return Some(unsafe { std::fs::File::from_raw_fd(fd) });
    #[cfg(not(unix))]
    {
        let _ = fd;
        None
    }
}

/// A Linux open refused the optional offload, so the same spec is retried without it.
#[cfg(target_os = "linux")]
fn open_linux(spec: &Spec, queues: usize) -> io::Result<(Vec<tun_rs::SyncDevice>, bool)> {
    match build_queues(spec, queues) {
        Ok(found) => Ok(found),
        // A kernel without `IFF_MULTI_QUEUE`, or a clone the interface refused: serve the one queue the platform gives.
        Err(_) if queues > 1 => build_queues(spec, 1),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn build_queues(spec: &Spec, queues: usize) -> io::Result<(Vec<tun_rs::SyncDevice>, bool)> {
    let multi = queues > 1;
    let (device, offload) = match crate::tun_stack::build(spec, multi, spec.gso()) {
        Ok((device, true, _)) => {
            // The kernel enabled UDP segment offload with the TCP ones; the handler does not split an aggregate, so the device is narrowed before its name is released for the plain rebuild.
            if crate::tun_stack::tcp_only_offload(&device) {
                (device, true)
            } else {
                drop(device);
                let (device, _, _) = crate::tun_stack::build(spec, multi, false)?;
                (device, false)
            }
        }
        Ok((device, false, _)) => (device, false),
        Err(error) if offload_refused(&error) => {
            let (device, _, _) = crate::tun_stack::build(spec, multi, false)?;
            (device, false)
        }
        Err(error) => return Err(error),
    };
    let mut devices = Vec::with_capacity(queues);
    for _ in 1..queues {
        devices.push(device.try_clone()?);
    }
    devices.push(device);
    Ok((devices, offload))
}

#[cfg(target_os = "linux")]
fn offload_refused(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    ) || matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EOPNOTSUPP || code == libc::ENOTSUP
    )
}

/// The pseudo-header checksum a GSO segment carries into the kernel: the field holds the folded sum before the segment, and the kernel folds the payload onto it.
fn partial_tcp_checksum(source: IpAddr, destination: IpAddr, tcp_len: usize) -> u16 {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo_header_checksum(&source.octets(), &destination.octets(), TCP_PROTO, tcp_len)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo_header_checksum(&source.octets(), &destination.octets(), TCP_PROTO, tcp_len)
        }
        _ => 0,
    }
}

fn write_tcp_checksum(source: IpAddr, destination: IpAddr, partial: bool, out: &mut [u8]) {
    let ip_header = if source.is_ipv6() {
        IPV6_HEADER
    } else {
        IPV4_HEADER
    };
    let tcp_len = out.len() - ip_header;
    let field = ip_header + 16;
    // Both fields hold the pseudo-header sum in network order; the offload one leaves the segment for the kernel to add and complete.
    let value = if partial {
        partial_tcp_checksum(source, destination, tcp_len)
    } else {
        let (source, destination) = octets(source, destination);
        tcp_checksum(&source, &destination, &out[ip_header..])
    };
    out[field..field + 2].copy_from_slice(&value.to_be_bytes());
}

fn addr_octets(address: IpAddr) -> ([u8; 16], usize) {
    let mut bytes = [0u8; 16];
    match address {
        IpAddr::V4(address) => {
            bytes[..4].copy_from_slice(&address.octets());
            (bytes, 4)
        }
        IpAddr::V6(address) => {
            bytes.copy_from_slice(&address.octets());
            (bytes, 16)
        }
    }
}

fn octets(source: IpAddr, destination: IpAddr) -> ([u8; 16], [u8; 16]) {
    (addr_octets(source).0, addr_octets(destination).0)
}

/// The IP header length a source and destination share, or `None` when the families disagree.
fn ip_header_len(src: IpAddr, dst: IpAddr) -> Option<usize> {
    match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Some(IPV4_HEADER),
        (IpAddr::V6(_), IpAddr::V6(_)) => Some(IPV6_HEADER),
        _ => None,
    }
}

/// Write the IP and TCP headers in front of a segment whose payload already sits at `head..`
/// and checksum it in place. The response thread reads the relay's socket straight into that
/// hole, so a response byte is written to the device where it landed instead of being copied
/// into a second buffer. A GSO render leaves the TCP field as the pseudo-header sum the kernel completes.
#[allow(clippy::too_many_arguments)]
fn render_tcp_headers_ip(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload_len: usize,
    partial: bool,
    out: &mut [u8],
) -> bool {
    let (src_ip, src_port) = src;
    let (dst_ip, dst_port) = dst;
    let Some(head) = ip_header_len(src_ip, dst_ip) else {
        return false;
    };
    // The data path carries no options and its payload already sits behind a twenty-byte header; the handshake pads its options to a word.
    if !options.len().is_multiple_of(4) || options.len() > 40 {
        return false;
    }
    let tcp_len = 20 + options.len() + payload_len;
    if out.len() < head + tcp_len {
        return false;
    }
    if head == IPV4_HEADER {
        let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src_ip, dst_ip) else {
            return false;
        };
        out[..IPV4_HEADER].fill(0);
        out[0] = 0x45;
        out[2..4].copy_from_slice(&((IPV4_HEADER + tcp_len) as u16).to_be_bytes());
        out[6] = 0x40;
        out[8] = 64;
        out[9] = TCP_PROTO;
        out[12..16].copy_from_slice(&src_ip.octets());
        out[16..20].copy_from_slice(&dst_ip.octets());
        let c = ipv4_checksum(&out[..IPV4_HEADER]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
    } else {
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src_ip, dst_ip) else {
            return false;
        };
        out[..IPV6_HEADER].fill(0);
        out[0] = 0x60;
        out[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        out[6] = TCP_PROTO;
        out[7] = 64;
        out[8..24].copy_from_slice(&src_ip.octets());
        out[24..40].copy_from_slice(&dst_ip.octets());
    }
    let tcp = &mut out[head..head + 20];
    tcp.fill(0);
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack_num.to_be_bytes());
    tcp[12] = (((20 + options.len()) / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    out[head + 20..head + 20 + options.len()].copy_from_slice(options);
    write_tcp_checksum(src_ip, dst_ip, partial, &mut out[..head + tcp_len]);
    true
}

/// Render one IP/TCP packet into `out` — the caller's reused buffer — copying `payload` behind headers built in place. The control path (SYN-ACK, ACK, FIN/RST) carries no payload and uses this; a data response reaches `render_tcp_headers_ip` with its payload already in the buffer.
#[allow(clippy::too_many_arguments)]
fn render_tcp_packet_ip(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
    partial: bool,
    out: &mut Vec<u8>,
) {
    let Some(head) = ip_header_len(src.0, dst.0) else {
        return;
    };
    let header = head + 20 + options.len();
    crate::proxy::resize_scratch(out, header + payload.len());
    out[header..].copy_from_slice(payload);
    let rendered = render_tcp_headers_ip(
        src,
        dst,
        seq,
        ack_num,
        flags,
        window,
        options,
        payload.len(),
        partial,
        out,
    );
    if !rendered {
        out[..header].fill(0);
    }
}

/// Render one IPv4/TCP packet with no offload, the shape the caller's tests and the v4-only path already exercised.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn render_tcp_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    render_tcp_packet_ip(
        (IpAddr::from(src.0), src.1),
        (IpAddr::from(dst.0), dst.1),
        seq,
        ack_num,
        flags,
        window,
        &[],
        payload,
        false,
        out,
    );
}

/// An ICMP echo request answered as the device's own destination would: the shared renderer
/// flips the type, swaps the addresses and recomputes both checksums into the caller's reused
/// `out`, so a ping storm allocates nothing per reply. `src` and `dst` are the reply's, the
/// request's the other way round.
fn render_icmp_reply_ip(src: IpAddr, dst: IpAddr, request: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let _ = icmp_echo_reply(dst, src, request, out);
}

#[cfg(test)]
fn render_icmp_reply(src: [u8; 4], dst: [u8; 4], request: &[u8], out: &mut Vec<u8>) {
    render_icmp_reply_ip(IpAddr::from(src), IpAddr::from(dst), request, out);
}

/// Test-only: the render pair behind a fresh vector, so a caller that only wants to inspect one packet need not thread a buffer. Production emits reach the device through `render_*_packet` into a reused buffer.
#[cfg(test)]
fn build_tcp_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    render_tcp_packet(src, dst, seq, ack_num, flags, window, payload, &mut out);
    out
}

#[cfg(all(test, unix))]
#[allow(clippy::too_many_arguments)]
fn build_tcp_packet_options(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    render_tcp_packet_ip(
        (IpAddr::from(src.0), src.1),
        (IpAddr::from(dst.0), dst.1),
        seq,
        ack_num,
        flags,
        window,
        options,
        payload,
        false,
        &mut out,
    );
    out
}

#[cfg(test)]
fn build_icmp_reply(src: [u8; 4], dst: [u8; 4], request: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    render_icmp_reply(src, dst, request, &mut out);
    out
}

#[cfg(test)]
fn build_ipv6_tcp_packet(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    render_tcp_packet_ip(
        src,
        dst,
        seq,
        ack_num,
        flags,
        window,
        &[],
        payload,
        false,
        &mut out,
    );
    out
}

/// The peer's send window for one flow: the highest sequence it acknowledged and the room it advertises, so the response thread stalls instead of overrunning a receive buffer and losing segments this handler cannot retransmit. Both fields share one word, so a reader never pairs the cursor of one ACK with the window of another.
struct SendWindow {
    /// `una << 32 | window`, the window in bytes after the peer's shift.
    state: AtomicU64,
    closed: AtomicBool,
    parked: AtomicBool,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl SendWindow {
    fn new(una: u32, window: u32) -> Self {
        Self {
            state: AtomicU64::new((u64::from(una) << 32) | u64::from(window)),
            closed: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            thread: std::sync::OnceLock::new(),
        }
    }

    /// Fold one device ACK into the window, already scaled by the shift the peer offered; a stale number never moves the cursor, and a zero-window probe still opens the window.
    fn acked(&self, ack: u32, window: u32, sent: u32) {
        let mut state = self.state.load(SeqCst);
        loop {
            let una = (state >> 32) as u32;
            if ack.wrapping_sub(una) >= 1u32 << 31 {
                break;
            }
            // An ACK past what the device has been handed names bytes it never received; the next one carries the truth.
            let cursor = if sent.wrapping_sub(ack) < 1u32 << 31 {
                ack
            } else {
                una
            };
            let next = (u64::from(cursor) << 32) | u64::from(window);
            match self
                .state
                .compare_exchange_weak(state, next, SeqCst, SeqCst)
            {
                Ok(_) => break,
                Err(seen) => state = seen,
            }
        }
        self.wake();
    }

    #[cfg(test)]
    fn cursor(&self) -> u32 {
        (self.state.load(SeqCst) >> 32) as u32
    }

    fn close(&self) {
        self.closed.store(true, SeqCst);
        self.wake();
    }

    fn wake(&self) {
        if self.parked.swap(false, SeqCst) {
            if let Some(thread) = self.thread.get() {
                thread.unpark();
            }
        }
    }

    /// Room the peer's window leaves right now; `None` when the flow ended or a silent peer kept the window shut past the idle budget.
    fn room(&self, sent: &AtomicU32) -> Option<u32> {
        // The clock is only read when the window is shut: an open window returns without a syscall per segment.
        let mut deadline = None;
        loop {
            if self.closed.load(SeqCst) {
                return None;
            }
            let state = self.state.load(SeqCst);
            let inflight = sent.load(SeqCst).wrapping_sub((state >> 32) as u32);
            if inflight < state as u32 {
                return Some(state as u32 - inflight);
            }
            self.parked.store(true, SeqCst);
            // Re-read after publishing the park flag so an ACK that lands in between is not lost.
            let state = self.state.load(SeqCst);
            let inflight = sent.load(SeqCst).wrapping_sub((state >> 32) as u32);
            let window = state as u32;
            if self.closed.load(SeqCst) {
                self.parked.store(false, SeqCst);
                return None;
            }
            if inflight < window {
                self.parked.store(false, SeqCst);
                continue;
            }
            let now = std::time::Instant::now();
            let deadline = *deadline.get_or_insert(now + budgets::udp_idle());
            if now >= deadline {
                self.parked.store(false, SeqCst);
                return None;
            }
            if self.thread.get().is_some() {
                std::thread::park_timeout(deadline - now);
            }
            self.parked.store(false, SeqCst);
        }
    }

    /// Room the peer's window leaves right now, the queue's non-blocking reading of the same state: a shut window answers zero here where `room` would park for the ack that opens it.
    fn room_now(&self, sent: &AtomicU32) -> Option<u32> {
        if self.closed.load(SeqCst) {
            return None;
        }
        let state = self.state.load(SeqCst);
        let inflight = sent.load(SeqCst).wrapping_sub((state >> 32) as u32);
        Some((state as u32).saturating_sub(inflight))
    }
}

/// One active TCP flow's state. The two cursors are shared with the response
/// thread: `rcv_nxt` advances as the handler delivers payload to the proxy, and
/// `snd_nxt` advances as the response thread sends payload out, so a pure ACK
/// carries both numbers truthfully.
struct Flow {
    /// The generation this entry was inserted at, so a late reaper cannot remove a replacement with the same tuple.
    id: u64,
    /// The client's initial sequence, so a retransmitted SYN replays the handshake instead of minting a second flow.
    isn: u32,
    /// The server's initial sequence, drawn independently of the client's so a blind forger cannot predict it.
    server_isn: u32,
    /// The shift the peer offered for its own receive window in the SYN, so each ACK's window field is read in bytes.
    peer_shift: u8,
    /// Answers in a row that did not arrive inside the queue's wait, so an upload whose peer speaks once a segment stops paying it and a ping-pong keeps it.
    misses: AtomicU32,
    /// The upload half, installed once the lane is live: a direct dial or the loopback pair's device end. A retransmitted SYN waits for it instead of replaying a handshake no lane carries yet.
    write_half: Mutex<Option<Connection>>,
    rcv_nxt: Arc<AtomicU32>,
    snd_nxt: Arc<AtomicU32>,
    /// Payload reached the proxy since the response thread's last idle expiry: a flow is alive when either direction spoke inside the budget.
    busy: Arc<AtomicBool>,
    last_acked: AtomicU32,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    /// The largest payload the response thread may put in one segment; a path-MTU report lowers it.
    mss: Arc<AtomicU32>,
    /// The peer's advertised window, updated from every ACK, so a download stalls at the receive buffer instead of flooding past it.
    send: Arc<SendWindow>,
    /// One close packet — `FIN` or `RST` — leaves per flow, whichever thread sees the end first.
    signaled: Arc<AtomicBool>,
    /// Held across one dequeue and the sequence it publishes, by whichever thread reads: the queue serving an answer and the response thread waiting on the same stream would otherwise number the two segments out of stream order.
    read_gate: Mutex<()>,
    /// The device's `FIN` reached the upload half, so a response thread waiting on a direct lane
    /// whose download closed first can finish the flow.
    upload_finished: UploadFinished,
}

/// The upload's half-close, signalled from the handler to a response thread that ended the
/// download first: a direct lane's upstream may close only its write direction, and the flow
/// lives until the device's own `FIN` or the stall budget names it dead.
#[derive(Default)]
struct UploadFinished {
    state: Mutex<UploadState>,
    wake: std::sync::Condvar,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum UploadState {
    #[default]
    Live,
    Finished,
}

impl UploadFinished {
    fn finish(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = UploadState::Finished;
        self.wake.notify_all();
    }

    /// Wait for the upload's `FIN` up to `budget`, and answer whether it arrived.
    fn wait(&self, budget: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *state == UploadState::Live {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self
                .wake
                .wait_timeout(state, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// The relay function the TUN handler calls per TCP flow: takes the proxied Connection, the lane
/// the dial already resolved for a fallback flow, and the destination from the packet headers. An
/// error means the proxy leg was refused, so the device's established flow is reset rather than
/// left silent.
pub(crate) type Relay = Arc<
    dyn Fn(Connection, Option<&crate::proxy::Lane>, crate::proxy::Destination) -> io::Result<()>
        + Send
        + Sync,
>;

/// The direct dial: a lane that reaches its edge with the destination alone hands the handler the
/// connected stream, so a device flow owes no loopback pair and no second thread.
pub(crate) type Dial = Arc<dyn Fn(&crate::proxy::Destination) -> DialOutcome + Send + Sync>;

/// What a direct dial found: a stream the device speaks through, a lane the front's own
/// `serve_connect` has to carry over the loopback pair (already resolved, so it is not picked
/// twice), or a target the edge refused.
pub(crate) enum DialOutcome {
    Direct(Connection),
    Fallback(crate::proxy::Lane),
    Refused,
}

/// The device's datagram dial: the SOCKS5 association the outbound's own server answers, opened
/// once and ridden by every leg, so a device datagram crosses no loopback association and no
/// second SOCKS server. `None` keeps the front-served association.
pub(crate) type Datagram = crate::proxy::Datagram;

/// The datagram entry the TUN handler rides per UDP flow: handed the client half of an association, it runs the same SOCKS5 UDP server the SOCKS inbound reaches, `serve_socks_udp`.
pub(crate) type Associate = Arc<dyn Fn(Connection) + Send + Sync>;

/// The device's one association: the control leg stays open for its life, as every other SOCKS front's does, and `relay` is where every flow's framed datagram is sent.
struct Association {
    control: Connection,
    relay: SocketAddr,
}

impl Association {
    /// Associate over a loopback pair and read the relay address off the reply: the
    /// reply is the ten bytes a SOCKS5 server writes for a `UDP ASSOCIATE`, so the
    /// outbound's UDP arms cannot tell a device from a proxy client.
    fn open(associate: &Associate) -> io::Result<Self> {
        let associate = Arc::clone(associate);
        let association =
            crate::proxy::udp_association(move |conn| associate(conn)).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the association refused its address type",
                )
            })?;
        Ok(Self {
            control: association.control,
            relay: association.relay,
        })
    }
}

/// The flow table every queue reads: one entry per tuple, so a segment that lands on a queue other than the one the handshake opened still finds its flow instead of stalling it.
#[derive(Clone)]
pub(crate) struct Flows {
    table: Arc<Mutex<HashMap<FlowKey, Arc<Flow>>>>,
    ids: Arc<AtomicU64>,
    ended_tx: mpsc::Sender<Ended>,
    ended_rx: Arc<Mutex<mpsc::Receiver<Ended>>>,
}

impl Default for Flows {
    fn default() -> Self {
        let (ended_tx, ended_rx) = mpsc::channel();
        Self {
            table: Arc::default(),
            ids: Arc::default(),
            ended_tx,
            ended_rx: Arc::new(Mutex::new(ended_rx)),
        }
    }
}

impl Flows {
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<FlowKey, Arc<Flow>>> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Relaxed)
    }

    fn reap(&self, legs: &Legs) {
        let Ok(rx) = self.ended_rx.lock() else {
            return;
        };
        while let Ok(ended) = rx.try_recv() {
            match ended {
                Ended::Stream(key, id) => {
                    let mut table = self.table();
                    if table.get(&key).is_some_and(|flow| flow.id == id) {
                        table.remove(&key);
                    }
                }
                Ended::Datagram(key, id) => {
                    let mut table = legs.table();
                    if table.get(&key).is_some_and(|leg| leg.id == id) {
                        table.remove(&key);
                    }
                }
            }
        }
    }
}

/// One leg in the shared datagram table: its id, the socket that frames its datagrams, and the
/// direct relay it was opened for, so a dead control drops only the legs that rode that relay.
struct Leg {
    id: u64,
    socket: Arc<UdpSocket>,
    relay: Option<SocketAddr>,
}

/// The datagram table every queue reads: one leg per tuple, so a client's packets that hash to
/// different queues still ride the one socket the association opened.
type LegTable = HashMap<UdpKey, Leg>;

#[derive(Clone, Default)]
pub(crate) struct Legs {
    table: Arc<Mutex<LegTable>>,
    ids: Arc<AtomicU64>,
}

impl Legs {
    fn table(&self) -> std::sync::MutexGuard<'_, LegTable> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Relaxed)
    }

    #[cfg(all(test, unix))]
    fn len(&self) -> usize {
        self.table().len()
    }

    #[cfg(all(test, unix))]
    fn relay_of(&self, key: &UdpKey) -> Option<SocketAddr> {
        self.table().get(key).and_then(|leg| leg.relay)
    }
}

/// The TUN handler: reads packets, relays each TCP flow and each UDP flow through the proxy outbound.
pub(crate) struct Handler {
    device: Device,
    relay: Relay,
    associate: Associate,
    /// The lanes this front can reach without the loopback pair; a flow the dial falls back on keeps the pair.
    dial: Option<Dial>,
    /// The outbound's own datagram association, when its lane has one the handler can ride directly.
    datagram: Option<Datagram>,
    flows: Flows,
    legs: Legs,
    frame: Vec<u8>,
    /// Reused render buffer for every device-bound packet this thread emits (SYN-ACK, pure ACK, ICMP reply), so the emit path allocates nothing in steady state.
    emit: Vec<u8>,
    /// The inline serve's buffer: sized once to one read's worth and never cleared, so an answer a queue takes keeps the flow thread's zeroing out of the hot path.
    served: Vec<u8>,
    association: Option<Association>,
    /// The direct datagram lane this handler opened, kept alive by its control connection.
    direct_datagram: Option<crate::proxy::DirectDatagram>,
    /// The direct lane's association while a worker dials it: the dial and its handshake cost a
    /// network round trip, and the queue keeps dispatching while it is pending.
    opening: Option<mpsc::Receiver<Option<crate::proxy::DirectDatagram>>>,
    /// The earliest moment a refused direct lane may be tried again, so a dead server costs one
    /// worker per budget instead of one per datagram.
    datagram_retry: Option<std::time::Instant>,
    /// Set by the watcher parked on the direct lane's control: the relay ended the association, so
    /// the lane and its legs are dropped before the next datagram frames at a dead address.
    direct_dead: Arc<AtomicBool>,
    udp_idle: std::time::Duration,
    endpoint_independent_nat: bool,
}

impl Handler {
    #[cfg(all(test, unix))]
    pub(crate) fn new(device: Device, relay: Relay, associate: Associate) -> Self {
        Self::on(
            device,
            relay,
            associate,
            None,
            None,
            Flows::default(),
            Legs::default(),
            &Spec::new(None, None),
        )
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_dial(
        device: Device,
        relay: Relay,
        associate: Associate,
        dial: Dial,
    ) -> Self {
        Self::on(
            device,
            relay,
            associate,
            Some(dial),
            None,
            Flows::default(),
            Legs::default(),
            &Spec::new(None, None),
        )
    }

    /// One queue of a multi-queue device: every queue passes the same `flows` and `legs`, so a flow
    /// is whole wherever the kernel hashes its next segment or datagram.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on(
        device: Device,
        relay: Relay,
        associate: Associate,
        dial: Option<Dial>,
        datagram: Option<Datagram>,
        flows: Flows,
        legs: Legs,
        spec: &Spec,
    ) -> Self {
        let emit = Vec::with_capacity(device.mtu + 64);
        Self {
            device,
            relay,
            associate,
            dial,
            datagram,
            flows,
            legs,
            frame: Vec::with_capacity(FRAME_CAP),
            emit,
            served: Vec::new(),
            association: None,
            direct_datagram: None,
            opening: None,
            datagram_retry: None,
            direct_dead: Arc::new(AtomicBool::new(false)),
            udp_idle: spec.udp_idle(),
            endpoint_independent_nat: spec.endpoint_independent_nat(),
        }
    }

    pub(crate) fn serve(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET + 64];
        loop {
            let n = self.device.read_packet(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            if let Err(e) = self.dispatch(&buf[..n]) {
                eprintln!("tun dispatch: {e}");
            }
        }
    }

    fn dispatch(&mut self, packet: &[u8]) -> io::Result<()> {
        // Threads that left their flow report here, so neither table keeps a dead entry or the socket inside it.
        self.flows.reap(&self.legs);
        let Some((ip, body)) = ip_head(packet) else {
            return Ok(());
        };
        match ip.protocol {
            TCP_PROTO => self.handle_tcp(&ip, body),
            PROTOCOL_UDP => self.handle_udp(&ip, body),
            ICMP_PROTO | ICMPV6_PROTO => self.handle_icmp(&ip, body),
            _ => Ok(()),
        }
    }

    /// Relay one datagram: the flow's leg is raised on the association's relay address and every packet afterwards rides it, framed with the destination the device asked for. A packet whose association or leg cannot be raised is lost, as an unroutable datagram is at every other front.
    fn handle_udp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
        let Some((udp, payload)) = udp_head(body) else {
            return Ok(());
        };
        if self.direct_dead.swap(false, Relaxed) {
            // The control closed, so the relay address its legs frame at is gone: drop only those, and let the retry budget gate a fresh lane while the front's association carries the datagrams.
            if let Some(dead) = self.direct_datagram.take() {
                self.legs
                    .table()
                    .retain(|_, leg| leg.relay != Some(dead.relay));
            }
            self.datagram_retry = Some(std::time::Instant::now() + budgets::handshake());
        }
        self.poll_datagram_lane();
        if self.association.is_none() && self.direct_datagram.is_none() && self.opening.is_none() {
            let direct_due = self
                .datagram_retry
                .is_none_or(|at| std::time::Instant::now() >= at);
            if self.datagram.as_ref().is_some_and(Datagram::ready) && direct_due {
                self.open_datagram_lane();
            } else if let Ok(association) = Association::open(&self.associate) {
                self.association = Some(association);
            }
        }
        let (relay, direct_relay) = match (&self.direct_datagram, &self.association) {
            (Some(direct), _) => (direct.relay, Some(direct.relay)),
            (None, Some(association)) => (association.relay, None),
            (None, None) => return Ok(()),
        };
        let target = SocketAddr::new(ip.destination, udp.destination_port);
        // An endpoint-independent mapping keys on the client source alone; the frame still names each datagram's destination, and the reply's source comes back off that frame.
        let (key, pinned) = if self.endpoint_independent_nat {
            (
                UdpKey {
                    source: ip.source,
                    source_port: udp.source_port,
                    destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    destination_port: 0,
                },
                None,
            )
        } else {
            (
                UdpKey {
                    source: ip.source,
                    source_port: udp.source_port,
                    destination: ip.destination,
                    destination_port: udp.destination_port,
                },
                Some((ip.destination, udp.destination_port)),
            )
        };
        let (id, leg) = {
            let mut table = self.legs.table();
            match table.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    let leg = entry.into_mut();
                    (leg.id, Arc::clone(&leg.socket))
                }
                std::collections::hash_map::Entry::Vacant(vacant) => {
                    let id = self.legs.next_id();
                    let socket = Arc::new(open_leg(
                        &self.device,
                        relay,
                        pinned,
                        (ip.source, udp.source_port),
                        self.udp_idle,
                        key,
                        id,
                        &self.flows.ended_tx,
                    )?);
                    vacant.insert(Leg {
                        id,
                        socket: Arc::clone(&socket),
                        relay: direct_relay,
                    });
                    (id, socket)
                }
            }
        };
        let mut frame = std::mem::take(&mut self.frame);
        let (front, tail) = crate::proxy::socks_udp_parts(&mut frame, &target, payload);
        let sent = crate::proxy::send_two(&leg, front, tail);
        self.frame = frame;
        if sent.is_err() {
            let mut table = self.legs.table();
            if table.get(&key).is_some_and(|leg| leg.id == id) {
                table.remove(&key);
            }
        }
        Ok(())
    }

    /// Start the direct datagram lane's association on a worker: the dial and the server's SOCKS
    /// handshake are network round trips, and the packet queue must keep dispatching while they
    /// are outstanding.
    fn open_datagram_lane(&mut self) {
        let Some(open) = self.datagram.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.opening = Some(rx);
        budgets::spawn(move || {
            let _ = tx.send(open.open());
        });
    }

    /// Take the worker's verdict: a lane becomes this handler's, and a refusal starts the retry
    /// budget so the next datagram falls back to the front's association.
    fn poll_datagram_lane(&mut self) {
        let Some(rx) = self.opening.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(Some(direct)) => {
                // The relay ends the association with its control connection; a watcher parks on that socket so the next datagram can drop the lane instead of framing at a dead address.
                if let Ok(mut control) = direct.control.try_clone() {
                    let dead = Arc::clone(&self.direct_dead);
                    std::thread::spawn(move || {
                        let mut byte = [0u8; 1];
                        loop {
                            match control.read(&mut byte) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        dead.store(true, Relaxed);
                    });
                }
                self.direct_datagram = Some(direct);
            }
            Ok(None) | Err(mpsc::TryRecvError::Disconnected) => {
                self.datagram_retry = Some(std::time::Instant::now() + budgets::handshake());
            }
            Err(mpsc::TryRecvError::Empty) => self.opening = Some(rx),
        }
    }

    fn handle_tcp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
        let Some((tcp, payload)) = tcp_head(body) else {
            return Ok(());
        };
        let key = FlowKey {
            source: ip.source,
            source_port: tcp.source_port,
            destination: ip.destination,
            destination_port: tcp.destination_port,
        };
        if tcp.flags & FLAG_SYN != 0 && tcp.flags & FLAG_ACK == 0 {
            return self.accept_flow(ip, &tcp, key);
        }
        if tcp.flags & FLAG_RST != 0 {
            let id = self.flows.table().get(&key).map(|flow| flow.id);
            if let Some(id) = id {
                self.close_flow(key, id, None);
            }
            return Ok(());
        }
        let flow = self.flows.table().get(&key).cloned();
        if let Some(flow) = flow {
            if tcp.flags & FLAG_ACK != 0 {
                let sent = flow.snd_nxt.load(Relaxed);
                flow.send
                    .acked(tcp.ack_num, u32::from(tcp.window) << flow.peer_shift, sent);
            }
            let fin = tcp.flags & FLAG_FIN != 0;
            let len = payload.len() as u32;
            // What the queue served behind the upload: an answer already carries this segment's ack, a refused one ends the flow.
            let mut served = Served::None;
            // A pure ACK only moves the window: it never touches the upload half, so it takes no pipe lock.
            if !payload.is_empty() || fin {
                let mut guard = flow
                    .write_half
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(half) = guard.as_mut() else {
                    // The lane is not live yet; the device retransmits what this segment carried.
                    return Ok(());
                };
                // A device retransmits and can reorder, so only the bytes past `rcv_nxt` reach the proxy: a duplicate is dropped and an overlapping segment is trimmed, never written twice. The trim and the store sit inside the pipe's lock because a second queue can be handed the same flow at the same time.
                let rcv = flow.rcv_nxt.load(Relaxed);
                let gap = rcv.wrapping_sub(tcp.seq);
                let skip = if i32::try_from(gap).is_ok() {
                    gap as usize
                } else {
                    usize::MAX
                };
                let mut end = rcv;
                if skip < payload.len() {
                    flow.busy.store(true, Relaxed);
                    // The cursor moves by what the pipe accepted, so a short or refused write is the device's to retransmit; the read leg still delivers what the relay wrote before it closed.
                    let sent = half.write(&payload[skip..]).unwrap_or(0);
                    end = rcv.wrapping_add(sent as u32);
                    flow.rcv_nxt.store(end, Relaxed);
                    if sent > 0 && !fin {
                        served = self.serve_inline(half, &flow);
                    }
                }
                if fin && tcp.seq.wrapping_add(len) == flow.rcv_nxt.load(Relaxed) {
                    flow.rcv_nxt.store(end.wrapping_add(1), Relaxed);
                    let _ = half.shutdown(Shutdown::Write);
                    flow.upload_finished.finish();
                }
            }
            if served == Served::Failed {
                self.retire(&flow, Some(FLAG_RST | FLAG_ACK));
                return Ok(());
            }
            // Every data segment or FIN gets an ACK: a segment without PSH must not wait for a later one that may never come, and a duplicate still has to stop a retransmit.
            let unacked = flow
                .rcv_nxt
                .load(Relaxed)
                .wrapping_sub(flow.last_acked.load(Relaxed));
            if let Served::Ack(ack) = served {
                // The response carried this segment's ack, so the standalone one would only repeat it, and the cursor stored is the one that left rather than whatever another queue advanced meanwhile.
                flow.last_acked.store(ack, Relaxed);
            } else if fin || !payload.is_empty() || unacked > 0 {
                let snd = flow.snd_nxt.load(Relaxed);
                let rcv = flow.rcv_nxt.load(Relaxed);
                let mut emit = std::mem::take(&mut self.emit);
                render_tcp_packet_ip(
                    (ip.destination, tcp.destination_port),
                    (ip.source, tcp.source_port),
                    snd,
                    rcv,
                    FLAG_ACK,
                    65535,
                    &[],
                    &[],
                    false,
                    &mut emit,
                );
                let _ = self.device.write_packet(&emit);
                self.emit = emit;
                flow.last_acked.store(rcv, Relaxed);
            }
        }
        Ok(())
    }

    /// Take the answer a request-and-reply earns, on the queue thread that still holds the flow, so the transaction costs no response-thread wake. A non-blocking read never waits and the stream hands each byte to exactly one reader, so a flow thread parked in its own read keeps what this leaves. A flow learns whether an answer is due: it waits one exchange window while answers have been landing, and a bulk upload's four misses cost a millisecond once and leave it one non-blocking read per segment.
    fn serve_inline(&mut self, half: &mut Connection, flow: &Flow) -> Served {
        // A host whose descriptor has no per-call non-blocking read keeps the answer on the response thread rather than blocking a queue behind it.
        if cfg!(not(unix)) || flow.signaled.load(Relaxed) {
            return Served::None;
        }
        let Some(body) = ip_header_len(flow.local.0, flow.remote.0).map(|head| head + 20) else {
            return Served::None;
        };
        let max = (flow.mss.load(Relaxed) as usize).max(1);
        // One segment: a queue's own descriptor writes without the offload a GSO frame needs, so a larger answer is the response thread's.
        let cap = max.min(MAX_PACKET - body);
        if cap == 0 {
            return Served::None;
        }
        if self.served.len() < body + cap {
            self.served.resize(body + cap, 0);
        }
        // No clock for a flow that stopped waiting: a bulk upload's segment takes one non-blocking read and nothing else.
        let deadline = (flow.misses.load(Relaxed) < PING_PONG_MISSES)
            .then(|| std::time::Instant::now() + PING_PONG_SPIN);
        // A packet already in the ring belongs to another flow: waiting here would hold it back for a wait that only helps this one.
        #[cfg(unix)]
        if deadline.is_some() && self.device.readable_now() {
            return Served::None;
        }
        let mut served = Served::None;
        loop {
            let gated = match flow.read_gate.try_lock() {
                Ok(gated) => gated,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => break,
            };
            // The room the response thread parked on is re-read here: it may have taken the window in between, and this read must not spend bytes the peer is not waiting for.
            let room = flow
                .send
                .room_now(&flow.snd_nxt)
                .map_or(0, |room| room as usize);
            let read = if room == 0 {
                None
            } else {
                Some(
                    half.read_ready(&mut self.served[body..body + cap.min(room)])
                        .map(|n| (n, flow.snd_nxt.fetch_add(n as u32, Relaxed))),
                )
            };
            drop(gated);
            let Some(read) = read else { break };
            match read {
                Ok((0, _)) => break,
                Ok((n, seq)) => {
                    flow.misses.store(0, Relaxed);
                    served = match emit_upstream(
                        flow,
                        &mut self.served,
                        n,
                        seq,
                        false,
                        max,
                        flow.local,
                        flow.remote,
                        |packet, _| self.device.write_packet(packet),
                    ) {
                        Ok(ack) => Served::Ack(ack),
                        // The answer left the stream and the cursor moved with it; a device that took neither leaves a hole no retransmit can fill, so this reports the refusal and the caller retires the flow outside the pipe lock.
                        Err(_) => Served::Failed,
                    };
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let Some(deadline) = deadline else { break };
                    if std::time::Instant::now() >= deadline {
                        if flow.misses.load(Relaxed) < PING_PONG_MISSES {
                            flow.misses.fetch_add(1, Relaxed);
                        }
                        break;
                    }
                    std::hint::spin_loop();
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        served
    }

    /// The device flow's byte pipe: one `AF_UNIX` pair on a Unix host instead of a loopback TCP
    /// listener plus `connect`/`accept`, so a flow opens with one `socketpair(2)`.
    #[cfg(unix)]
    fn flow_pair() -> io::Result<(Connection, Connection)> {
        let (device, proxy) = UnixStream::pair()?;
        Ok((Connection::from(device), Connection::from(proxy)))
    }

    #[cfg(not(unix))]
    fn flow_pair() -> io::Result<(Connection, Connection)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let device = TcpStream::connect(address)?;
        let (proxy, _) = listener.accept()?;
        device.set_nodelay(true)?;
        proxy.set_nodelay(true)?;
        Ok((Connection::from(device), Connection::from(proxy)))
    }

    #[allow(clippy::too_many_lines)]
    fn accept_flow(&mut self, ip: &IpHead, tcp: &TcpHead<'_>, key: FlowKey) -> io::Result<()> {
        let peer_shift = window_shift(tcp.options);
        let existing = self.flows.table().get(&key).cloned();
        if let Some(flow) = existing {
            // A retransmitted SYN keeps its flow and only needs the SYN-ACK again; a new SYN on a live tuple ends the old flow first, so its threads and lane cannot outlive it.
            if flow.isn == tcp.seq {
                // A lane still dialing has no SYN-ACK to replay: the device's next retransmission finds one.
                if flow
                    .write_half
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_none()
                {
                    return Ok(());
                }
                let mut emit = std::mem::take(&mut self.emit);
                let (options, len) = syn_ack_options(flow.mss.load(Relaxed), peer_shift.is_some());
                render_tcp_packet_ip(
                    flow.local,
                    flow.remote,
                    flow.server_isn,
                    flow.isn.wrapping_add(1),
                    FLAG_SYN | FLAG_ACK,
                    65535,
                    &options[..len],
                    &[],
                    false,
                    &mut emit,
                );
                let wrote = self.device.write_packet(&emit);
                self.emit = emit;
                return wrote.map(|_| ());
            }
            self.close_flow(key, flow.id, Some(FLAG_RST | FLAG_ACK));
        }
        let local_ip = ip.destination;
        let remote_ip = ip.source;
        let local_port = tcp.destination_port;
        let remote_port = tcp.source_port;
        let syn_seq = tcp.seq;
        let server_isn = initial_sequence(syn_seq);
        let offered_mss = peer_mss(tcp.options);
        let device_mss = self.device.mss(remote_ip);
        let mss = Arc::new(AtomicU32::new(
            offered_mss.map_or(device_mss, |offered| offered.min(device_mss)),
        ));

        // The lane comes first and the SYN-ACK follows it, so a refused edge never opens a half handshake and no segment outruns the pipe that carries it.
        let target = SocketAddr::new(ip.destination, tcp.destination_port);
        let destination = crate::proxy::Destination::from(target);
        let relay = Arc::clone(&self.relay);
        let dial = self.dial.clone();

        let mut dev_writer = self.device.clone_writer()?;
        let rcv_nxt = Arc::new(AtomicU32::new(syn_seq.wrapping_add(1)));
        let snd_nxt = Arc::new(AtomicU32::new(server_isn.wrapping_add(1)));
        let busy = Arc::new(AtomicBool::new(false));
        let signaled = Arc::new(AtomicBool::new(false));
        let send = Arc::new(SendWindow::new(
            server_isn.wrapping_add(1),
            u32::from(tcp.window),
        ));
        let id = self.flows.next_id();
        let flow = Arc::new(Flow {
            id,
            isn: syn_seq,
            server_isn,
            peer_shift: peer_shift.unwrap_or(0),
            write_half: Mutex::new(None),
            rcv_nxt: Arc::clone(&rcv_nxt),
            snd_nxt: Arc::clone(&snd_nxt),
            busy: Arc::clone(&busy),
            last_acked: AtomicU32::new(syn_seq.wrapping_add(1)),
            local: (local_ip, local_port),
            remote: (remote_ip, remote_port),
            mss: Arc::clone(&mss),
            send: Arc::clone(&send),
            signaled: Arc::clone(&signaled),
            misses: AtomicU32::new(0),
            read_gate: Mutex::new(()),
            upload_finished: UploadFinished::default(),
        });
        // Claim the tuple under the table lock: a duplicate SYN that raced this handshake on another queue finds a flow here and keeps it instead of opening a second leg, and whatever flow ours replaces is retired rather than left running beside it.
        let response_flow = Arc::clone(&flow);
        let (racer, displaced) = {
            let mut table = self.flows.table();
            match table.get(&key).map(|flow| flow.isn) {
                Some(isn) if isn == syn_seq => (true, None),
                _ => (false, table.insert(key, flow)),
            }
        };
        if racer {
            return Ok(());
        }
        if let Some(displaced) = displaced {
            self.retire(&displaced, Some(FLAG_RST | FLAG_ACK));
        }

        let ended_tx = self.flows.ended_tx.clone();
        let flow = response_flow;
        budgets::spawn(move || {
            let _ = send.thread.set(std::thread::current());
            let gso_capable = dev_writer.gso();
            let initial = (mss.load(Relaxed) as usize).max(1);
            let head = ip_header_len(local_ip, remote_ip).unwrap_or(IPV6_HEADER);
            let body = head + 20;
            let (syn_options, syn_len) = syn_ack_options(mss.load(Relaxed), peer_shift.is_some());
            let payload_cap = if gso_capable {
                MAX_PACKET - body
            } else {
                initial.max(syn_len)
            };
            let mut pkt = vec![0u8; body + payload_cap];
            let (direct, lane, refused) = match dial.map(|dial| dial(&destination)) {
                Some(DialOutcome::Direct(stream)) => (Some(stream), None, false),
                Some(DialOutcome::Fallback(lane)) => (None, Some(lane), false),
                Some(DialOutcome::Refused) => (None, None, true),
                None => (None, None, false),
            };
            let mut outcome = None;
            let mut reader;
            if let Some(upstream) = direct {
                let Ok(write) = upstream.try_clone() else {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                };
                // Silence past the idle budget is death: an untimed read parks a thread, and with it the flow's lane, for the life of the process.
                if upstream
                    .set_read_timeout(Some(budgets::udp_idle()))
                    .is_err()
                {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                }
                // The handler writes this half on the queue's own thread while it holds the flow, so a peer that stops reading must not park the queue: the timeout turns it into a short write the device retransmits.
                if write
                    .set_write_timeout(Some(budgets::relay_quantum()))
                    .is_err()
                {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                }
                *flow
                    .write_half
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(write);
                reader = upstream;
            } else if refused {
                refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                return;
            } else {
                let Ok((tun_half, proxy_half)) = Self::flow_pair() else {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                };
                let Ok(write_half) = tun_half.try_clone() else {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                };
                let Ok(proxy_hold) = proxy_half.try_clone() else {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                };
                if tun_half
                    .set_read_timeout(Some(budgets::udp_idle()))
                    .is_err()
                {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                }
                if write_half
                    .set_write_timeout(Some(budgets::relay_quantum()))
                    .is_err()
                {
                    refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                    return;
                }
                *flow
                    .write_half
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(write_half);
                reader = tun_half;
                let (outcome_tx, outcome_rx) = mpsc::channel();
                outcome = Some(outcome_rx);
                budgets::spawn(move || {
                    let ok = relay(proxy_half, lane.as_ref(), destination).is_ok();
                    let _ = outcome_tx.send(ok);
                    // The duplicate holds the pair's far end open until the verdict is queued, so an EOF before it is a clean remote close, not a refusal.
                    drop(proxy_hold);
                });
            }
            // The device reset the tuple while the lane dialed: the entry is gone, so nothing answers.
            if flow.signaled.load(Relaxed) {
                let _ = ended_tx.send(Ended::Stream(key, id));
                return;
            }
            // The handshake answers only once the pipe exists, so the device's first segment has somewhere to land.
            let rendered = render_tcp_headers_ip(
                (local_ip, local_port),
                (remote_ip, remote_port),
                server_isn,
                syn_seq.wrapping_add(1),
                FLAG_SYN | FLAG_ACK,
                65535,
                &syn_options[..syn_len],
                0,
                false,
                &mut pkt[..body + syn_len],
            );
            // A device that dropped the SYN-ACK has not refused the lane: retry the same packet for one relay quantum before resetting, so a transient refusal cannot kill a connection the device will retransmit the SYN for.
            let handshake = rendered && {
                let deadline = std::time::Instant::now() + budgets::relay_quantum();
                loop {
                    match dev_writer.write_packet(&pkt[..body + syn_len]) {
                        Ok(true) => break true,
                        Ok(false)
                            if std::time::Instant::now() < deadline
                                && !flow.signaled.load(Relaxed) =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        Ok(false) | Err(_) => break false,
                    }
                }
            };
            if !handshake {
                refuse_flow(&flow, key, &mut dev_writer, &mut pkt, &ended_tx);
                return;
            }
            // A direct lane's upstream can half-close: its EOF leaves the upload live, where a pair lane's EOF is the whole flow.
            let mut half_closed = false;
            let end = loop {
                let max = (mss.load(Relaxed) as usize).max(1);
                // Park on the window the way an ACK wakes it; the read itself re-checks the room inside the gate.
                if send.room(&snd_nxt).is_none() {
                    break FLAG_RST | FLAG_ACK;
                }
                let limit = read_limit(gso_capable, max, payload_cap);
                match read_upstream(
                    &flow,
                    &flow.read_gate,
                    &mut reader,
                    &mut pkt[body..],
                    limit,
                    budgets::udp_idle(),
                    &snd_nxt,
                ) {
                    // The queue served the stream while this thread parked: the window is gone, not the peer.
                    Ok(None) => {}
                    Ok(Some((0, _))) if outcome.as_ref().is_none() => {
                        half_closed = true;
                        break FLAG_FIN | FLAG_ACK;
                    }
                    Ok(Some((0, _))) => {
                        // A clean close ends with FIN, a refused leg with RST; a relay that never reports is dead.
                        let clean = match outcome.as_ref() {
                            None => true,
                            Some(rx) => match rx.try_recv() {
                                Ok(clean) => clean,
                                Err(mpsc::TryRecvError::Empty) => true,
                                Err(mpsc::TryRecvError::Disconnected) => false,
                            },
                        };
                        break if clean {
                            FLAG_FIN | FLAG_ACK
                        } else {
                            FLAG_RST | FLAG_ACK
                        };
                    }
                    Ok(Some((n, seq))) => {
                        if emit_upstream(
                            &flow,
                            &mut pkt,
                            n,
                            seq,
                            gso_capable,
                            max,
                            (local_ip, local_port),
                            (remote_ip, remote_port),
                            |packet, gso| {
                                if gso {
                                    dev_writer.write_gso(packet, max as u16)
                                } else {
                                    dev_writer.write_packet(packet)
                                }
                            },
                        )
                        .is_err()
                        {
                            break FLAG_RST | FLAG_ACK;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    // The budget expired with nothing to carry: the upload leg gets one more budget to speak, and a silent one ends the flow.
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if !busy.swap(false, Relaxed) {
                            break FLAG_RST | FLAG_ACK;
                        }
                    }
                    Err(_) => break FLAG_RST | FLAG_ACK,
                }
            };
            if !signaled.swap(true, Relaxed) {
                // A FIN consumes one sequence number, so a half-closed flow's later ACKs name the sequence after it; reserve it before the write the way the data path does.
                let seq = snd_nxt.load(Relaxed);
                if end & FLAG_FIN != 0 {
                    snd_nxt.store(seq.wrapping_add(1), Relaxed);
                }
                render_tcp_packet_ip(
                    (local_ip, local_port),
                    (remote_ip, remote_port),
                    seq,
                    rcv_nxt.load(Relaxed),
                    end,
                    65535,
                    &[],
                    &[],
                    false,
                    &mut pkt,
                );
                let _ = dev_writer.write_packet(&pkt);
            }
            if half_closed {
                // The FIN above closed the download; the upload stays until the device's FIN or a stall budget, never reaped by a removal queued before it. A segment that moves the receive window is progress, so an upload longer than one budget is not cut on the clock.
                let mut seen = rcv_nxt.load(Relaxed);
                let mut stalled = std::time::Duration::ZERO;
                while !flow.upload_finished.wait(budgets::relay_quantum()) {
                    let now = rcv_nxt.load(Relaxed);
                    if now == seen {
                        stalled += budgets::relay_quantum();
                        if stalled >= budgets::relay_stall() {
                            break;
                        }
                    } else {
                        seen = now;
                        stalled = std::time::Duration::ZERO;
                    }
                }
                let _ = ended_tx.send(Ended::Stream(key, id));
                return;
            }
            // Queue the entry's removal before the shutdown that wakes the relay leg, so a caller that sees the leg end can reap the entry at its next dispatch.
            let _ = ended_tx.send(Ended::Stream(key, id));
            // Both halves, because the handler's write half is a clone of this descriptor and only a shutdown tells it the flow is over.
            let _ = reader.shutdown(Shutdown::Both);
        });

        Ok(())
    }

    /// Answer an ICMP echo request as the device's own address would, so a ping off the
    /// interface returns instead of vanishing; a message that is not a well-formed echo
    /// request is left unanswered, exactly as the reference's handler returns.
    fn handle_icmp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
        if is_echo_request(ip.protocol, body) {
            let mut emit = std::mem::take(&mut self.emit);
            render_icmp_reply_ip(ip.destination, ip.source, body, &mut emit);
            let wrote = self.device.write_packet(&emit);
            self.emit = emit;
            return wrote.map(|_| ());
        }
        if let Some((key, seq)) = icmp_error_flow(ip.protocol, body) {
            let Some(flow) = self.flows.table().get(&key).cloned() else {
                return Ok(());
            };
            // A forged report names a segment this handler never sent; the quote's sequence has to sit inside what has already gone out.
            let sent = flow.snd_nxt.load(Relaxed);
            if seq == sent || sent.wrapping_sub(seq) > u32::MAX / 2 {
                return Ok(());
            }
            if let Some(mtu) = reported_mtu(ip.protocol, body) {
                self.shrink_flow(key, mtu);
            } else {
                self.close_flow(key, flow.id, Some(FLAG_RST | FLAG_ACK));
            }
        }
        Ok(())
    }

    /// Take a path-MTU report for the rest of a flow: only a smaller segment size is believed, and the floor keeps a forged report from stopping the flow.
    fn shrink_flow(&mut self, key: FlowKey, mtu: u32) {
        if let Some(flow) = self.flows.table().get(&key).cloned() {
            let mss = path_mss(mtu, flow.remote.0.is_ipv6());
            flow.mss.fetch_min(mss, Relaxed);
        }
    }

    /// Remove and retire the flow a key names, unless the entry has been replaced since the caller looked: a late error must not close the connection that took the tuple.
    fn close_flow(&mut self, key: FlowKey, id: u64, signal: Option<u8>) {
        let removed = {
            let mut table = self.flows.table();
            if table.get(&key).is_some_and(|flow| flow.id == id) {
                table.remove(&key)
            } else {
                None
            }
        };
        if let Some(flow) = removed {
            self.retire(&flow, signal);
        }
    }

    fn retire(&mut self, flow: &Flow, signal: Option<u8>) {
        // A half-closed flow's response thread is waiting for its upload; a reset ends that wait.
        flow.upload_finished.finish();
        match signal {
            Some(flags) if !flow.signaled.swap(true, Relaxed) => {
                let mut emit = std::mem::take(&mut self.emit);
                render_tcp_packet_ip(
                    flow.local,
                    flow.remote,
                    flow.snd_nxt.load(Relaxed),
                    flow.rcv_nxt.load(Relaxed),
                    flags,
                    65535,
                    &[],
                    &[],
                    false,
                    &mut emit,
                );
                let _ = self.device.write_packet(&emit);
                self.emit = emit;
            }
            // The device reset the flow itself: nothing has to travel back.
            _ => flow.signaled.store(true, Relaxed),
        }
        flow.send.close();
        if let Some(half) = flow
            .write_half
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = half.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Handler {
    /// The device is gone: closing the control leg ends the association, whose relay socket and reader threads would otherwise outlive the inbound that opened them.
    fn drop(&mut self) {
        if let Some(association) = self.association.take() {
            let _ = association.control.shutdown(Shutdown::Both);
        }
        if let Some(direct) = self.direct_datagram.take() {
            let _ = direct.control.shutdown(Shutdown::Both);
        }
    }
}

/// End a flow whose lane never opened: reset the device's half-open flow once and hand the entry back, so a refused edge costs no silent thread.
fn refuse_flow(
    flow: &Flow,
    key: FlowKey,
    writer: &mut PacketWriter,
    pkt: &mut Vec<u8>,
    ended: &mpsc::Sender<Ended>,
) {
    if !flow.signaled.swap(true, Relaxed) {
        render_tcp_packet_ip(
            flow.local,
            flow.remote,
            flow.snd_nxt.load(Relaxed),
            flow.rcv_nxt.load(Relaxed),
            FLAG_RST | FLAG_ACK,
            65535,
            &[],
            &[],
            false,
            pkt,
        );
        let _ = writer.write_packet(pkt);
    }
    let _ = ended.send(Ended::Stream(key, flow.id));
    if let Some(half) = flow
        .write_half
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        let _ = half.shutdown(Shutdown::Both);
    }
}

/// Raise one flow's leg: a socket on the association's own address that the handler sends framed datagrams through, answered by a reader that re-wraps each reply as a packet back to the flow's source. Silence past the idle budget ends the flow, so neither its thread nor its leg outlives a target that stopped answering.
#[allow(clippy::too_many_arguments)]
fn open_leg(
    device: &Device,
    relay: SocketAddr,
    pinned: Option<(IpAddr, u16)>,
    client: (IpAddr, u16),
    idle: std::time::Duration,
    key: UdpKey,
    id: u64,
    ended: &mpsc::Sender<Ended>,
) -> io::Result<UdpSocket> {
    let leg = crate::proxy::relay_leg_armed(relay, idle)?;
    let reader = leg.try_clone()?;
    let mut dev_writer = device.clone_writer()?;
    let mtu = device.mtu;
    let ended = ended.clone();
    let (client_bytes, client_len) = addr_octets(client.0);
    let target = pinned.map(|(ip, port)| SocketAddr::new(ip, port));
    std::thread::spawn(move || {
        let mut buf = crate::proxy::udp_buffer();
        let mut out: Vec<u8> = Vec::with_capacity(IPV6_HEADER + UDP_HEADER + mtu);
        while let Ok(n) = reader.recv(&mut buf) {
            let Some((source, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
                continue;
            };
            if target.is_some_and(|target| source != target) {
                continue;
            }
            let (endpoint, source_port) = target.map_or((source.ip(), source.port()), |target| {
                (target.ip(), target.port())
            });
            let (endpoint_bytes, endpoint_len) = addr_octets(endpoint);
            let datagram = UdpDatagram {
                source: &endpoint_bytes[..endpoint_len],
                destination: &client_bytes[..client_len],
                source_port,
                destination_port: client.1,
                payload,
            };
            out.clear();
            if !udp_datagram(&datagram, &mut out) {
                continue;
            }
            if dev_writer.write_packet(&out).is_err() {
                break;
            }
        }
        let _ = ended.send(Ended::Datagram(key, id));
    });
    Ok(leg)
}

pub(crate) fn refusal_reason(spec: &Spec) -> String {
    format!(
        "`{}` (mtu {} B) cannot open a TUN: no ioctl and no FERROX_TUN_FD",
        if spec.name.is_empty() {
            "default"
        } else {
            spec.name.as_str()
        },
        spec.mtu
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use ferrox_core::foxy::connectip::checksum;

    #[test]
    fn device_protocols_recognized() {
        for p in ["tun", "utun", "wintun", "tun2socks"] {
            assert!(is_device(p));
        }
        assert!(!is_device("vless"));
    }

    #[test]
    fn a_tun_prefix_is_kept_or_refused_by_family() {
        let (address, prefix) = parse_address(Some("198.18.0.1/0"), None).unwrap();
        assert_eq!(address, Some("198.18.0.1".parse().unwrap()));
        assert_eq!(prefix, Some(0));
        assert!(parse_address(Some("198.18.0.1/33"), None).is_err());
        assert!(parse_address(Some("2001:db8::1/129"), None).is_err());
        assert!(parse_address(Some("not-an-ip"), None).is_err());
        let (_, prefix) = parse_address(Some("2001:db8::1"), None).unwrap();
        assert_eq!(prefix, None);
    }

    #[test]
    fn the_tun_spec_defaults_ipv6_and_bounds_its_values() {
        let spec = Spec::with(None, None, Some("2001:db8::1".parse().unwrap()), None, None);
        assert_eq!(spec.prefix(), 64);
        assert!(Spec::with(None, Some(65_536), None, None, None)
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, Some(33), None)
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, None, Some(0))
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, None, Some(5))
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, Some(0), None)
            .validate()
            .is_ok());
    }

    #[test]
    fn a_spec_carries_every_address_its_config_names() {
        let v4: IpAddr = "198.18.0.1".parse().unwrap();
        let v6: IpAddr = "fdfe:dcba:9876::1".parse().unwrap();
        let spec = Spec::with(None, None, Some(v4), Some(15), None)
            .with_addresses(vec![(v4, 15), (v6, 126)]);
        assert_eq!(spec.addresses().len(), 2);
        assert_eq!(spec.addresses()[0], (v4, 15));
        assert_eq!(spec.addresses()[1], (v6, 126));
        assert_eq!(spec.address(), v4, "the first address stays the primary");
        assert_eq!(spec.prefix(), 15);
        spec.validate().expect("both prefixes are in range");
        assert!(
            spec.with_addresses(vec![(v6, 129)]).validate().is_err(),
            "the second address's prefix is bounded too"
        );
        let kept = Spec::with(None, None, Some(v4), Some(15), None).with_addresses(Vec::new());
        assert_eq!(
            kept.addresses().len(),
            1,
            "an empty list keeps the address the builder already has"
        );
        assert_eq!(kept.address(), v4);
    }

    #[test]
    fn a_window_scale_is_read_past_the_options_a_client_sends() {
        assert_eq!(
            window_shift(&[]),
            None,
            "a SYN without options scales nothing"
        );
        assert_eq!(window_shift(&[1, 3, 3, 7]), Some(7));
        assert_eq!(
            window_shift(&[4, 2, 1, 3, 3, 7]),
            Some(7),
            "SACK, a NOP, then the scale"
        );
        assert_eq!(
            window_shift(&[1, 3, 3, 15]),
            Some(14),
            "a shift past fourteen is taken as fourteen"
        );
        assert_eq!(window_shift(&[3]), None, "a truncated option is refused");
        assert_eq!(window_shift(&[3, 3]), None, "a missing shift is refused");
    }

    #[test]
    fn a_scaled_peer_window_is_room_in_bytes() {
        let window = SendWindow::new(1_000, 1_000);
        window.acked(1_000, 65_535 << OUR_WINDOW_SHIFT, 1_000);
        assert_eq!(
            window.room(&AtomicU32::new(1_000)),
            Some(65_535 << OUR_WINDOW_SHIFT)
        );
    }

    #[test]
    fn tcp_head_parses_syn() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.protocol, TCP_PROTO);
        let (tcp, pl) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 80);
        assert_eq!(tcp.seq, 1000);
        assert_eq!(tcp.flags, FLAG_SYN);
        assert_eq!(pl, []);
    }

    #[test]
    fn tcp_head_parses_payload() {
        let pkt = build_tcp_packet(
            ([1, 2, 3, 4], 999),
            ([5, 6, 7, 8], 1000),
            50,
            10,
            FLAG_ACK,
            4096,
            b"hello tun",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"hello tun");
    }

    #[test]
    fn tcp_head_refuses_short_segment() {
        assert!(tcp_head(&[0u8; 10]).is_none());
    }

    #[test]
    fn an_ipv4_fragment_is_not_a_flow_packet() {
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        assert!(ip_head(&pkt).is_some());
        pkt[6] |= 0x20;
        assert!(ip_head(&pkt).is_none(), "more fragments");
        pkt[6] &= !0x20;
        pkt[6] |= 0x1f;
        assert!(ip_head(&pkt).is_none(), "a high fragment offset");
        pkt[6] = 0;
        pkt[7] = 1;
        assert!(ip_head(&pkt).is_none(), "a low fragment offset");
    }

    #[test]
    fn an_mss_option_of_zero_is_absent() {
        assert_eq!(peer_mss(&[2, 4, 0x05, 0xdc]), Some(1500));
        assert_eq!(peer_mss(&[2, 4, 0, 0]), None);
        let (options, _) = syn_ack_options(0, false);
        assert_ne!(
            u16::from_be_bytes([options[2], options[3]]),
            0,
            "the SYN-ACK never advertises MSS zero"
        );
    }

    #[test]
    fn a_gso_read_can_take_more_than_one_mss() {
        assert_eq!(read_limit(true, 1400, 65_515), 65_515);
        assert_eq!(read_limit(false, 1400, 65_515), 1400);
        assert_eq!(read_limit(false, 1400, 700), 700);
    }

    #[test]
    fn a_virtio_gso_header_names_the_tcp_segment() {
        assert_eq!(Framing::Virtio.header_len(), VIRTIO_NET_HDR_LEN);
        assert_eq!(Framing::Utun.header_len(), UTUN_HEADER_LEN);
        let packet = build_ipv6_tcp_packet(
            ("2001:db8::2".parse().unwrap(), 1),
            ("2001:db8::1".parse().unwrap(), 2),
            0,
            0,
            FLAG_ACK,
            4096,
            b"",
        );
        let header = virtio_header(&packet, Some(1400));
        assert_eq!(header[0], VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(header[1], VIRTIO_NET_HDR_GSO_TCPV6);
        assert_eq!(u16::from_ne_bytes([header[2], header[3]]), 60);
        assert_eq!(u16::from_ne_bytes([header[4], header[5]]), 1400);
        assert_eq!(u16::from_ne_bytes([header[6], header[7]]), 40);
        assert_eq!(u16::from_ne_bytes([header[8], header[9]]), 16);
    }

    /// Drives one SYN through the handler and returns the GSO frame the response thread writes for the relay read: the header, the frame bytes, and the payload the read carried.
    #[cfg(target_os = "linux")]
    fn gso_frame_for_one_relay_read() -> ([u8; VIRTIO_NET_HDR_LEN], Vec<u8>, Vec<u8>) {
        use std::io::Write;
        let (a, mut peer) = peer_with_deadline().unwrap();
        let payload: Vec<u8> = (0..4_000u32).map(|i| (i % 251) as u8).collect();
        let sent = payload.clone();
        let relay: Relay = Arc::new(move |mut conn: Connection, _lane, _dest| {
            conn.write_all(&sent)?;
            Ok(())
        });
        let device = Device {
            handle: a,
            mtu: 100,
            framing: Framing::Virtio,
            gso: true,
        };
        let mut handler = Handler::new(device, relay, no_associate());
        let client = (SCRIPT_CLIENT, 51001);
        let endpoint = ([203, 0, 113, 53], 53);
        let mut buf = vec![0u8; MAX_PACKET + 64];

        // A virtio-framed SYN: the device read strips the ten-byte header as a Linux descriptor's does, and the response thread is spawned off the flow.
        let syn = build_tcp_packet(client, endpoint, 7000, 0, FLAG_SYN, 65535, &[]);
        let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
        frame.extend_from_slice(&syn);
        peer.write_all(&frame).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut gso = None;
        for _ in 0..2_500 {
            match peer.read(&mut buf) {
                Ok(n) if n > VIRTIO_NET_HDR_LEN => {
                    let header: [u8; VIRTIO_NET_HDR_LEN] =
                        buf[..VIRTIO_NET_HDR_LEN].try_into().unwrap();
                    if header[1] == VIRTIO_NET_HDR_GSO_TCPV4 {
                        gso = Some((header, n, buf[VIRTIO_NET_HDR_LEN..n].to_vec()));
                        break;
                    }
                    // The SYN-ACK carries no GSO header; answer it so the flow's receive cursor moves, then wait for the response.
                    if header == [0u8; VIRTIO_NET_HDR_LEN] {
                        if let Some((_ip, body)) = ipv4_head(&buf[VIRTIO_NET_HDR_LEN..n]) {
                            if let Some((tcp, _)) = tcp_head(body) {
                                if tcp.flags == FLAG_SYN | FLAG_ACK {
                                    let ack = build_tcp_packet(
                                        client,
                                        endpoint,
                                        7001,
                                        tcp.seq.wrapping_add(1),
                                        FLAG_ACK,
                                        65535,
                                        &[],
                                    );
                                    let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
                                    frame.extend_from_slice(&ack);
                                    peer.write_all(&frame).unwrap();
                                    let m = handler.device.read_packet(&mut buf).unwrap();
                                    handler.dispatch(&buf[..m]).unwrap();
                                }
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        let (header, _total, frame) =
            gso.expect("a read larger than the MSS leaves as one GSO frame");
        (header, frame, payload)
    }

    /// The ACK that ends a write acks the cursor the writer just reached, so `ack == sent` is the ordinary case and must move the window; a stale number must not.
    #[test]
    fn an_ack_at_the_sent_cursor_moves_the_window() {
        let paced = SendWindow::new(1100, 1000);
        let cursor = AtomicU32::new(1600);
        paced.acked(1600, 400, 1600);
        assert_eq!(paced.cursor(), 1600);
        assert_eq!(paced.room(&cursor), Some(400));
        paced.acked(1200, 400, 1600);
        assert_eq!(paced.cursor(), 1600);
        assert_eq!(paced.room(&cursor), Some(400));
        // A partial ACK moves the cursor too: waiting for one that equals the newest byte sent stalls a download the peer has already consumed most of.
        let partial = SendWindow::new(1_000, 1_000);
        let sent = AtomicU32::new(1_800);
        partial.acked(1_400, 1_000, 1_800);
        assert_eq!(partial.cursor(), 1_400);
        assert_eq!(partial.room(&sent), Some(600));
        // An ACK past the sent cursor names bytes the device was never handed, and must not push the cursor into the future.
        partial.acked(1_900, 1_000, 1_800);
        assert_eq!(partial.cursor(), 1_400);
        assert_eq!(partial.room(&sent), Some(600));
    }

    /// The response buffer is the packet: headers are written in front of the bytes the read
    /// landed, the payload's address is the one it was read at, and the bytes match a render
    /// that copies. Pointer identity is the gate a byte comparison cannot be.
    #[test]
    fn a_response_is_rendered_where_the_relay_read_landed() {
        let (src, dst) = (
            (IpAddr::from([10, 0, 0, 1]), 80),
            (IpAddr::from([10, 0, 0, 2]), 51_001),
        );
        let payload: Vec<u8> = (0..1_400u32).map(|i| (i % 251) as u8).collect();
        let mut pkt = vec![0u8; IPV4_HEADER + 20 + payload.len()];
        let base = pkt.as_ptr() as usize;
        let capacity = pkt.capacity();
        pkt[IPV4_HEADER + 20..].copy_from_slice(&payload);
        let landed = pkt[IPV4_HEADER + 20..].as_ptr() as usize;
        assert!(render_tcp_headers_ip(
            src,
            dst,
            4_096,
            7_003,
            FLAG_PSH | FLAG_ACK,
            65_535,
            &[],
            payload.len(),
            false,
            &mut pkt,
        ));
        assert_eq!(pkt.as_ptr() as usize, base, "the buffer did not move");
        assert_eq!(pkt.capacity(), capacity, "the segment did not reallocate");
        let (ip, body) = ipv4_head(&pkt).unwrap();
        let (tcp, carried) = tcp_head(body).unwrap();
        assert_eq!(tcp.seq, 4_096);
        assert_eq!(
            carried.as_ptr() as usize,
            landed,
            "the payload was not copied"
        );
        assert_eq!(carried, payload.as_slice());
        let mut copied = Vec::new();
        render_tcp_packet_ip(
            src,
            dst,
            4_096,
            7_003,
            FLAG_PSH | FLAG_ACK,
            65_535,
            &[],
            &payload,
            false,
            &mut copied,
        );
        assert_eq!(pkt, copied, "the in-place render is the copy render");
        assert_eq!(ip.destination, [10, 0, 0, 2]);
    }

    /// A response read larger than one segment leaves as one GSO frame: the end-to-end gate the header-only test cannot be, because it drives the response thread rather than calling the header builder.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_large_response_read_leaves_as_one_gso_frame() {
        let (header, frame, payload) = gso_frame_for_one_relay_read();
        assert_eq!(
            header[0] & VIRTIO_NET_HDR_F_NEEDS_CSUM,
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            "the kernel completes the checksum"
        );
        assert_eq!(header[1], VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(
            usize::from(u16::from_ne_bytes([header[4], header[5]])),
            60,
            "the split size is the flow's MSS"
        );
        let (ip, body) = ipv4_head(&frame).unwrap();
        let (_tcp, carried) = tcp_head(body).unwrap();
        assert_eq!(
            carried,
            payload.as_slice(),
            "one GSO frame carries the whole read"
        );
        // The offload field is the pseudo-header sum in network order, the same value the header-only test pins without the segment the kernel adds.
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&ip.source);
        pseudo.extend_from_slice(&ip.destination);
        pseudo.extend_from_slice(&[0, TCP_PROTO]);
        pseudo.extend_from_slice(&(body.len() as u16).to_be_bytes());
        let mut sum = 0u32;
        for word in pseudo.as_chunks::<2>().0 {
            sum += u32::from(u16::from_be_bytes(*word));
        }
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!(
            u16::from_be_bytes([body[16], body[17]]),
            (sum & 0xffff) as u16,
            "the partial checksum is the pseudo-header sum in the network order the kernel folds"
        );
    }

    /// A multi-queue device's gate: the queue that never saw the handshake still finds the flow, so a flow the kernel hashes across queues is not stalled.
    #[cfg(unix)]
    #[test]
    fn a_flow_opened_on_one_queue_is_served_from_another() {
        let (a, mut first) = unix_socketpair().unwrap();
        let (b, mut second) = unix_socketpair().unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let relay: Relay = Arc::new(move |mut conn: Connection, _lane, _dest| {
            let mut got = [0u8; 5];
            conn.read_exact(&mut got)?;
            let _ = seen_tx.send(got);
            Ok(())
        });
        let flows = Flows::default();
        let spec = Spec::new(None, None);
        let mut one = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            Arc::clone(&relay),
            no_associate(),
            None,
            None,
            flows.clone(),
            Legs::default(),
            &spec,
        );
        let mut two = Handler::on(
            Device::from_handle(b, DEFAULT_MTU),
            relay,
            no_associate(),
            None,
            None,
            flows,
            Legs::default(),
            &spec,
        );
        let client = ([10, 0, 0, 2], 44444);
        let endpoint = ([10, 0, 0, 1], 8080);
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let mut reply = vec![0u8; DEFAULT_MTU + 64];

        let syn = build_tcp_packet(client, endpoint, 1000, 0, FLAG_SYN, 65535, &[]);
        first.write_all(&syn).unwrap();
        let n = one.device.read_packet(&mut buf).unwrap();
        one.dispatch(&buf[..n]).unwrap();
        assert!(first.read(&mut reply).unwrap() > 0, "the SYN-ACK leaves");

        let data = build_tcp_packet(
            client,
            endpoint,
            1001,
            1002,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"queue",
        );
        second.write_all(&data).unwrap();
        let n = two.device.read_packet(&mut buf).unwrap();
        two.dispatch(&buf[..n]).unwrap();

        assert_eq!(
            seen_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            *b"queue",
            "the second queue delivers the payload to the flow's relay"
        );
        let n = second.read(&mut reply).unwrap();
        let (_ip, body) = ipv4_head(&reply[..n]).unwrap();
        let (tcp, _) = tcp_head(body).unwrap();
        assert_eq!(
            tcp.flags & FLAG_ACK,
            FLAG_ACK,
            "the second queue acknowledges what it found"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_offload_refusal_is_retried_without_it() {
        assert!(offload_refused(&io::Error::from_raw_os_error(libc::EINVAL)));
        assert!(offload_refused(&io::Error::new(
            io::ErrorKind::Unsupported,
            "offload"
        )));
        assert!(!offload_refused(&io::Error::from_raw_os_error(libc::EPERM)));
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_descriptor_does_not_claim_gso() {
        let (handle, _peer) = unix_socketpair().unwrap();
        let device = Device::from_handle(handle, 1500);
        assert!(!device.clone_writer().unwrap().gso());
    }

    #[cfg(unix)]
    #[test]
    fn a_framed_packet_takes_one_write() {
        let (mut writer, mut reader) = unix_socketpair().unwrap();
        let packet = [0x45u8; 20];
        for framing in [Framing::Raw, Framing::Utun, Framing::Virtio] {
            let mut expected = match framing {
                Framing::Raw => Vec::new(),
                Framing::Utun => vec![0, 0, 0, UTUN_AF_INET],
                Framing::Virtio => virtio_header(&packet, None).to_vec(),
            };
            expected.extend_from_slice(&packet);
            assert!(write_framed(&mut writer, framing, None, &packet).unwrap());
            let mut got = [0u8; 64];
            let n = reader.read(&mut got).unwrap();
            assert_eq!(&got[..n], expected, "{framing:?} split its frame");
        }
    }

    #[test]
    fn a_quoted_v6_flow_is_read_through_an_extension_header() {
        let mut quoted = vec![0u8; IPV6_HEADER + 16];
        quoted[0] = 0x60;
        quoted[6] = 0;
        quoted[7] = 64;
        quoted[8..24].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        quoted[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        quoted[40] = TCP_PROTO;
        quoted[48..50].copy_from_slice(&443u16.to_be_bytes());
        quoted[50..52].copy_from_slice(&12345u16.to_be_bytes());
        let (flow, seq) = quoted_flow(&quoted).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(flow.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.source_port, 12345);
        assert_eq!(flow.destination_port, 443);
        assert_eq!(flow.destination, "2001:db8::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn an_ipv6_tcp_packet_parses_and_renders_with_its_checksum() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::1".parse().unwrap();
        let pkt = build_ipv6_tcp_packet(
            (source, 12345),
            (destination, 443),
            1000,
            1001,
            FLAG_SYN | FLAG_ACK,
            65535,
            b"v6",
        );
        assert_eq!(pkt[0] >> 4, 6);
        let (ip, body) = ip_head(&pkt).unwrap();
        assert_eq!(ip.source, source);
        assert_eq!(ip.destination, destination);
        assert_eq!(ip.protocol, TCP_PROTO);
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 443);
        assert_eq!(payload, b"v6");
        let (from, to) = octets(source, destination);
        assert_eq!(tcp_checksum(&from, &to, body), 0);
    }

    #[test]
    fn an_ipv6_extension_header_is_walked_to_the_transport() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::1".parse().unwrap();
        let tcp = build_ipv6_tcp_packet((source, 7), (destination, 8), 1, 2, FLAG_ACK, 4096, b"x");
        let mut pkt = Vec::with_capacity(tcp.len() + 8);
        pkt.extend_from_slice(&tcp[..IPV6_HEADER]);
        pkt[6] = 60;
        pkt[4..6].copy_from_slice(&((tcp.len() - IPV6_HEADER + 8) as u16).to_be_bytes());
        pkt.extend_from_slice(&[TCP_PROTO, 0, 1, 4, 0, 0, 0, 0]);
        pkt.extend_from_slice(&tcp[IPV6_HEADER..]);
        let (ip, body) = ip_head(&pkt).unwrap();
        assert_eq!(ip.protocol, TCP_PROTO);
        assert_eq!(tcp_head(body).unwrap().1, b"x");
    }

    #[test]
    fn an_icmp_error_quotes_the_flow_it_ends() {
        let remote: IpAddr = "2001:db8::2".parse().unwrap();
        let client: IpAddr = "2001:db8::1".parse().unwrap();
        let quoted =
            build_ipv6_tcp_packet((remote, 443), (client, 5555), 9, 10, FLAG_ACK, 4096, b"");
        let mut body = vec![2, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&quoted[..IPV6_HEADER + 8]);
        let (key, seq) = icmp_error_flow(ICMPV6_PROTO, &body).unwrap();
        assert_eq!(seq, 9);
        assert_eq!(key.source_port, 5555);
        assert_eq!(key.source, client);
        assert_eq!(key.destination, remote);
        assert_eq!(key.destination_port, 443);
    }

    #[test]
    fn a_v4_icmp_error_quotes_the_flow_it_ends() {
        let quoted = build_tcp_packet(
            ([203, 0, 113, 7], 443),
            ([10, 0, 0, 2], 5555),
            9,
            10,
            FLAG_ACK,
            4096,
            b"",
        );
        let mut body = vec![3, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&quoted[..IPV4_HEADER + 8]);
        let (key, seq) = icmp_error_flow(ICMP_PROTO, &body).unwrap();
        assert_eq!(seq, 9);
        assert_eq!(key.source_port, 5555);
        assert_eq!(key.source, IpAddr::V4([10, 0, 0, 2].into()));
        assert_eq!(key.destination, IpAddr::V4([203, 0, 113, 7].into()));
        assert_eq!(key.destination_port, 443);
    }

    #[test]
    fn a_path_mtu_report_names_the_segment_size_left_for_the_path() {
        let v4 = [3, 4, 0, 0, 0, 0, 0x04, 0xb0];
        assert_eq!(reported_mtu(ICMP_PROTO, &v4), Some(1200));
        assert_eq!(
            reported_mtu(ICMP_PROTO, &[3, 3, 0, 0, 0, 0, 0x04, 0xb0]),
            None
        );
        let v6 = [2, 0, 0, 0, 0, 0, 0x04, 0xb0];
        assert_eq!(reported_mtu(ICMPV6_PROTO, &v6), Some(1280));
        assert_eq!(reported_mtu(ICMPV6_PROTO, &[1, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(path_mss(1200, false), 1160);
        assert_eq!(path_mss(1200, true), 1140);
        assert_eq!(path_mss(40, true), SMALLEST_MSS);
    }

    #[test]
    fn a_v6_echo_request_flips_to_a_v6_reply() {
        let request = [128u8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
        let mut out = Vec::new();
        render_icmp_reply_ip(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            &request,
            &mut out,
        );
        assert_eq!(out[0] >> 4, 6);
        assert_eq!(out[IPV6_HEADER], ICMPV6_ECHO_REPLY);
    }

    #[test]
    fn the_payload_is_borrowed_from_the_read_buffer() {
        // Pointer identity, not bytes: a parsing copy returns the same bytes from a moved base.
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 5),
            ([10, 0, 0, 1], 6),
            100,
            0,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"borrow me",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        let base = pkt.as_ptr() as usize;
        assert_eq!(payload.as_ptr() as usize, base + IPV4_HEADER + 20);
        assert!(payload.as_ptr() as usize + payload.len() <= base + pkt.len());
    }

    #[test]
    fn build_tcp_packet_roundtrips() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 1], 443),
            ([10, 0, 0, 2], 55555),
            100,
            200,
            FLAG_SYN | FLAG_ACK,
            65535,
            b"x",
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.source, [10, 0, 0, 1]);
        assert_eq!(ip.destination, [10, 0, 0, 2]);
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"x");
    }

    /// The emit path reallocates nothing under steady traffic: warm one render, then require the reused buffer's base pointer and capacity to survive every later TCP and ICMP render, and each render's bytes to equal a fresh build — the witness that buffer reuse leaks no stale byte a throwaway vector would not have carried.
    #[test]
    fn an_emitted_packet_reuses_its_render_buffer() {
        let src = ([10, 0, 0, 1], 443);
        let dst = ([10, 0, 0, 2], 55555);
        let mut out = Vec::new();
        render_tcp_packet(
            src,
            dst,
            100,
            200,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"0123456789",
            &mut out,
        );
        let warm_ptr = out.as_ptr() as usize;
        let warm_cap = out.capacity();
        for payload in [&[][..], &b"hi"[..], &b"borrow me"[..], &b"0123456789"[..]] {
            render_tcp_packet(
                src,
                dst,
                100,
                200,
                FLAG_PSH | FLAG_ACK,
                65535,
                payload,
                &mut out,
            );
            assert_eq!(
                out.as_ptr() as usize,
                warm_ptr,
                "no reallocation across the emit cycle"
            );
            assert_eq!(out.capacity(), warm_cap, "capacity held steady");
            assert_eq!(out.len(), IPV4_HEADER + 20 + payload.len());
            assert_eq!(
                out,
                build_tcp_packet(src, dst, 100, 200, FLAG_PSH | FLAG_ACK, 65535, payload),
                "a reused render is byte-identical to a fresh one"
            );
        }
        let request = [8u8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
        render_icmp_reply([10, 0, 0, 1], [10, 0, 0, 2], &request, &mut out);
        assert_eq!(
            out.as_ptr() as usize,
            warm_ptr,
            "the icmp reply rides the same buffer"
        );
        assert_eq!(
            out,
            build_icmp_reply([10, 0, 0, 1], [10, 0, 0, 2], &request),
            "a reused icmp render is byte-identical to a fresh one"
        );
    }

    /// The field a GSO frame hands the kernel is the folded pseudo-header sum, at either family: the in-place sum reads only the address runs, so the twelve- and forty-byte headers it replaces must still name the same value.
    #[test]
    fn a_gso_frame_carries_the_folded_pseudo_sum() {
        fn materialised(source: IpAddr, destination: IpAddr, tcp_len: usize) -> u16 {
            let mut pseudo = [0u8; IPV6_HEADER + 8];
            let len = match (source, destination) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    pseudo[..4].copy_from_slice(&source.octets());
                    pseudo[4..8].copy_from_slice(&destination.octets());
                    pseudo[9] = TCP_PROTO;
                    pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
                    12
                }
                (IpAddr::V6(source), IpAddr::V6(destination)) => {
                    pseudo[..16].copy_from_slice(&source.octets());
                    pseudo[16..32].copy_from_slice(&destination.octets());
                    pseudo[32..36].copy_from_slice(&(tcp_len as u32).to_be_bytes());
                    pseudo[39] = TCP_PROTO;
                    40
                }
                _ => unreachable!("one family"),
            };
            !ferrox_core::foxy::connectip::checksum(&pseudo[..len])
        }
        let segment = [0x5au8; 64];
        for (src, dst, head) in [
            (
                IpAddr::from([10, 0, 0, 1]),
                IpAddr::from([10, 0, 0, 2]),
                IPV4_HEADER,
            ),
            (
                IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
                IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]),
                IPV6_HEADER,
            ),
        ] {
            let mut out = vec![0u8; head + 20 + segment.len()];
            out[head + 20..].copy_from_slice(&segment);
            assert!(render_tcp_headers_ip(
                (src, 443),
                (dst, 55555),
                1,
                2,
                FLAG_PSH | FLAG_ACK,
                65535,
                &[],
                segment.len(),
                true,
                &mut out,
            ));
            let field = u16::from_be_bytes([out[head + 16], out[head + 17]]);
            assert_eq!(field, materialised(src, dst, 20 + segment.len()), "{src}");
        }
    }

    /// One reply packet, built the way the lane builds it.
    fn datagram(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(udp_datagram(
            &UdpDatagram {
                source: source.as_slice(),
                destination: destination.as_slice(),
                source_port,
                destination_port,
                payload,
            },
            &mut out,
        ));
        out
    }

    /// The device's datagram leaves as a head this handler builds and the device's own payload:
    /// the payload pointer is the tail, and the head's capacity is held over a push/drain cycle.
    #[test]
    fn a_device_datagram_hands_the_payload_over_by_pointer() {
        let target: SocketAddr = "[2001:db8::7]:53".parse().expect("addr");
        let payload = b"query";
        let mut head = Vec::with_capacity(FRAME_CAP);
        let base = head.as_ptr() as usize;
        let capacity = head.capacity();
        for _ in 0..2 {
            let (front, tail) = crate::proxy::socks_udp_parts(&mut head, &target, payload);
            assert_eq!(tail.as_ptr(), payload.as_ptr(), "no payload copy");
            assert_eq!(front.len(), 22, "the widest head is an IPv6 address");
            assert_eq!(head.as_ptr() as usize, base, "the head does not move");
            assert_eq!(head.capacity(), capacity, "the head does not grow");
        }
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let (front, tail) = crate::proxy::socks_udp_parts(&mut head, &target, payload);
            assert_eq!(front.len(), 22);
            assert_eq!(tail.len(), payload.len());
        });
        assert_eq!(counts.allocs, 0, "the warm head costs no heap buffer");
    }

    struct RefuseOnce {
        writes: usize,
        accepted: Vec<u8>,
    }

    impl Write for RefuseOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "one packet refused",
                ));
            }
            self.accepted.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_refused_packet_does_not_end_the_flow() {
        let mut writer = RefuseOnce {
            writes: 0,
            accepted: Vec::new(),
        };
        assert!(
            !write_packet_to(&mut writer, b"refused").expect("the refusal is reported"),
            "a refused packet is dropped"
        );
        assert!(
            write_packet_to(&mut writer, b"carried").expect("the next packet is written"),
            "the next packet is carried"
        );
        assert_eq!(
            writer.accepted, b"carried",
            "the packet after a refusal still reaches the device"
        );
    }

    struct InterruptOnce {
        writes: usize,
        accepted: Vec<u8>,
    }

    impl Write for InterruptOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == 1 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.accepted.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_interrupted_packet_write_is_retried() {
        let mut writer = InterruptOnce {
            writes: 0,
            accepted: Vec::new(),
        };
        assert!(
            write_packet_to(&mut writer, b"retried").expect("the retry carries the packet"),
            "a transient signal is retried, not treated as a refusal"
        );
        assert_eq!(writer.accepted, b"retried");
    }

    #[test]
    fn udp_head_parses_a_datagram() {
        let pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 51500, 53, b"query");
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.protocol, PROTOCOL_UDP);
        let (udp, payload) = udp_head(body).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (51500, 53));
        assert_eq!(payload, b"query");
    }

    #[test]
    fn udp_head_refuses_a_forged_length() {
        // A length field that disagrees with the body is refused, never read past.
        let mut pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 5, 6, b"ab");
        let forged = ((UDP_HEADER + 400) as u16).to_be_bytes();
        pkt[IPV4_HEADER + 4..IPV4_HEADER + 6].copy_from_slice(&forged);
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        assert!(udp_head(body).is_none());
        assert!(udp_head(&[0u8; 4]).is_none());
    }

    #[test]
    fn the_datagram_is_borrowed_from_the_read_buffer() {
        // Pointer identity, not bytes: the parse returns the packet's own storage.
        let pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 5, 6, b"borrow me");
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_udp, payload) = udp_head(body).unwrap();
        let base = pkt.as_ptr() as usize;
        assert_eq!(payload.as_ptr() as usize, base + IPV4_HEADER + UDP_HEADER);
        assert!(payload.as_ptr() as usize + payload.len() <= base + pkt.len());
    }

    #[test]
    fn the_reply_packet_verifies_at_the_reference_reader() {
        // Built here, verified by the core's own checksumming walk: the same bytes a peer's stack reads.
        let pkt = datagram([198, 51, 100, 7], [10, 0, 0, 2], 53, 51500, b"an answer");
        let read =
            ferrox_core::foxy::connectip::udp_from_packet(&pkt).expect("a readable datagram");
        assert!(read.verified, "both checksums hold");
        assert_eq!(read.payload, b"an answer");
        assert_eq!((read.source_port, read.destination_port), (53, 51500));
    }

    #[cfg(unix)]
    #[test]
    fn a_syn_flow_replies_syn_ack_over_a_socketpair() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;

        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(device, relay, no_associate());

        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &syn[..]);
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        assert!(rn > 0);
        let (_rip, rbody) = ipv4_head(&reply[..rn]).unwrap();
        let (rtcp, _) = tcp_head(rbody).unwrap();
        assert_eq!(rtcp.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(rtcp.source_port, 8080);
        assert_eq!(rtcp.destination_port, 44444);
        assert_eq!(rtcp.ack_num, 1001);
        assert_eq!(
            rtcp.options,
            [2, 4, 0x05, 0xb4],
            "a SYN without options still learns the MSS, and no scale"
        );
        assert_eq!(window_shift(rtcp.options), None, "no scale was offered");
    }

    /// A flow over a device the test drives by hand, with both cursors where the assertions below read them.
    #[cfg(unix)]
    fn test_flow(rcv: u32, snd: u32) -> Flow {
        Flow {
            id: 1,
            isn: 999,
            server_isn: 1000,
            peer_shift: 0,
            write_half: Mutex::new(None),
            rcv_nxt: Arc::new(AtomicU32::new(rcv)),
            snd_nxt: Arc::new(AtomicU32::new(snd)),
            busy: Arc::new(AtomicBool::new(false)),
            last_acked: AtomicU32::new(rcv),
            local: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
            remote: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 44444),
            mss: Arc::new(AtomicU32::new(1460)),
            send: Arc::new(SendWindow::new(snd, 65535)),
            signaled: Arc::new(AtomicBool::new(false)),
            misses: AtomicU32::new(0),
            read_gate: Mutex::new(()),
            upload_finished: UploadFinished::default(),
        }
    }

    /// The queue takes the answer its own upload earned: bytes already sitting in the lane leave as one segment that carries the request's ack and the cursor moves by what it carried, and a caller that expects no answer is handed nothing rather than waited on.
    #[cfg(unix)]
    #[test]
    fn an_armed_flow_serves_the_answer_the_lane_already_holds() {
        let (device_end, mut peer) = unix_socketpair().unwrap();
        let device = Device::from_handle(device_end, DEFAULT_MTU);
        let mut handler = Handler::new(device, Arc::new(|_, _, _| Ok(())), no_associate());
        let (lane, mut far) = UnixStream::pair().unwrap();
        let mut lane = Connection::from(lane);
        far.write_all(b"answer").unwrap();
        let flow = test_flow(5_000, 2_000);
        assert_eq!(
            handler.serve_inline(&mut lane, &flow),
            Served::Ack(5_000),
            "the answer the lane already holds is served on this thread, carrying the cursor the flow held"
        );
        let mut out = vec![0u8; DEFAULT_MTU + 64];
        let n = peer.read(&mut out).unwrap();
        let (_ip, body) = ipv4_head(&out[..n]).unwrap();
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"answer", "the bytes the lane held");
        assert_eq!(tcp.flags, FLAG_PSH | FLAG_ACK);
        assert_eq!(tcp.seq, 2_000);
        assert_eq!(tcp.ack_num, 5_000, "the request's ack rides the answer");
        assert_eq!(flow.snd_nxt.load(Relaxed), 2_006);
        assert_eq!(
            handler.serve_inline(&mut lane, &flow),
            Served::None,
            "a lane with nothing queued is handed nothing"
        );
        assert_eq!(
            flow.misses.load(Relaxed),
            1,
            "an answer that did not come is counted against the wait"
        );
        flow.misses.store(PING_PONG_MISSES, Relaxed);
        assert_eq!(
            handler.serve_inline(&mut lane, &flow),
            Served::None,
            "a flow that stopped landing answers is read once and not waited on"
        );
    }

    /// An answer consumed off the lane and refused by the device leaves a hole no retransmit can fill, so the flow ends here the way the response thread ends it.
    #[cfg(unix)]
    #[test]
    fn a_refused_inline_answer_ends_the_flow() {
        let (device_end, _reader) = full_pipe().unwrap();
        let device = Device::from_handle(device_end, DEFAULT_MTU);
        let mut handler = Handler::new(device, Arc::new(|_, _, _| Ok(())), no_associate());
        let (lane, mut far) = UnixStream::pair().unwrap();
        far.write_all(b"answer").unwrap();
        let flow = test_flow(5_000, 2_000);
        flow.misses.store(PING_PONG_MISSES, Relaxed);
        let mut guard = flow.write_half.lock().unwrap();
        *guard = Some(Connection::from(lane));
        assert_eq!(
            handler.serve_inline(guard.as_mut().unwrap(), &flow),
            Served::Failed,
            "a refused segment is not an answer"
        );
        drop(guard);
        handler.retire(&flow, Some(FLAG_RST | FLAG_ACK));
        assert!(
            flow.signaled.load(Relaxed),
            "the flow is ended instead of acknowledged for bytes it never carried"
        );
    }

    /// The cursor a ready segment takes is the one the segment before it left, so the gate that keeps a queue and the response thread apart cannot number the stream out of order.
    #[cfg(unix)]
    #[test]
    fn each_ready_segment_takes_the_cursor_the_one_before_it_left() {
        let (lane, mut far) = UnixStream::pair().unwrap();
        let mut lane = Connection::from(lane);
        let flow = test_flow(5_000, 1_000);
        let mut buf = [0u8; 16];
        let cap = buf.len();
        far.write_all(b"abc").unwrap();
        let (n, seq) = read_upstream(
            &flow,
            &flow.read_gate,
            &mut lane,
            &mut buf,
            cap,
            std::time::Duration::from_millis(10),
            &flow.snd_nxt,
        )
        .unwrap()
        .unwrap();
        assert_eq!((n, seq, &buf[..n]), (3, 1_000, &b"abc"[..]));
        far.write_all(b"def").unwrap();
        let (n, seq) = read_upstream(
            &flow,
            &flow.read_gate,
            &mut lane,
            &mut buf,
            cap,
            std::time::Duration::from_millis(10),
            &flow.snd_nxt,
        )
        .unwrap()
        .unwrap();
        assert_eq!((n, seq, &buf[..n]), (3, 1_003, &b"def"[..]));
        assert_eq!(flow.snd_nxt.load(Relaxed), 1_006);
    }

    /// A read that finds the window spent under the park hands the cursor back instead of spending bytes the peer is not waiting for.
    #[cfg(unix)]
    #[test]
    fn a_read_whose_window_closed_under_it_spends_nothing() {
        let (lane, mut far) = UnixStream::pair().unwrap();
        let mut lane = Connection::from(lane);
        let flow = test_flow(5_000, 1_000);
        flow.send.acked(1_000, 0, 1_000);
        let mut buf = [0u8; 16];
        let cap = buf.len();
        far.write_all(b"abc").unwrap();
        assert_eq!(
            read_upstream(
                &flow,
                &flow.read_gate,
                &mut lane,
                &mut buf,
                cap,
                std::time::Duration::from_millis(10),
                &flow.snd_nxt,
            )
            .unwrap(),
            None,
            "a shut window is not a readable socket"
        );
        assert_eq!(flow.snd_nxt.load(Relaxed), 1_000, "no cursor moved");
    }

    /// A device whose MSS is smaller than the SYN-ACK's own options still answers the handshake: the buffer is sized for the larger of the two, where before the header slice ran past it.
    #[cfg(unix)]
    #[test]
    fn a_tiny_mtu_still_answers_the_syn_with_options() {
        for (mtu, options, expected) in [
            (41, &[][..], &[2, 4, 0, 1][..]),
            (48, &[1, 3, 3, 7][..], &[2, 4, 0, 8, 1, 3, 3, 5][..]),
        ] {
            let (a, b) = unix_socketpair().unwrap();
            let device = Device::from_handle(a, mtu);
            let mut peer = b;

            let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
            let mut handler = Handler::new(device, relay, no_associate());

            let syn = build_tcp_packet_options(
                ([10, 0, 0, 2], 44444),
                ([10, 0, 0, 1], 8080),
                1000,
                0,
                FLAG_SYN,
                65535,
                options,
                &[],
            );
            peer.write_all(&syn).unwrap();

            let mut buf = vec![0u8; DEFAULT_MTU + 64];
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();

            let mut reply = vec![0u8; 128];
            let rn = peer.read(&mut reply).unwrap();
            let (_ip, body) = ipv4_head(&reply[..rn]).unwrap();
            let (rtcp, carried) = tcp_head(body).unwrap();
            assert_eq!(rtcp.flags, FLAG_SYN | FLAG_ACK, "an MTU of {mtu}");
            assert_eq!(rtcp.options, expected, "an MTU of {mtu}");
            assert_eq!(carried, [], "an MTU of {mtu}");
            assert_eq!(
                tcp_checksum(&[10, 0, 0, 1], &[10, 0, 0, 2], &reply[IPV4_HEADER..rn]),
                0
            );
        }
    }

    /// A SYN that offers a window scale is answered with the device's MSS and our scale, so both directions leave the sixty-four-kilobyte ceiling; the options sit inside the checksummed header.
    #[cfg(unix)]
    #[test]
    fn a_syn_that_offers_a_scale_is_answered_with_one() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;

        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(device, relay, no_associate());

        // The option set a Linux client sends: MSS, SACK permitted, timestamps, a NOP and a scale of seven.
        let options = [
            2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        assert_eq!(window_shift(&options), Some(7));
        let syn = build_tcp_packet_options(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &options,
            &[],
        );
        peer.write_all(&syn).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; 128];
        let rn = peer.read(&mut reply).unwrap();
        let (_ip, body) = ipv4_head(&reply[..rn]).unwrap();
        let (rtcp, carried) = tcp_head(body).unwrap();
        assert!(carried.is_empty(), "the SYN-ACK carries no payload");
        assert_eq!(rtcp.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(
            &rtcp.options[..4],
            &[2, 4, 0x05, 0xb4],
            "an MSS of 1460 for a 1500-byte device"
        );
        assert_eq!(window_shift(rtcp.options), Some(OUR_WINDOW_SHIFT));
        assert_eq!(
            tcp_checksum(&[10, 0, 0, 1], &[10, 0, 0, 2], &reply[IPV4_HEADER..rn]),
            0,
            "the options are covered by the checksum"
        );
    }

    #[test]
    fn a_non_echo_icmp_message_is_refused() {
        // The three shapes that are not an IPv4 echo request the handler would answer.
        assert!(
            !is_echo_request(ICMP_PROTO, &[0, 0, 0, 0, 0, 0, 0, 0]),
            "an echo reply"
        );
        assert!(
            !is_echo_request(ICMP_PROTO, &[8, 3, 0, 0, 0, 0, 0, 0]),
            "a non-zero code"
        );
        assert!(
            !is_echo_request(ICMP_PROTO, &[8, 0, 0, 0]),
            "shorter than the eight-byte header"
        );
        assert!(
            is_echo_request(ICMP_PROTO, &[8, 0, 0, 0, 0, 0, 0, 0]),
            "a well-formed request"
        );
        assert!(
            is_echo_request(ICMPV6_PROTO, &[128, 0, 0, 0, 0, 0, 0, 0]),
            "a well-formed v6 request"
        );
    }

    /// One IPv4 ICMP echo request, rendered independently of the reply so the round trip
    /// is not self-consistent: type 8, code 0, a carried identifier, sequence and data.
    #[cfg(unix)]
    fn icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let ip_len = IPV4_HEADER + 8 + data.len();
        let mut pkt = vec![0u8; ip_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = ICMP_PROTO;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let c = ipv4_checksum(&pkt[..IPV4_HEADER]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        let m = &mut pkt[IPV4_HEADER..];
        m[0] = ICMP_ECHO_REQUEST;
        m[4..6].copy_from_slice(&id.to_be_bytes());
        m[6..8].copy_from_slice(&seq.to_be_bytes());
        m[8..].copy_from_slice(data);
        let ic = checksum(m);
        m[2..4].copy_from_slice(&ic.to_be_bytes());
        pkt
    }

    #[cfg(unix)]
    #[test]
    fn an_icmp_echo_request_is_answered_as_a_reply() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(device, relay, no_associate());

        let request = icmp_echo([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 0x0007, b"ping data");
        peer.write_all(&request).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let rn = peer.read(&mut reply).unwrap();
        let (rip, rbody) = ipv4_head(&reply[..rn]).unwrap();
        assert_eq!(rip.protocol, ICMP_PROTO);
        // answered as the address the request asked, back to the pinger
        assert_eq!(rip.source, [10, 0, 0, 1]);
        assert_eq!(rip.destination, [10, 0, 0, 2]);
        assert_eq!(
            ipv4_checksum(&reply[..IPV4_HEADER]),
            0,
            "the header verifies"
        );
        // an echo reply whose own checksum holds, carrying the message back unchanged
        assert_eq!(rbody[0], ICMP_ECHO_REPLY);
        assert_eq!(rbody[1], 0);
        assert_eq!(
            checksum(rbody),
            0,
            "the reply carries a valid ICMP checksum"
        );
        assert_eq!(&rbody[4..8], &[0x12, 0x34, 0x00, 0x07]);
        assert_eq!(&rbody[8..], b"ping data");
    }

    #[cfg(unix)]
    #[test]
    fn a_packet_too_big_shrinks_the_response_segment() {
        let (a, b) = unix_socketpair().unwrap();
        let (_release, hold) = std::sync::mpsc::channel::<()>();
        let hold = Arc::new(std::sync::Mutex::new(hold));
        let relay: Relay = Arc::new(move |_conn, _lane, _dest| {
            let _ = hold.lock().unwrap().recv();
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut peer = b;
        let client = ([10, 0, 0, 2], 44444);
        let endpoint = ([10, 0, 0, 1], 8080);
        let syn = build_tcp_packet(client, endpoint, 1000, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let key = FlowKey {
            source: IpAddr::V4(client.0.into()),
            source_port: 44444,
            destination: IpAddr::V4(endpoint.0.into()),
            destination_port: 8080,
        };
        assert_eq!(
            handler.flows.table().get(&key).unwrap().mss.load(Relaxed),
            (DEFAULT_MTU - IPV4_HEADER - 20) as u32
        );
        let sent = handler
            .flows
            .table()
            .get(&key)
            .unwrap()
            .snd_nxt
            .load(Relaxed)
            .wrapping_sub(1);

        let quoted = build_tcp_packet(
            (endpoint.0, 8080),
            (client.0, 44444),
            sent,
            1001,
            FLAG_ACK,
            65535,
            &[],
        );
        let mut pkt = vec![0u8; IPV4_HEADER + 8 + IPV4_HEADER + 8];
        let len = pkt.len() as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = ICMP_PROTO;
        pkt[12..16].copy_from_slice(&endpoint.0);
        pkt[16..20].copy_from_slice(&client.0);
        let body = &mut pkt[IPV4_HEADER..];
        body[0] = 3;
        body[1] = 4;
        body[6..8].copy_from_slice(&1200u16.to_be_bytes());
        body[8..8 + IPV4_HEADER + 8].copy_from_slice(&quoted[..IPV4_HEADER + 8]);
        handler.dispatch(&pkt).unwrap();

        assert_eq!(
            handler.flows.table().get(&key).unwrap().mss.load(Relaxed),
            1160
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_v6_packet_too_big_shrinks_the_response_segment() {
        let (a, b) = unix_socketpair().unwrap();
        let (_release, hold) = std::sync::mpsc::channel::<()>();
        let hold = Arc::new(std::sync::Mutex::new(hold));
        let relay: Relay = Arc::new(move |_conn, _lane, _dest| {
            let _ = hold.lock().unwrap().recv();
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut peer = b;
        let client: IpAddr = "2001:db8::2".parse().unwrap();
        let endpoint: IpAddr = "2001:db8::1".parse().unwrap();
        let syn = build_ipv6_tcp_packet(
            (client, 44444),
            (endpoint, 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let key = FlowKey {
            source: client,
            source_port: 44444,
            destination: endpoint,
            destination_port: 8080,
        };
        assert_eq!(
            handler.flows.table().get(&key).unwrap().mss.load(Relaxed),
            (DEFAULT_MTU - IPV6_HEADER - 20) as u32
        );
        let sent = handler
            .flows
            .table()
            .get(&key)
            .unwrap()
            .snd_nxt
            .load(Relaxed)
            .wrapping_sub(1);

        let quoted = build_ipv6_tcp_packet(
            (endpoint, 8080),
            (client, 44444),
            sent,
            1001,
            FLAG_ACK,
            65535,
            &[],
        );
        let mut pkt = vec![0u8; IPV6_HEADER + 8 + IPV6_HEADER + 8];
        let payload = (pkt.len() - IPV6_HEADER) as u16;
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&payload.to_be_bytes());
        pkt[6] = ICMPV6_PROTO;
        pkt[7] = 64;
        let (from, to) = octets(endpoint, client);
        pkt[8..24].copy_from_slice(&from);
        pkt[24..40].copy_from_slice(&to);
        let body = &mut pkt[IPV6_HEADER..];
        body[0] = 2;
        body[4..8].copy_from_slice(&1200u32.to_be_bytes());
        body[8..8 + IPV6_HEADER + 8].copy_from_slice(&quoted[..IPV6_HEADER + 8]);
        handler.dispatch(&pkt).unwrap();

        assert_eq!(
            handler.flows.table().get(&key).unwrap().mss.load(Relaxed),
            1220
        );
    }

    /// A full pipe with its read end open: a device that refuses a write without a hangup for `poll`.
    #[cfg(unix)]
    fn full_pipe() -> io::Result<(std::fs::File, std::fs::File)> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        let chunk = [0u8; 4096];
        loop {
            match writer.write(&chunk) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok((writer, reader))
    }

    #[cfg(unix)]
    fn unix_socketpair() -> io::Result<(std::fs::File, std::fs::File)> {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe {
            std::fs::File::from_raw_fd(fds[1])
        }))
    }

    #[cfg(unix)]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// One `FLOW` line of `scripts/tun-oracle/script.txt`: the destination the packet
    /// names, the client port, the SYN sequence, and the payload chunks as separate
    /// segments — the same rendering rules the Go oracle reads from that file.
    #[cfg(unix)]
    struct FlowSpec {
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        chunks: Vec<Vec<u8>>,
    }

    /// One `UFLOW` line of the same script: a client source port, a destination, and
    /// each datagram body, rendered by the oracle as one independent IPv4 UDP packet.
    #[cfg(unix)]
    struct DatagramSpec {
        destination: SocketAddr,
        source_port: u16,
        datagrams: Vec<Vec<u8>>,
    }

    #[cfg(unix)]
    const SCRIPT_CLIENT: [u8; 4] = [10, 0, 0, 2];

    #[cfg(unix)]
    fn parse_script(text: &str) -> Vec<FlowSpec> {
        let mut flows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("FLOW") => {}
                Some("UFLOW") => continue,
                other => panic!("the script holds only FLOW and UFLOW lines, found {other:?}"),
            }
            let destination = fields.next().unwrap().parse().unwrap();
            let source_port = fields.next().unwrap().parse().unwrap();
            let syn_seq = fields.next().unwrap().parse().unwrap();
            let chunks = fields.map(hex_decode).collect();
            flows.push(FlowSpec {
                destination,
                source_port,
                syn_seq,
                chunks,
            });
        }
        flows
    }

    #[cfg(unix)]
    fn parse_datagram_script(text: &str) -> Vec<DatagramSpec> {
        let mut flows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("UFLOW") => {}
                Some("FLOW") => continue,
                other => panic!("the script holds only FLOW and UFLOW lines, found {other:?}"),
            }
            let destination = fields.next().unwrap().parse().unwrap();
            let source_port = fields.next().unwrap().parse().unwrap();
            let datagrams = fields.map(hex_decode).collect();
            flows.push(DatagramSpec {
                destination,
                source_port,
                datagrams,
            });
        }
        flows
    }

    /// The dial set the golden records for one transport: every `<keyword> <target>
    /// <hex>` line, sorted. `DIAL` is the TCP half and `UDIAL` the datagram half, so
    /// one file carries both and each differential reads its own kind.
    #[cfg(unix)]
    fn parse_dials(text: &str, keyword: &str) -> Vec<(String, Vec<u8>)> {
        let mut dials = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            if fields.next() != Some(keyword) {
                continue;
            }
            dials.push((
                fields.next().unwrap().to_owned(),
                hex_decode(fields.next().unwrap()),
            ));
        }
        dials.sort();
        dials
    }

    /// The recorded dial set: every (target, payload) pair a relay saw, shared
    /// between the recorder and the tests that wait on it.
    #[cfg(unix)]
    type Dials = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// An association that answers nothing: the stream tests never frame a datagram, and a leg closed at once is what a datagram they did send would deserve.
    #[cfg(unix)]
    fn no_associate() -> Associate {
        Arc::new(|_conn| {})
    }

    /// A dial recorder behind the same `Relay` seam the app installs: it reads each
    /// flow to EOF, exactly as `serve_connect` does, and keeps (target, payload).
    #[cfg(unix)]
    fn recording_relay(results: Dials) -> Relay {
        Arc::new(
            move |mut conn: Connection, _lane, dest: crate::proxy::Destination| {
                let mut payload = Vec::new();
                let _ = conn.read_to_end(&mut payload);
                let target = match dest {
                    crate::proxy::Destination::Address(a) => a.to_string(),
                    crate::proxy::Destination::Name(host, port) => format!("{host}:{port}"),
                };
                results.lock().unwrap().push((target, payload));
                Ok(())
            },
        )
    }

    #[cfg(unix)]
    fn wait_for(results: &Dials, count: usize) {
        for _ in 0..2_500 {
            if results.lock().unwrap().len() == count {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!(
            "{count} dials did not arrive; got {:?}",
            results.lock().unwrap().len()
        );
    }

    /// One client-side flow rendered by the script's rules: SYN, then the ACK whose
    /// acknowledgement number is read off this stack's own SYN-ACK (a reference picks
    /// its initial sequence itself — `tcp_lightweight.go` `rand.Uint32()` — so the
    /// golden cannot pin it), then each payload chunk as one PSH, then FIN.
    #[cfg(unix)]
    fn run_flow(handler: &mut Handler, peer: &mut std::fs::File, flow: &FlowSpec, buf: &mut [u8]) {
        let SocketAddr::V4(destination) = flow.destination else {
            panic!("the script names IPv4 destinations only");
        };
        let dst = destination.ip().octets();
        let dst_port = destination.port();
        let endpoint = (dst, dst_port);
        let client = (SCRIPT_CLIENT, flow.source_port);
        let syn = build_tcp_packet(client, endpoint, flow.syn_seq, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let syn_ack = next_syn_ack(peer);
        assert_eq!(
            syn_ack.flags,
            FLAG_SYN | FLAG_ACK,
            "the handshake opens with a SYN-ACK"
        );
        let peer_ack = syn_ack.seq.wrapping_add(1);

        let ack = build_tcp_packet(
            client,
            endpoint,
            flow.syn_seq.wrapping_add(1),
            peer_ack,
            FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&ack).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut seq = flow.syn_seq.wrapping_add(1);
        for chunk in &flow.chunks {
            let psh = build_tcp_packet(
                client,
                endpoint,
                seq,
                peer_ack,
                FLAG_PSH | FLAG_ACK,
                65535,
                chunk,
            );
            peer.write_all(&psh).unwrap();
            let n = handler.device.read_packet(buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        let fin = build_tcp_packet(
            client,
            endpoint,
            seq,
            peer_ack,
            FLAG_FIN | FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&fin).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
    }

    /// The row's identity claim, checked: the set of (target, payload) dials the
    /// inbound produces from the pinned packet stream equals the golden recorded
    /// from the reference stack by `scripts/tun-oracle`.
    #[cfg(unix)]
    #[test]
    fn the_dial_set_matches_the_pinned_stream() {
        let flows = parse_script(include_str!("../../../scripts/tun-oracle/script.txt"));
        let expected = parse_dials(
            include_str!("../../../scripts/tun-oracle/expected.txt"),
            "DIAL",
        );
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            recording_relay(results.clone()),
            no_associate(),
        );

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for flow in &flows {
            run_flow(&mut handler, &mut peer, flow, &mut buf);
        }
        wait_for(&results, flows.len());

        let mut got: Vec<(String, Vec<u8>)> = results.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, expected, "the dial set is the reference's own");
    }

    /// The direct lane's whole path: the device's bytes reach the dialed stream, the stream's
    /// answer leaves as the device's next segment, and the close that ends it is the stream's own.
    #[cfg(unix)]
    #[test]
    fn a_direct_lane_carries_the_flow_without_the_pair() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let (upstream, mut lane) = UnixStream::pair().unwrap();
        lane.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let dialed = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&dialed);
        let dial: Dial = Arc::new(move |_dest| {
            seen.store(true, Relaxed);
            DialOutcome::Direct(Connection::from(upstream.try_clone().unwrap()))
        });
        let mut handler = Handler::with_dial(
            Device::from_handle(a, DEFAULT_MTU),
            Arc::new(|_conn, _lane, _dest| Ok(())),
            no_associate(),
            dial,
        );

        let client = ([10, 0, 0, 2], 44444);
        let endpoint = ([10, 0, 0, 1], 8080);
        let syn = build_tcp_packet(client, endpoint, 1, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let syn_ack = next_syn_ack(&mut peer);
        assert!(dialed.load(Relaxed), "the direct dial was the lane");

        let ack = syn_ack.seq.wrapping_add(1);
        let request = build_tcp_packet(
            client,
            endpoint,
            2,
            ack,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"ping",
        );
        peer.write_all(&request).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let mut got = [0u8; 4];
        lane.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping", "the device's bytes reach the dialed stream");
        // The push the device just sent is acknowledged before the lane's answer, so the next segment the device reads is that ACK.
        let (ack, ack_payload) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(ack.flags, FLAG_ACK);
        assert_eq!(ack_payload, [] as [u8; 0]);

        lane.write_all(b"pong").unwrap();
        let (reply, payload) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(payload, b"pong", "the stream's answer leaves as a segment");
        assert_eq!(reply.flags, FLAG_PSH | FLAG_ACK);

        lane.shutdown(Shutdown::Write).unwrap();
        let (end, payload) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(end.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(payload, [] as [u8; 0]);

        // The stream closed only its write half: a pause lets a full close shut the pipe first, so this gate fails against the old behaviour.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let upload = build_tcp_packet(
            client,
            endpoint,
            6,
            end.ack_num,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"late",
        );
        peer.write_all(&upload).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let mut got = [0u8; 4];
        lane.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"late", "the upload outlives the download's FIN");
        // The FIN consumed one sequence number: the ACK for the late upload names the sequence after it, not the FIN's own.
        let (late_ack, _) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(late_ack.flags, FLAG_ACK);
        assert_eq!(late_ack.seq, end.seq.wrapping_add(1));
    }

    /// A segment without PSH is still acknowledged: waiting for a push that may never follow
    /// leaves the peer retransmitting bytes this end already holds.
    #[cfg(unix)]
    #[test]
    fn a_segment_without_push_is_answered() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let (upstream, mut lane) = UnixStream::pair().unwrap();
        lane.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let dial: Dial = Arc::new(move |_dest| {
            DialOutcome::Direct(Connection::from(upstream.try_clone().unwrap()))
        });
        let mut handler = Handler::with_dial(
            Device::from_handle(a, DEFAULT_MTU),
            Arc::new(|_conn, _lane, _dest| Ok(())),
            no_associate(),
            dial,
        );

        let client = ([10, 0, 0, 2], 44444);
        let endpoint = ([10, 0, 0, 1], 8080);
        let syn = build_tcp_packet(client, endpoint, 1, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let syn_ack = next_syn_ack(&mut peer);

        let request = build_tcp_packet(
            client,
            endpoint,
            2,
            syn_ack.seq.wrapping_add(1),
            FLAG_ACK,
            65535,
            b"ping",
        );
        peer.write_all(&request).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let mut got = [0u8; 4];
        lane.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping", "the segment reached the lane");
        let (ack, payload) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(ack.flags, FLAG_ACK, "a quiet segment is acknowledged");
        assert_eq!(ack.ack_num, 6, "the ACK names every byte that landed");
        assert_eq!(payload, [] as [u8; 0]);
    }

    /// One queue's dead direct control drops only the legs that rode its relay: a second queue
    /// sharing the table keeps its own leg and socket.
    #[cfg(unix)]
    #[test]
    fn a_dead_control_drops_only_its_own_legs() {
        use std::io::Write;
        let legs = Legs::default();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let queue = |relay: std::net::UdpSocket| {
            let relay_addr = relay.local_addr().unwrap();
            relay.set_nonblocking(true).unwrap();
            let (ctl, ctl_peer) = UnixStream::pair().unwrap();
            let (a, peer) = peer_with_deadline().unwrap();
            let open = Datagram::always(Arc::new(move || {
                Some(crate::proxy::DirectDatagram {
                    relay: relay_addr,
                    control: Connection::from(ctl.try_clone().unwrap()),
                })
            }));
            let relay_fn: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
            let handler = Handler::on(
                Device::from_handle(a, DEFAULT_MTU),
                relay_fn,
                echo_associate(frames.clone()),
                None,
                Some(open),
                Flows::default(),
                legs.clone(),
                &Spec::new(None, None),
            );
            (handler, peer, ctl_peer, relay)
        };
        let (mut one, mut one_peer, one_ctl, one_relay) =
            queue(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let (mut two, mut two_peer, _two_ctl, two_relay) =
            queue(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let key_one = UdpKey {
            source: IpAddr::from(SCRIPT_CLIENT),
            source_port: 51510,
            destination: IpAddr::from([198, 51, 100, 10]),
            destination_port: 53,
        };
        let key_two = UdpKey {
            source_port: 51511,
            ..key_one
        };
        let query_one = datagram(SCRIPT_CLIENT, [198, 51, 100, 10], 51510, 53, b"one");
        let query_two = datagram(SCRIPT_CLIENT, [198, 51, 100, 10], 51511, 53, b"two");
        assert!(
            pump_datagram(&mut one, &mut one_peer, &one_relay, &query_one),
            "the first queue frames at its own relay"
        );
        assert!(
            pump_datagram(&mut two, &mut two_peer, &two_relay, &query_two),
            "the second queue frames at its own relay"
        );
        let dead = one_relay.local_addr().unwrap();
        let healthy = two_relay.local_addr().unwrap();
        assert_eq!(legs.relay_of(&key_one), Some(dead));
        assert_eq!(legs.relay_of(&key_two), Some(healthy));
        drop(one_ctl);
        std::thread::sleep(std::time::Duration::from_millis(50));
        for _ in 0..2_500 {
            if legs.relay_of(&key_one) != Some(dead) {
                break;
            }
            one_peer.write_all(&query_one).unwrap();
            let mut buf = vec![0u8; DEFAULT_MTU + 64];
            let n = one.device.read_packet(&mut buf).unwrap();
            one.dispatch(&buf[..n]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_ne!(
            legs.relay_of(&key_one),
            Some(dead),
            "the dead lane's leg is gone"
        );
        assert_eq!(
            legs.relay_of(&key_two),
            Some(healthy),
            "the other queue's leg keeps its socket"
        );
    }

    /// A direct datagram lane whose control closes is dropped: the legs on its dead relay are
    /// cleared and the datagrams fall back to the front's association until the retry budget.
    #[cfg(unix)]
    #[test]
    fn a_closed_direct_datagram_control_drops_the_lane() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        relay.set_nonblocking(true).unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (ctl, ctl_peer) = UnixStream::pair().unwrap();
        let opens = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&opens);
        let open = Datagram::always(Arc::new(move || {
            seen.fetch_add(1, Relaxed);
            Some(crate::proxy::DirectDatagram {
                relay: relay_addr,
                control: Connection::from(ctl.try_clone().unwrap()),
            })
        }));
        let relay_fn: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            relay_fn,
            echo_associate(frames.clone()),
            None,
            Some(open),
            Flows::default(),
            Legs::default(),
            &Spec::new(None, None),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 9], 51501, 53, b"dead");
        // A datagram rides the lane once the worker installs it.
        let mut rode = false;
        for _ in 0..2_500 {
            peer.write_all(&query).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            if relay.recv(&mut buf[..]).is_ok() {
                rode = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(rode, "a datagram rides the direct lane's relay");
        // The relay ends its control: the next datagram drops the lane and takes the front's association.
        drop(ctl_peer);
        std::thread::sleep(std::time::Duration::from_millis(50));
        for _ in 0..2_500 {
            if !frames.lock().unwrap().is_empty() {
                break;
            }
            peer.write_all(&query).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        wait_for_frames(&frames, 1);
        assert_eq!(
            opens.load(Relaxed),
            1,
            "the retry budget gates a second lane"
        );
    }

    #[cfg(unix)]
    type Frames = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

    /// The association a test answers with: a SOCKS5 UDP server on loopback that keeps every frame it is handed and echoes each one back, so the device's datagram lane is walked end to end without dialing a target.
    #[cfg(unix)]
    fn echo_associate(frames: Frames) -> Associate {
        Arc::new(move |mut client: Connection| {
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).is_err() || client.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut request = [0u8; 10];
            if client.read_exact(&mut request).is_err() {
                return;
            }
            let Ok(relay) = UdpSocket::bind("127.0.0.1:0") else {
                return;
            };
            let Ok(addr) = relay.local_addr() else {
                return;
            };
            let mut reply = vec![5, 0, 0];
            crate::proxy::push_socks_addr(&mut reply, &addr);
            if client.write_all(&reply).is_err() {
                return;
            }
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, src)) = relay.recv_from(&mut buf) else {
                    return;
                };
                let frame = buf[..n].to_vec();
                let Some((target, payload)) = crate::proxy::parse_socks_udp(&frame) else {
                    continue;
                };
                let mut back = vec![0u8, 0, 0];
                crate::proxy::push_socks_addr(&mut back, &target);
                back.extend_from_slice(payload);
                frames.lock().unwrap().push(frame);
                if relay.send_to(&back, src).is_err() {
                    return;
                }
            }
        })
    }

    /// Pump one queue with a datagram until the fake relay receives a frame, so a test can wait
    /// for the asynchronously opened lane without a fixed sleep.
    #[cfg(unix)]
    fn pump_datagram(
        handler: &mut Handler,
        peer: &mut std::fs::File,
        relay: &std::net::UdpSocket,
        packet: &[u8],
    ) -> bool {
        use std::io::Write;
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for _ in 0..2_500 {
            peer.write_all(packet).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            if relay.recv(&mut buf[..]).is_ok() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        false
    }

    #[cfg(unix)]
    fn wait_for_frames(frames: &Frames, count: usize) {
        for _ in 0..2_500 {
            if frames.lock().unwrap().len() >= count {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("{count} frames did not arrive");
    }

    /// The next packet the device wrote, with the same bounded wait the stream tests use: a lane that answers nothing fails rather than parking the suite.
    #[cfg(unix)]
    fn next_datagram(peer: &mut std::fs::File, buf: &mut [u8]) -> usize {
        for _ in 0..2_500 {
            match peer.read(buf) {
                Ok(n) if n > 0 => return n,
                Ok(_) => {}
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no datagram answer came back to the device");
    }

    /// The row's datagram claim, checked: a packet off the device becomes the RFC 1928 request the association names, and the answer comes back re-wrapped for the flow that asked.
    #[cfg(unix)]
    #[test]
    fn a_datagram_flow_frames_the_association_and_returns_the_echo() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            echo_associate(frames.clone()),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 7], 51500, 53, b"who-is");
        peer.write_all(&query).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        // Reserved, fragment, address type, the destination the packet named, then the datagram itself.
        let mut want = vec![0u8, 0, 0, 1, 198, 51, 100, 7, 0, 53];
        want.extend_from_slice(b"who-is");
        wait_for_frames(&frames, 1);
        assert_eq!(
            frames.lock().unwrap().first().map(Vec::as_slice),
            Some(want.as_slice()),
            "the association carries the request the spec writes"
        );

        let n = next_datagram(&mut peer, &mut buf);
        let (ip, body) = ipv4_head(&buf[..n]).unwrap();
        assert_eq!(ip.protocol, PROTOCOL_UDP);
        assert_eq!(
            (ip.source, ip.destination),
            ([198, 51, 100, 7], SCRIPT_CLIENT)
        );
        let (udp, payload) = udp_head(body).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (53, 51500));
        assert_eq!(payload, b"who-is");
    }

    /// A direct datagram lane frames the outbound's own relay and renders its answer without the
    /// front's loopback association: the handler writes the same RFC 1928 request the association
    /// path writes, and the leg reader turns the relay's framed answer back into a device packet.
    #[cfg(unix)]
    #[test]
    fn a_direct_datagram_lane_frames_the_relay_without_the_association() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let relay_address = upstream.local_addr().unwrap();
        let seen = frames.clone();
        // The relay every leg frames onto: the outbound server's own echo, no front association behind it.
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, src)) = upstream.recv_from(&mut buf) {
                let frame = buf[..n].to_vec();
                let Some((target, payload)) = crate::proxy::parse_socks_udp(&frame) else {
                    continue;
                };
                let mut back = vec![0u8, 0, 0];
                crate::proxy::push_socks_addr(&mut back, &target);
                back.extend_from_slice(payload);
                seen.lock().unwrap().push(frame);
                if upstream.send_to(&back, src).is_err() {
                    break;
                }
            }
        });
        let (control, _hold) = UnixStream::pair().unwrap();
        let slot = Arc::new(std::sync::Mutex::new(Some(Connection::from(control))));
        let open = Datagram::always(Arc::new(move || {
            let control = slot.lock().unwrap().take()?;
            Some(crate::proxy::DirectDatagram {
                relay: relay_address,
                control,
            })
        }));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let associate: Associate = Arc::new(|_conn| {
            unreachable!("a direct datagram lane must not open the front association")
        });
        let mut handler = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            associate,
            None,
            Some(open),
            Flows::default(),
            Legs::default(),
            &Spec::new(None, None),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 7], 51500, 53, b"who-is");
        peer.write_all(&query).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        // The lane opens on a worker, so the first datagram is dropped while it dials: turn the queue until the handler holds the lane, then send again.
        for _ in 0..2_500 {
            if handler.direct_datagram.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
            handler.poll_datagram_lane();
        }
        assert!(
            handler.direct_datagram.is_some(),
            "the direct lane opened on its worker"
        );
        peer.write_all(&query).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut want = vec![0u8, 0, 0, 1, 198, 51, 100, 7, 0, 53];
        want.extend_from_slice(b"who-is");
        wait_for_frames(&frames, 1);
        assert_eq!(
            frames.lock().unwrap().first().map(Vec::as_slice),
            Some(want.as_slice()),
            "the direct lane writes the same frame the association path writes"
        );

        let n = next_datagram(&mut peer, &mut buf);
        let (ip, body) = ipv4_head(&buf[..n]).unwrap();
        assert_eq!(
            (ip.source, ip.destination),
            ([198, 51, 100, 7], SCRIPT_CLIENT)
        );
        let (udp, payload) = udp_head(body).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (53, 51500));
        assert_eq!(payload, b"who-is");
    }

    /// A direct lane that refuses hands the flow back to the front's association: the worker's
    /// refusal costs the datagram that found it, and the next one frames the association.
    #[cfg(unix)]
    #[test]
    fn a_refused_direct_datagram_lane_falls_back_to_the_association() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&attempts);
        let open = Datagram::always(Arc::new(move || {
            seen.fetch_add(1, Relaxed);
            None
        }));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            echo_associate(frames.clone()),
            None,
            Some(open),
            Flows::default(),
            Legs::default(),
            &Spec::new(None, None),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 7], 51500, 53, b"who-is");
        for _ in 0..2_500 {
            if !frames.lock().unwrap().is_empty() {
                break;
            }
            peer.write_all(&query).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        wait_for_frames(&frames, 1);
        assert_eq!(
            attempts.load(Relaxed),
            1,
            "the refused lane costs one worker, not one per datagram"
        );
    }

    /// A multi-queue device's datagram gate: the queue that never saw the association still finds
    /// the leg, so one client source keeps one socket instead of one per queue.
    #[cfg(unix)]
    #[test]
    fn a_leg_opened_on_one_queue_is_served_from_another() {
        let (a, mut first) = unix_socketpair().unwrap();
        let (b, mut second) = unix_socketpair().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let spec = Spec::new(None, None).with_endpoint_independent_nat(true);
        let legs = Legs::default();
        let mut one = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            Arc::clone(&relay),
            echo_associate(frames.clone()),
            None,
            None,
            Flows::default(),
            legs.clone(),
            &spec,
        );
        let mut two = Handler::on(
            Device::from_handle(b, DEFAULT_MTU),
            relay,
            echo_associate(frames),
            None,
            None,
            Flows::default(),
            legs,
            &spec,
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 7], 51500, 53, b"one");
        first.write_all(&query).unwrap();
        let n = one.device.read_packet(&mut buf).unwrap();
        one.dispatch(&buf[..n]).unwrap();
        assert_eq!(one.legs.len(), 1, "the first queue opens the leg");
        assert_eq!(two.legs.len(), 1, "the second queue reads the same table");

        let query = datagram(SCRIPT_CLIENT, [203, 0, 113, 9], 51500, 53, b"two");
        second.write_all(&query).unwrap();
        let n = two.device.read_packet(&mut buf).unwrap();
        two.dispatch(&buf[..n]).unwrap();
        assert_eq!(two.legs.len(), 1, "the second queue reuses the leg");
    }

    /// The endpoint-independent mapping: one leg per client source, with the reply's source read off the frame the association answers with.
    #[cfg(unix)]
    #[test]
    fn an_endpoint_independent_leg_serves_every_destination() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let spec = Spec::new(None, None).with_endpoint_independent_nat(true);
        let mut handler = Handler::on(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            echo_associate(frames.clone()),
            None,
            None,
            Flows::default(),
            Legs::default(),
            &spec,
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for (destination, payload) in [
            ([198, 51, 100, 7], &b"one"[..]),
            ([203, 0, 113, 9], &b"two"[..]),
        ] {
            let query = datagram(SCRIPT_CLIENT, destination, 51500, 53, payload);
            peer.write_all(&query).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
        }
        wait_for_frames(&frames, 2);
        assert_eq!(handler.legs.len(), 1, "one leg carries both destinations");
        let got = frames.lock().unwrap().clone();
        assert!(got[0].ends_with(b"one"), "the first destination framed");
        assert!(got[1].ends_with(b"two"), "the second destination framed");
        for (destination, payload) in [
            ([198, 51, 100, 7], &b"one"[..]),
            ([203, 0, 113, 9], &b"two"[..]),
        ] {
            let n = next_datagram(&mut peer, &mut buf);
            let (ip, body) = ipv4_head(&buf[..n]).unwrap();
            assert_eq!((ip.source, ip.destination), (destination, SCRIPT_CLIENT));
            let (udp, echoed) = udp_head(body).unwrap();
            assert_eq!((udp.source_port, udp.destination_port), (53, 51500));
            assert_eq!(echoed, payload);
        }
    }

    /// Without the flag a destination gets its own leg, the shape every other front's datagram dial has.
    #[cfg(unix)]
    #[test]
    fn the_default_datagram_leg_is_per_destination() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            echo_associate(frames.clone()),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for destination in [[198, 51, 100, 7], [203, 0, 113, 9]] {
            let query = datagram(SCRIPT_CLIENT, destination, 51500, 53, b"x");
            peer.write_all(&query).unwrap();
            let n = handler.device.read_packet(&mut buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
        }
        wait_for_frames(&frames, 2);
        assert_eq!(handler.legs.len(), 2, "one leg per destination");
    }

    /// A recording association: the SOCKS5 UDP server the device's leg reaches, but
    /// it keeps each frame's (target, datagram) instead of echoing, so the outbound
    /// half of the datagram lane is witnessed without dialing a real target.
    #[cfg(unix)]
    fn recording_associate(dials: Dials) -> Associate {
        use std::io::Write;
        Arc::new(move |mut client: Connection| {
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).is_err() || client.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut request = [0u8; 10];
            if client.read_exact(&mut request).is_err() {
                return;
            }
            let Ok(relay) = UdpSocket::bind("127.0.0.1:0") else {
                return;
            };
            let Ok(addr) = relay.local_addr() else {
                return;
            };
            let mut reply = vec![5, 0, 0];
            crate::proxy::push_socks_addr(&mut reply, &addr);
            if client.write_all(&reply).is_err() {
                return;
            }
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _src)) = relay.recv_from(&mut buf) else {
                    return;
                };
                if let Some((target, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) {
                    dials
                        .lock()
                        .unwrap()
                        .push((target.to_string(), payload.to_vec()));
                }
            }
        })
    }

    /// The row's datagram identity claim, checked against the reference stack rather
    /// than the spec's own frame: the set of (target, datagram) the inbound hands to
    /// its association equals the golden `scripts/tun-oracle` recorded by running
    /// smoltcp's UDP socket over the same pinned stream. Where it bites and the
    /// frame test does not: two bodies to one port stay two dials (a datagram is
    /// never coalesced the way a TCP stream is), a body shaped like a frame header
    /// survives verbatim, and an odd length is delivered whole.
    #[cfg(unix)]
    #[test]
    fn the_datagram_dial_set_matches_the_pinned_stream() {
        let flows = parse_datagram_script(include_str!("../../../scripts/tun-oracle/script.txt"));
        let expected = parse_dials(
            include_str!("../../../scripts/tun-oracle/expected.txt"),
            "UDIAL",
        );
        let wanted: usize = flows.iter().map(|flow| flow.datagrams.len()).sum();
        let dials: Dials = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            recording_associate(dials.clone()),
        );

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for flow in &flows {
            let SocketAddr::V4(destination) = flow.destination else {
                panic!("the script names IPv4 destinations only");
            };
            let dst = destination.ip().octets();
            for body in &flow.datagrams {
                let packet = datagram(
                    SCRIPT_CLIENT,
                    dst,
                    flow.source_port,
                    destination.port(),
                    body,
                );
                peer.write_all(&packet).unwrap();
                let n = handler.device.read_packet(&mut buf).unwrap();
                handler.dispatch(&buf[..n]).unwrap();
            }
        }
        wait_for(&dials, wanted);

        let mut got: Vec<(String, Vec<u8>)> = dials.lock().unwrap().clone();
        got.sort();
        assert_eq!(
            got, expected,
            "the datagram dial set is the reference's own"
        );
    }

    /// A nonblocking peer: a frame that never arrives fails the assertions instead
    /// of parking the suite until the job timeout names nothing.
    #[cfg(unix)]
    fn peer_with_deadline() -> io::Result<(std::fs::File, std::fs::File)> {
        let (a, peer) = unix_socketpair()?;
        let rc = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((a, peer))
    }

    /// The pair a device flow rides is one `AF_UNIX` socket on a Unix host, and its
    /// half-close still reaches the far end as EOF.
    #[cfg(unix)]
    #[test]
    fn a_device_flow_pair_is_one_unix_socket_with_half_close() {
        let (device, proxy) = Handler::flow_pair().expect("pair");
        assert!(matches!(&device, Connection::Unix(_)));
        assert!(matches!(&proxy, Connection::Unix(_)));
        let mut device_write = device.try_clone().expect("dup");
        device_write.write_all(b"ping").expect("write");
        let mut proxy_read = proxy.try_clone().expect("dup");
        let mut seen = [0u8; 4];
        proxy_read.read_exact(&mut seen).expect("read");
        assert_eq!(&seen, b"ping");
        device_write.shutdown(Shutdown::Write).expect("half-close");
        let mut rest = [0u8; 1];
        assert_eq!(proxy_read.read(&mut rest).expect("eof"), 0);
    }

    /// The header fields a test reads off a packet the handler wrote, owned because a parsed head borrows the read buffer.
    #[cfg(unix)]
    #[derive(Clone, Copy)]
    struct Written {
        source_port: u16,
        destination_port: u16,
        seq: u32,
        ack_num: u32,
        flags: u8,
    }

    #[cfg(unix)]
    impl Written {
        fn of(tcp: &TcpHead<'_>) -> Self {
            Self {
                source_port: tcp.source_port,
                destination_port: tcp.destination_port,
                seq: tcp.seq,
                ack_num: tcp.ack_num,
                flags: tcp.flags,
            }
        }
    }

    /// Read frames off the peer until the SYN-ACK: a flow that ran earlier leaves
    /// its delayed ACKs queued ahead of it on the shared descriptor.
    #[cfg(unix)]
    fn next_syn_ack(peer: &mut std::fs::File) -> Written {
        let mut reply = [0u8; 64];
        for _ in 0..1_000 {
            match peer.read(&mut reply) {
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((tcp, _)) = tcp_head(body) {
                            if tcp.flags == FLAG_SYN | FLAG_ACK {
                                return Written::of(&tcp);
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no SYN-ACK arrived on the device");
    }

    /// The next TCP packet the handler wrote to the device, waited for with a bound
    /// so a silent lane fails the test instead of parking it.
    #[cfg(unix)]
    fn next_tcp_packet(peer: &mut std::fs::File, buf: &mut [u8]) -> (Written, Vec<u8>) {
        for _ in 0..2_500 {
            match peer.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&buf[..n]) {
                        if let Some((tcp, payload)) = tcp_head(body) {
                            return (Written::of(&tcp), payload.to_vec());
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no packet arrived on the device");
    }

    /// The reverse role, checked: bytes the outbound writes back leave the handler as
    /// IP packets carrying exactly those bytes on the same descriptor.
    #[cfg(unix)]
    #[test]
    fn the_response_bytes_come_back_as_ip_packets() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|mut conn: Connection, _lane, _dest| {
            use std::io::Write;
            let _ = conn.write_all(b"pong\n");
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let flow = FlowSpec {
            destination: "203.0.113.53:53".parse().unwrap(),
            source_port: 51001,
            syn_seq: 7000,
            chunks: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        };
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        run_flow(&mut handler, &mut peer, &flow, &mut buf);

        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let mut payload = Vec::new();
        for _ in 0..250 {
            match peer.read(&mut reply) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((_, pl)) = tcp_head(body) {
                            payload.extend_from_slice(pl);
                        }
                    }
                    if payload.windows(5).any(|w| w == b"pong\n") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        assert!(
            payload.windows(5).any(|w| w == b"pong\n"),
            "the response bytes ride back as a payload"
        );
    }

    /// The tun2socks shape: a device's TCP flow leaves through the SOCKS5 client
    /// lane, and the echo comes back as IP packets on the same descriptor.
    ///
    /// The SOCKS5 server here answers the greeting, the `CONNECT` request and the
    /// reply the way a SOCKS5 client writes them, and relays to the destination the
    /// request named — so the lane cannot tell a device from a proxy client.
    #[cfg(unix)]
    #[test]
    fn a_device_flow_leaves_through_the_socks_client_lane() {
        let echo = echo_server();
        let (asked, port) = socks_server();
        let out = crate::proxy::Outbound::Socks(crate::proxy::SocksOut::new(
            "127.0.0.1",
            port,
            "",
            "",
            crate::socks::Version::V5,
        ));
        let relay: Relay = Arc::new(move |conn, lane, dest| {
            crate::proxy::serve_device_flow(conn, lane, &out, &dest)
        });
        let (a, mut peer) = peer_with_deadline().unwrap();
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let flow = FlowSpec {
            destination: format!("127.0.0.1:{echo}").parse().unwrap(),
            source_port: 51002,
            syn_seq: 8000,
            chunks: vec![b"ping".to_vec()],
        };
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        run_flow(&mut handler, &mut peer, &flow, &mut buf);

        // The SOCKS5 server received the CONNECT for the destination the device named; the dial runs on the flow's own thread, so the record is waited for.
        let record = Arc::clone(&asked);
        let mut seen = Vec::new();
        for _ in 0..2_500 {
            seen = record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if !seen.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            seen.as_slice(),
            &[format!("127.0.0.1:{echo}").parse().expect("an address")],
            "the device's destination is the one the request names"
        );

        // And the echo rides back as IP packets on the device's own descriptor.
        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let mut payload = Vec::new();
        for _ in 0..500 {
            match peer.read(&mut reply) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((_, pl)) = tcp_head(body) {
                            payload.extend_from_slice(pl);
                        }
                    }
                    if payload.windows(4).any(|w| w == b"ping") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        assert!(
            payload.windows(4).any(|w| w == b"ping"),
            "the echo rides back as a payload"
        );
    }

    /// A TCP echo server on loopback: the destination the device's flow names.
    #[cfg(unix)]
    fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// A SOCKS5 server on loopback: the greeting, the `CONNECT` request and the reply,
    /// and then a relay to the destination the request named. The destination is kept
    /// so a test can see what the client asked for.
    #[cfg(unix)]
    fn socks_server() -> (Arc<std::sync::Mutex<Vec<SocketAddr>>>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let asked: Arc<std::sync::Mutex<Vec<SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_err() || stream.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut head = [0u8; 4];
            if stream.read_exact(&mut head).is_err() {
                return;
            }
            let mut body = [0u8; 6];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            let target = SocketAddr::from((
                [body[0], body[1], body[2], body[3]],
                u16::from_be_bytes([body[4], body[5]]),
            ));
            record.lock().expect("the record").push(target);
            if stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
                return;
            }
            let Ok(mut upstream) = TcpStream::connect(target) else {
                return;
            };
            let Ok(mut down) = stream.try_clone() else {
                return;
            };
            let Ok(mut up) = upstream.try_clone() else {
                return;
            };
            let mut back = stream;
            let forward = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = up.read(&mut buf) {
                    if n == 0 || back.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let mut buf = [0u8; 4096];
            while let Ok(n) = down.read(&mut buf) {
                if n == 0 || upstream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = forward.join();
        });
        (asked, port)
    }

    /// One flow opened and then silent: SYN, the ACK read off this stack's own SYN-ACK, and nothing after.
    #[cfg(unix)]
    fn open_flow(
        handler: &mut Handler,
        peer: &mut std::fs::File,
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        buf: &mut [u8],
    ) -> FlowKey {
        let SocketAddr::V4(destination) = destination else {
            panic!("the flow names an IPv4 destination");
        };
        let endpoint = (destination.ip().octets(), destination.port());
        let client = (SCRIPT_CLIENT, source_port);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq,
            0,
            FLAG_SYN,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let syn_ack = next_syn_ack(peer);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq.wrapping_add(1),
            syn_ack.seq.wrapping_add(1),
            FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::from(SCRIPT_CLIENT)),
            source_port,
            destination: IpAddr::V4(*destination.ip()),
            destination_port: endpoint.1,
        }
    }

    /// Silence past the idle budget is death, not a leak: a flow that stops speaking on both sides hands its relay leg back at the budget, and its entry goes at the next dial.
    #[cfg(unix)]
    #[test]
    fn a_quiet_tun_flow_hands_its_threads_back() {
        let idle = std::time::Duration::from_millis(250);
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(idle),
            ..Default::default()
        });
        let (a, mut peer) = peer_with_deadline().unwrap();
        let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
        let relay: Relay = Arc::new(move |mut conn: Connection, _lane, _dest| {
            let mut sink = Vec::new();
            let _ = conn.read_to_end(&mut sink);
            let _ = gone_tx.send(());
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let key = open_flow(&mut handler, &mut peer, destination, 51500, 9000, &mut buf);
        assert!(
            handler.flows.table().contains_key(&key),
            "the dial opens before its budget runs"
        );
        let back = gone_rx.recv_timeout(idle + std::time::Duration::from_secs(5));
        budgets::clear();
        assert!(
            back.is_ok(),
            "a flow silent past its idle budget still holds its relay leg"
        );

        // The entry goes at the next dial, so the packet path pays nothing for the reap.
        let second = open_flow(&mut handler, &mut peer, destination, 51501, 9500, &mut buf);
        let has_second = handler.flows.table().contains_key(&second);
        let has_key = handler.flows.table().contains_key(&key);
        assert!(
            has_second && !has_key,
            "the quiet flow's entry is gone at the next dial"
        );
        assert_eq!(handler.flows.table().len(), 1, "only the live flow is left");

        // The client's goodbye outranks the budget: a reset flow hands its leg back at once.
        let IpAddr::V4(second_ip) = second.destination else {
            panic!("the test flow names an IPv4 destination");
        };
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, second.source_port),
            (second_ip.octets(), second.destination_port),
            9501,
            0,
            FLAG_RST | FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let second_back = gone_rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            second_back.is_ok(),
            "a reset flow is still holding its relay leg"
        );
        assert!(
            handler.flows.table().is_empty(),
            "the reset flow's entry is gone"
        );
    }

    /// A proxy leg that closes after its bytes finishes the device's flow: the
    /// response payload arrives first, then `FIN | ACK`, and a device `FIN` is
    /// still accepted instead of being answered with a reset.
    #[cfg(unix)]
    #[test]
    fn a_closed_proxy_leg_sends_fin_after_its_bytes() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|mut conn: Connection, _lane, _dest| {
            use std::io::Write;
            let _ = conn.write_all(b"reply");
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.61:80".parse().unwrap();
        let destination_ip = match destination {
            SocketAddr::V4(address) => address.ip().octets(),
            SocketAddr::V6(_) => panic!("the flow names IPv4"),
        };
        let source_port = 52000;
        let syn_seq = 3000;
        open_flow(
            &mut handler,
            &mut peer,
            destination,
            source_port,
            syn_seq,
            &mut buf,
        );

        let mut payload = Vec::new();
        let mut fin = None;
        for _ in 0..4 {
            let (tcp, body) = next_tcp_packet(&mut peer, &mut buf);
            if tcp.flags & FLAG_FIN != 0 {
                fin = Some(tcp);
                break;
            }
            payload.extend_from_slice(&body);
        }
        assert_eq!(payload, b"reply", "the proxy bytes reach the device first");
        let fin = fin.expect("a proxy close must finish the device flow");
        assert_eq!(fin.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(fin.source_port, destination.port());
        assert_eq!(fin.destination_port, source_port);

        // The device's own goodbye still lands after the proxy's.
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, source_port),
            (destination_ip, destination.port()),
            syn_seq.wrapping_add(1),
            fin.seq.wrapping_add(1),
            FLAG_FIN | FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
    }

    /// A proxy leg that refuses before carrying a byte cannot leave the device
    /// waiting on an established socket: the flow is reset instead.
    #[cfg(unix)]
    #[test]
    fn a_refused_proxy_leg_resets_the_device_flow() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|_conn: Connection, _lane, _dest| {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.62:443".parse().unwrap();
        let source_port = 52001;
        open_flow(
            &mut handler,
            &mut peer,
            destination,
            source_port,
            4000,
            &mut buf,
        );

        let (tcp, _) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(
            tcp.flags,
            FLAG_RST | FLAG_ACK,
            "a refused dial resets the device's established flow"
        );
        assert_eq!(tcp.source_port, destination.port());
        assert_eq!(tcp.destination_port, source_port);
    }

    #[test]
    fn a_forged_packet_is_refused_not_repaired() {
        // A forged IP length and a short TCP body must leave the parse silent, not reading past.
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"x",
        );
        let forged_len = (pkt.len() + 8) as u16;
        pkt[2..4].copy_from_slice(&forged_len.to_be_bytes());
        assert!(ipv4_head(&pkt).is_none());
        let short = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        assert!(tcp_head(&short[IPV4_HEADER..IPV4_HEADER + 19]).is_none());
    }

    #[test]
    fn a_syn_with_options_leaves_the_payload_where_the_header_ends() {
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"ab",
        );
        // Insert a 4-byte MSS option and bump the data offset to six words.
        let head = pkt[..IPV4_HEADER + 20].to_vec();
        let tail = pkt[IPV4_HEADER + 20..].to_vec();
        pkt = head;
        pkt[IPV4_HEADER + 12] = 0x60;
        pkt.extend_from_slice(&[2, 4, 0, 140]);
        pkt.extend_from_slice(&tail);
        let l = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&l.to_be_bytes());
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(payload, b"ab", "the payload starts after the options");
    }

    #[cfg(unix)]
    #[test]
    fn the_syn_ack_numbers_wrap_at_the_sequence_space_boundary() {
        let (a, mut peer) = unix_socketpair().unwrap();
        let relay: Relay = Arc::new(|_conn, _lane, _dest| Ok(()));
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 80),
            u32::MAX - 1,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = [0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        let (_ip, body) = ipv4_head(&reply[..rn]).unwrap();
        let (syn_ack, _) = tcp_head(body).unwrap();
        assert_eq!(
            syn_ack.ack_num,
            u32::MAX,
            "the receive cursor wraps instead of saturating"
        );
        let key = FlowKey {
            source: IpAddr::V4(Ipv4Addr::from([10, 0, 0, 2])),
            source_port: 44444,
            destination: IpAddr::V4(Ipv4Addr::from([10, 0, 0, 1])),
            destination_port: 80,
        };
        let expected = handler
            .flows
            .table()
            .get(&key)
            .expect("the flow")
            .server_isn;
        assert_eq!(syn_ack.seq, expected, "the server sequence is its own");
    }
}

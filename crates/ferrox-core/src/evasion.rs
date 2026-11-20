//! Active DPI evasion at the two seams that do not change a payload's bytes: a UDP flow's first
//! datagrams, and a fake `ClientHello` sent beside a TCP handshake.
//!
//! [`Noise`] describes one decoy plan: a datagram shape, how many of it to send, and the wait
//! between copies. [`SniSpoof`] describes a fake `ClientHello`: the name it carries, the sequence it
//! claims, and which of the reference's methods to use. Only the decoy is built here; the methods
//! that edit the real hello's record are app-side write shaping, and the urgent byte and TCP
//! Fast Open belong to the transport, not this module.
//!
//! The raw injector is Linux-only and needs `CAP_NET_RAW`. It sends a complete IPv4/TCP segment
//! outside the connection's sequence window, so the real peer discards it while a passive parser
//! still reads the allow-listed name. A caller that lacks the capability gets `false`, which is the
//! reference's own answer and the signal to fall back to `ClientHello` fragmentation.

#[cfg(any(target_os = "linux", test))]
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// One decoy datagram shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseKind {
    /// Uniform bytes over an inclusive range.
    Rand { bytes: (u8, u8) },
    /// The same bytes every time.
    Fixed(Vec<u8>),
    /// A QUIC long-header Initial shape; never handed to a QUIC implementation.
    Quic,
}

/// One `noises` entry: what to send, how long it may be, how many copies, and the gap between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noise {
    pub kind: NoiseKind,
    pub length_min: u64,
    pub length_max: u64,
    pub delay_min: u64,
    pub delay_max: u64,
    pub count: u32,
}

impl Noise {
    /// One datagram, redrawn on every call.
    pub fn generate(&self) -> Option<Vec<u8>> {
        match &self.kind {
            NoiseKind::Fixed(bytes) => Some(bytes.clone()),
            NoiseKind::Rand { bytes } => {
                let length =
                    usize::try_from(rand_between(self.length_min, self.length_max)).ok()?;
                let mut packet = vec![0u8; length];
                if bytes.0 == 0 && bytes.1 == u8::MAX {
                    getrandom::fill(&mut packet).ok()?;
                } else {
                    draw_bytes(&mut packet, bytes.0, bytes.1)?;
                }
                Some(packet)
            }
            NoiseKind::Quic => {
                let length = usize::try_from(rand_between(self.length_min, self.length_max))
                    .ok()?
                    .max(25);
                let mut packet = vec![0u8; length];
                getrandom::fill(&mut packet).ok()?;
                packet[0] = 0xc0 | (packet[0] & 0x0f);
                packet[1..5].copy_from_slice(&1u32.to_be_bytes());
                packet[5] = 8;
                packet[14] = 8;
                packet[23] = 0;
                Some(packet)
            }
        }
    }

    /// The wait after one copy.
    pub fn delay(&self) -> Duration {
        Duration::from_millis(rand_between(self.delay_min, self.delay_max))
    }
}

/// The half-open draw the reference calls `RandBetween`: a span of 0 or 1 answers its low end.
fn rand_between(from: u64, to: u64) -> u64 {
    let (from, to) = if from <= to { (from, to) } else { (to, from) };
    let span = to.saturating_sub(from);
    if span <= 1 {
        return from;
    }
    let mut raw = [0u8; 8];
    loop {
        if getrandom::fill(&mut raw).is_err() {
            return from;
        }
        let value = u64::from_le_bytes(raw);
        let limit = u64::MAX - (u64::MAX % span);
        if value < limit {
            return from.saturating_add(value % span);
        }
    }
}

/// Fill `out` with bytes in `low..=high`, from one entropy supply rather than one syscall per
/// byte; each raw byte past the rejection limit is dropped, so the draw stays uniform.
fn draw_bytes(out: &mut [u8], low: u8, high: u8) -> Option<()> {
    let (low, high) = if low <= high {
        (low, high)
    } else {
        (high, low)
    };
    let span = u16::from(high) - u16::from(low) + 1;
    let limit = 256 - (256 % span);
    let mut supply = [0u8; 64];
    let mut at = supply.len();
    for byte in out {
        *byte = loop {
            if at == supply.len() {
                getrandom::fill(&mut supply).ok()?;
                at = 0;
            }
            let raw = u16::from(supply[at]);
            at += 1;
            if raw < limit {
                break u8::try_from(u16::from(low) + raw % span).ok()?;
            }
        };
    }
    Some(())
}

/// The ways the reference keeps a server name from a filter that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SniMethod {
    /// The decoy where the kernel allows it, the record version otherwise.
    #[default]
    Auto,
    /// A fake `ClientHello` outside the TCP window.
    Decoy,
    /// One extra urgent byte in the middle of the name.
    Urgent,
    /// The hello in the SYN.
    FastOpen,
    /// Another version in the first record header.
    Record,
    /// An empty handshake record ahead of the hello.
    EmptyRecord,
}

/// What keeps a decoy from the server it is addressed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecoyFooling {
    /// The signature option the reference prefers, the same segment it sends where the kernel
    /// has TCP-MD5; the out-of-window sequence is no extra guard here.
    #[default]
    Auto,
    /// The TCP signature option, signed with no key so the peer's stack drops it.
    Md5,
    /// A hop limit that expires between the filter and the server.
    Ttl,
}

/// One `sniSpoof` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniSpoof {
    pub fake_sni: String,
    pub sequence: u32,
    pub method: SniMethod,
    pub fooling: DecoyFooling,
    pub ttl: u8,
    /// Rewrite the real hello's name in mixed case, `LxBox` 016's second cut at the same match.
    pub mixed_case: bool,
}

/// The write-time methods that need no privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniShape {
    /// `03 04` in the first record header where TLS put `03 01` or `03 03`.
    Record,
    /// One empty handshake record ahead of the hello.
    EmptyRecord,
    /// One extra byte marked urgent in the middle of the name, sent with `MSG_OOB`.
    Urgent,
}

/// The empty handshake record written ahead of a hello.
pub const EMPTY_RECORD: [u8; 5] = [0x16, 0x03, 0x03, 0x00, 0x00];

/// The record-header version the `record` method writes.
pub const RECORD_VERSION: [u8; 2] = [0x03, 0x04];

/// The record-header version the reference's decoy template carries.
const DECOY_RECORD_VERSION: [u8; 2] = [0x03, 0x01];

/// The size every decoy hello reaches by padding, as the reference's fixed packet is.
pub const FAKE_HELLO_LEN: usize = 517;

/// The largest fake name the fixed packet leaves room for.
pub const FAKE_SNI_MAX: usize = 219;

type Fill = dyn FnMut(&mut [u8]) -> Result<(), String>;

/// A fake `ClientHello` of [`FAKE_HELLO_LEN`] bytes carrying `fake_sni`.
///
/// `?`, `#` and `*` draw a letter, a digit or either, once per call, so one process never sends
/// the same decoy name twice. The random, session id and key share are drawn from `fill`, which
/// keeps the builder deterministic under a test.
pub fn build_fake_client_hello(fake_sni: &str, fill: &mut Fill) -> Result<Vec<u8>, String> {
    if fake_sni.is_empty()
        || fake_sni.len() > FAKE_SNI_MAX
        || !fake_sni.bytes().all(|byte| byte > 0x20)
    {
        return Err(format!("fake SNI must be 1..={FAKE_SNI_MAX} visible bytes"));
    }
    let mut name = fake_sni.as_bytes().to_vec();
    draw_wildcards(&mut name, fill)?;
    let name = name.as_slice();

    let mut random = [0u8; 32];
    let mut session = [0u8; 32];
    let mut key_share = [0u8; 32];
    fill(&mut random)?;
    fill(&mut session)?;
    fill(&mut key_share)?;

    let padding_len = FAKE_HELLO_LEN
        .checked_sub(182 + name.len())
        .ok_or_else(|| "fake SNI leaves no room for the padding".to_string())?;
    let mut hello = Vec::with_capacity(FAKE_HELLO_LEN);

    hello.push(0x16);
    hello.extend_from_slice(&DECOY_RECORD_VERSION);
    hello.extend_from_slice(&[0, 0]);
    hello.push(0x01);
    hello.extend_from_slice(&[0, 0, 0]);
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&random);
    hello.push(0x20);
    hello.extend_from_slice(&session);

    let suites: [u16; 5] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
    push_u16(
        &mut hello,
        u16::try_from(suites.len() * 2).expect("five suites fit"),
    );
    for suite in suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }
    hello.extend_from_slice(&[0x01, 0x00]);

    let ext_at = hello.len();
    hello.extend_from_slice(&[0, 0]);

    push_u16(&mut hello, 0x0000);
    push_u16(
        &mut hello,
        u16::try_from(5 + name.len()).expect("a bounded name fits"),
    );
    push_u16(
        &mut hello,
        u16::try_from(3 + name.len()).expect("a bounded name fits"),
    );
    hello.push(0x00);
    push_u16(
        &mut hello,
        u16::try_from(name.len()).expect("a bounded name fits"),
    );
    hello.extend_from_slice(name);

    hello.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    hello.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    hello.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x05, 0x03,
    ]);
    hello.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    hello.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    hello.extend_from_slice(&key_share);

    push_u16(&mut hello, 0x0015);
    push_u16(
        &mut hello,
        u16::try_from(padding_len).expect("padding fits in a u16"),
    );
    hello.resize(ext_at + 2 + 90 + name.len() + padding_len, 0);

    let ext_len = u16::try_from(hello.len() - ext_at - 2).expect("extensions fit");
    hello[ext_at..ext_at + 2].copy_from_slice(&ext_len.to_be_bytes());
    let body_len = hello.len() - 9;
    let body_len = u32::try_from(body_len).expect("the hello fits");
    hello[6..9].copy_from_slice(&body_len.to_be_bytes()[1..]);
    let record_len = u16::try_from(hello.len() - 5).expect("the hello fits");
    hello[3..5].copy_from_slice(&record_len.to_be_bytes());
    debug_assert_eq!(hello.len(), FAKE_HELLO_LEN);
    Ok(hello)
}

fn draw_wildcards(name: &mut [u8], fill: &mut Fill) -> Result<(), String> {
    for byte in name {
        let letter = match *byte {
            b'?' => Some(true),
            b'#' => Some(false),
            b'*' => {
                let mut pick = [0u8; 1];
                fill(&mut pick)?;
                Some(pick[0] & 1 == 0)
            }
            _ => None,
        };
        if let Some(letter) = letter {
            let mut pick = [0u8; 1];
            fill(&mut pick)?;
            *byte = if letter {
                b'a' + pick[0] % 26
            } else {
                b'0' + pick[0] % 10
            };
        }
    }
    Ok(())
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// One complete IPv4/TCP segment carrying `payload` at `sequence`.
///
/// The checksums are computed here, so a raw socket with `IP_HDRINCL` sends exactly these bytes.
/// `ttl` is stamped in the IPv4 header because a supplied header is what the kernel sends, and
/// `md5` adds the TCP signature option whose absent key at the peer drops the segment.
#[cfg(any(target_os = "linux", test))]
pub fn build_ipv4_packet(
    local: SocketAddr,
    peer: SocketAddr,
    sequence: u32,
    ttl: u8,
    md5: bool,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (local.ip(), peer.ip()) else {
        return Err("SNI desync needs an IPv4 pair".to_owned());
    };
    let tcp_len = if md5 { 40 } else { 20 };
    let total = 20usize
        .checked_add(tcp_len)
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or_else(|| "SNI desync packet length overflow".to_string())?;
    let total_u16 = u16::try_from(total).map_err(|_| "SNI desync packet is too large")?;
    let mut packet = vec![0u8; total];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).map_err(|error| error.to_string())?;
    packet[4..6].copy_from_slice(&id);
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = ttl;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());

    packet[20..22].copy_from_slice(&local.port().to_be_bytes());
    packet[22..24].copy_from_slice(&peer.port().to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[32] = (tcp_len as u8) << 2;
    packet[33] = 0x18;
    packet[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
    if md5 {
        packet[40..44].copy_from_slice(&[1, 1, 19, 18]);
    }
    packet[20 + tcp_len..].copy_from_slice(payload);

    let segment = &mut packet[20..];
    if md5 {
        let digest = tcp_md5(source, destination, &segment[..tcp_len], payload);
        segment[24..40].copy_from_slice(&digest);
    }
    let checksum = tcp_checksum(source, destination, &segment[..tcp_len], payload);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

/// The RFC 2385 digest over the segment, signed with no key: the peer has none either, and its
/// stack drops a signed segment it cannot verify.
#[cfg(any(target_os = "linux", test))]
fn tcp_md5(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    header: &[u8],
    payload: &[u8],
) -> [u8; 16] {
    let mut signed = Vec::with_capacity(12 + header.len() + payload.len());
    signed.extend_from_slice(&source.octets());
    signed.extend_from_slice(&destination.octets());
    signed.extend_from_slice(&[0, 6]);
    signed.extend_from_slice(
        &u16::try_from(header.len() + payload.len())
            .expect("a TCP segment fits")
            .to_be_bytes(),
    );
    signed.extend_from_slice(header);
    signed.extend_from_slice(payload);
    md5::compute(&signed).0
}

#[cfg(any(target_os = "linux", test))]
fn tcp_checksum(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    header: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum = checksum_add(0, &source.octets());
    sum = checksum_add(sum, &destination.octets());
    sum = checksum_add(sum, &[0, 6]);
    let length = u16::try_from(header.len() + payload.len()).expect("a TCP segment fits");
    sum = checksum_add(sum, &length.to_be_bytes());
    sum = checksum_add(sum, header);
    checksum_finish(checksum_add(sum, payload))
}

#[cfg(any(target_os = "linux", test))]
fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, bytes))
}

#[cfg(any(target_os = "linux", test))]
fn checksum_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let (words, tail) = bytes.as_chunks::<2>();
    for pair in words {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let Some(byte) = tail.first() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

#[cfg(any(target_os = "linux", test))]
fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("the folded sum is sixteen bits")
}

/// Send one fake `ClientHello` outside `connection`'s sequence window.
///
/// `Ok(false)` is the capability or platform boundary: the caller falls back the way the
/// reference does. `Ok(true)` means the segment left whole.
#[cfg(target_os = "linux")]
pub fn inject_fake_client_hello(
    connection: std::os::fd::RawFd,
    local: SocketAddr,
    peer: SocketAddr,
    spoof: &SniSpoof,
) -> Result<bool, String> {
    let payload = build_fake_client_hello(&spoof.fake_sni, &mut |buf| {
        getrandom::fill(buf).map_err(|error| error.to_string())
    })?;
    if !matches!((local.ip(), peer.ip()), (IpAddr::V4(_), IpAddr::V4(_))) {
        return Err(
            "the decoy needs an IPv4 pair; this dial rewrites the first record instead".into(),
        );
    }
    let (ttl, md5) = match spoof.fooling {
        DecoyFooling::Ttl => (spoof.ttl, false),
        DecoyFooling::Auto | DecoyFooling::Md5 => (64, true),
    };
    let packet = build_ipv4_packet(local, peer, spoof.sequence, ttl, md5, &payload)?;

    // SAFETY: the socket is owned here and closed below; the arguments are plain integers.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => Ok(false),
            _ => Err(format!("SNI desync raw socket: {error}")),
        };
    }
    // A decoy that cannot take the same mark and interface as the real hello is worse than none.
    if !copy_route_binding(connection, raw) {
        // SAFETY: `raw` was opened above and is closed exactly once here.
        unsafe { libc::close(raw) };
        return Ok(false);
    }
    let destination = sockaddr_in(peer);
    // SAFETY: `packet` is live for the call, the destination is a `sockaddr_in`, and `raw` is open.
    let sent = unsafe {
        libc::sendto(
            raw,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::from_ref(&destination).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    // SAFETY: `raw` was opened above and is closed exactly once here.
    unsafe { libc::close(raw) };
    match usize::try_from(sent) {
        Ok(sent) if sent == packet.len() => Ok(true),
        Ok(_) => Err("SNI desync raw socket sent a partial packet".to_owned()),
        Err(_) => Err(format!(
            "SNI desync packet injection: {}",
            std::io::Error::last_os_error()
        )),
    }
}

#[cfg(target_os = "linux")]
fn copy_route_binding(from: std::os::fd::RawFd, to: std::os::fd::RawFd) -> bool {
    // SAFETY: both descriptors are caller-owned; each option's buffer and length live for the call.
    unsafe {
        let mut mark: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&mark) as libc::socklen_t;
        let marked = libc::getsockopt(
            from,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_mut(&mut mark).cast(),
            std::ptr::from_mut(&mut len),
        ) == 0
            && (mark == 0
                || libc::setsockopt(
                    to,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    std::ptr::from_ref(&mark).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                ) == 0);
        let mut device = [0u8; libc::IFNAMSIZ];
        let mut len = device.len() as libc::socklen_t;
        let bound = libc::getsockopt(
            from,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_mut_ptr().cast(),
            std::ptr::from_mut(&mut len),
        ) == 0
            && (len == 0
                || device[0] == 0
                || libc::setsockopt(
                    to,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    device.as_ptr().cast(),
                    len,
                ) == 0);
        marked && bound
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_in(address: SocketAddr) -> libc::sockaddr_in {
    let SocketAddr::V4(address) = address else {
        unreachable!("the caller checked IPv4")
    };
    let mut out: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    out.sin_family = u16::try_from(libc::AF_INET).expect("AF_INET is a u16");
    out.sin_port = address.port().to_be();
    out.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    out
}

/// Where a `ClientHello`'s server name sits in the record, when the write is one whole handshake
/// record that carries a DNS name. The range is into `record`, so a caller can rewrite the name or
/// place a cut inside it without copying the hello first.
pub fn server_name_range(record: &[u8]) -> Option<std::ops::Range<usize>> {
    let u16_at = |at: usize| {
        Some(usize::from(u16::from_be_bytes([
            *record.get(at)?,
            *record.get(at + 1)?,
        ])))
    };
    if record.len() < 43 || record[0] != 0x16 || record[5] != 0x01 {
        return None;
    }
    let record_len = 5 + u16_at(3)?;
    if record_len > record.len() {
        return None;
    }
    let handshake =
        (usize::from(record[6]) << 16) | (usize::from(record[7]) << 8) | usize::from(record[8]);
    if 9 + handshake != record_len {
        return None;
    }
    let version = u16_at(9)?;
    if version & 0xfffc != 0x0300 && version != 0x0304 {
        return None;
    }
    let mut at = 43;
    at += 1 + usize::from(*record.get(at)?);
    at += 2 + u16_at(at)?;
    at += 1 + usize::from(*record.get(at)?);
    let end = at + 2 + u16_at(at)?;
    at += 2;
    if end > record_len {
        return None;
    }
    while at + 4 <= end {
        let (kind, length) = (u16_at(at)?, u16_at(at + 2)?);
        at += 4;
        if length > end - at {
            return None;
        }
        if kind == 0 {
            let name_len = u16_at(at + 3)?;
            let start = at + 5;
            return (*record.get(at + 2)? == 0 && name_len > 0 && start + name_len <= at + length)
                .then_some(start..start + name_len);
        }
        at += length;
    }
    None
}

/// One cut inside every label of `name` that is long enough to hold two.
///
/// A censor that reads the name out of a single record reassembles nothing here: each label is
/// split at a fresh random byte, so no record carries a whole label, and the TLD is split too.
/// The result is sorted and in `1..name.len()`, so every piece is non-empty.
pub fn label_cuts(name: &[u8]) -> Vec<usize> {
    let mut cuts = Vec::new();
    let mut start = 0;
    while start < name.len() {
        let end = name[start..]
            .iter()
            .position(|byte| *byte == b'.')
            .map_or(name.len(), |at| start + at);
        if end - start >= 2 {
            let offset = usize::try_from(rand_between(1, (end - start) as u64)).unwrap_or(1);
            cuts.push(start + offset);
        }
        start = end + 1;
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

/// The server name a dial hands its TLS backend in mixed case, the way `LxBox` 016 does: the first
/// letter of each label is upper case and every other letter draws its case. The backend hashes the
/// hello it builds, so the name must be rewritten before the transcript, not below it; DNS names are
/// case-insensitive, so the peer still routes the same host.
pub fn mixed_case_name(name: &str) -> String {
    let mut bytes = name.as_bytes().to_vec();
    let mut draw = [0u8; 32];
    let mut left = 0usize;
    let mut first = true;
    for byte in &mut bytes {
        if *byte == b'.' {
            first = true;
            continue;
        }
        if byte.is_ascii_alphabetic() {
            if left == 0 {
                // One draw answers a run of letters, so a short name spends one syscall, not one a byte.
                left = draw.len();
                if getrandom::fill(&mut draw).is_err() {
                    draw.fill(0);
                }
            }
            let upper = first || draw[draw.len() - left] & 1 == 0;
            left -= 1;
            *byte = if upper {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            };
            first = false;
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        |buf| {
            buf.fill(0);
            Ok(())
        }
    }

    #[test]
    fn a_fake_hello_is_the_fixed_packet_and_carries_its_name() {
        let hello = build_fake_client_hello("www.speedtest.net", &mut zeros()).expect("builds");
        assert_eq!(hello.len(), FAKE_HELLO_LEN);
        let name = b"www.speedtest.net";
        assert!(hello.windows(name.len()).any(|window| window == name));
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &DECOY_RECORD_VERSION);
        assert_eq!(hello[5], 0x01);
        let record = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
        assert_eq!(record, FAKE_HELLO_LEN - 5);
        let handshake =
            usize::from(hello[6]) << 16 | usize::from(hello[7]) << 8 | usize::from(hello[8]);
        assert_eq!(handshake, FAKE_HELLO_LEN - 9);

        let ext_at = 90;
        let end = ext_at + 2 + usize::from(u16::from_be_bytes([hello[ext_at], hello[ext_at + 1]]));
        assert_eq!(end, FAKE_HELLO_LEN);
        let mut at = ext_at + 2;
        while at < end {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            assert!(at + 4 + len <= end);
            if kind == 0x0015 {
                assert_eq!(at + 4 + len, end);
            }
            at += 4 + len;
        }
        assert_eq!(at, end);
    }

    #[test]
    fn the_wildcards_draw_a_name_of_the_same_length() {
        let hello = build_fake_client_hello("a?b#c*", &mut zeros()).expect("builds");
        let at = hello
            .windows(5)
            .position(|window| window[0] == b'a' && window[2] == b'b' && window[4] == b'c')
            .expect("the name is there");
        assert_eq!(hello[at + 1], b'a');
        assert_eq!(hello[at + 3], b'0');
        assert_eq!(hello[at + 5], b'a');
    }

    #[test]
    fn a_fake_name_outside_the_bound_is_refused() {
        assert!(build_fake_client_hello("", &mut zeros()).is_err());
        assert!(build_fake_client_hello(&"a".repeat(FAKE_SNI_MAX + 1), &mut zeros()).is_err());
        assert!(build_fake_client_hello("a\u{1}b", &mut zeros()).is_err());
    }

    #[test]
    fn the_internet_checksum_matches_the_rfc_example() {
        let sum = checksum_add(0, &[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xddf2);
        assert_eq!(checksum_finish(sum), 0x220d);
    }

    #[test]
    fn a_decoy_packet_has_both_checksums_right() {
        let local: SocketAddr = "192.0.2.10:40000".parse().expect("local");
        let peer: SocketAddr = "198.51.100.20:443".parse().expect("peer");
        let packet = build_ipv4_packet(local, peer, 0, 8, false, &[1, 2, 3, 4]).expect("packet");
        assert_eq!(packet.len(), 44);
        assert_eq!(packet[8], 8, "the header carries the hop limit");
        assert_eq!(internet_checksum(&packet[..20]), 0);
        let source: std::net::Ipv4Addr = "192.0.2.10".parse().expect("source");
        let destination: std::net::Ipv4Addr = "198.51.100.20".parse().expect("destination");
        let mut sum = checksum_add(0, &source.octets());
        sum = checksum_add(sum, &destination.octets());
        sum = checksum_add(sum, &[0, 6]);
        sum = checksum_add(sum, &24u16.to_be_bytes());
        sum = checksum_add(sum, &packet[20..40]);
        sum = checksum_add(sum, &[1, 2, 3, 4]);
        assert_eq!(checksum_finish(sum), 0);
    }

    #[test]
    fn an_md5_decoy_signs_its_segment() {
        let local: SocketAddr = "192.0.2.10:40000".parse().expect("local");
        let peer: SocketAddr = "198.51.100.20:443".parse().expect("peer");
        let packet = build_ipv4_packet(local, peer, 7, 64, true, &[1, 2, 3, 4]).expect("packet");
        assert_eq!(packet.len(), 64);
        assert_eq!(packet[32] >> 4, 10, "ten 32-bit words carry the option");
        assert_eq!(&packet[40..44], &[1, 1, 19, 18]);
        assert_eq!(internet_checksum(&packet[..20]), 0);

        let source: std::net::Ipv4Addr = "192.0.2.10".parse().expect("source");
        let destination: std::net::Ipv4Addr = "198.51.100.20".parse().expect("destination");
        let mut unsigned = packet[20..60].to_vec();
        unsigned[16..18].fill(0);
        unsigned[24..40].fill(0);
        assert_eq!(
            &packet[44..60],
            &tcp_md5(source, destination, &unsigned, &[1, 2, 3, 4])
        );

        let mut sum = checksum_add(0, &source.octets());
        sum = checksum_add(sum, &destination.octets());
        sum = checksum_add(sum, &[0, 6]);
        sum = checksum_add(sum, &44u16.to_be_bytes());
        sum = checksum_add(sum, &packet[20..60]);
        sum = checksum_add(sum, &[1, 2, 3, 4]);
        assert_eq!(checksum_finish(sum), 0);
    }

    #[test]
    fn a_noise_plan_draws_its_lengths_and_counts() {
        let noise = Noise {
            kind: NoiseKind::Rand { bytes: (7, 7) },
            length_min: 10,
            length_max: 12,
            delay_min: 0,
            delay_max: 0,
            count: 3,
        };
        for _ in 0..8 {
            let packet = noise.generate().expect("draws");
            assert!((10..=11).contains(&packet.len()));
            assert!(packet.iter().all(|byte| *byte == 7));
        }
        assert_eq!(noise.delay(), Duration::ZERO);
    }

    fn hello(name: &str) -> Vec<u8> {
        let mut server = vec![0, 0, 0];
        server.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server.extend_from_slice(name.as_bytes());
        let list = (name.len() + 3) as u16;
        server[0..2].copy_from_slice(&list.to_be_bytes());
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(server.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server);
        let mut handshake = vec![0x01, 0, 0, 0, 0x03, 0x03];
        handshake.extend_from_slice(&[0x11; 32]);
        handshake.push(0);
        handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        handshake.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&ext);
        let length = (handshake.len() - 4) as u32;
        handshake[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_server_name_is_found_and_never_guessed_on_a_cut_record() {
        let record = hello("www.example.com");
        let range = server_name_range(&record).expect("a name");
        assert_eq!(&record[range.clone()], b"www.example.com");
        for cut in 0..range.end {
            assert!(
                server_name_range(&record[..cut]).is_none(),
                "a record cut at {cut} has no complete name"
            );
        }
        let mut server_hello = record.clone();
        server_hello[5] = 0x02;
        assert!(server_name_range(&server_hello).is_none());
        let mut longer = record.clone();
        longer.push(0);
        assert!(
            server_name_range(&longer).is_some(),
            "a trailing write is not part of the record"
        );
    }

    #[test]
    fn every_label_of_a_name_takes_a_cut_inside_it() {
        let name = b"www.example.co.uk";
        for _ in 0..16 {
            let cuts = label_cuts(name);
            assert_eq!(cuts.len(), 4, "one cut inside each of the four labels");
            assert!(cuts.windows(2).all(|pair| pair[0] < pair[1]), "{cuts:?}");
            for cut in &cuts {
                assert!((1..name.len()).contains(cut));
                assert_ne!(name[*cut], b'.', "a cut never lands on a label boundary");
            }
        }
        assert_eq!(label_cuts(b"a"), Vec::<usize>::new());
        assert_eq!(label_cuts(b"."), Vec::<usize>::new());
    }

    #[test]
    fn a_mixed_case_name_is_the_same_name_to_the_server() {
        for _ in 0..16 {
            let name = mixed_case_name("www.example.com");
            assert_eq!(name.len(), 15);
            assert!(name.eq_ignore_ascii_case("www.example.com"));
            for label in name.split('.') {
                assert!(
                    label.starts_with(|first: char| first.is_ascii_uppercase()),
                    "{name}: every label opens upper case"
                );
            }
        }
        assert_eq!(mixed_case_name(""), "");
        assert_eq!(mixed_case_name("192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn an_extension_length_past_the_record_is_refused_not_returned() {
        let mut record = hello("www.example.com");
        let range = server_name_range(&record).expect("a name");
        let mut at = 43;
        at += 1 + usize::from(record[at]);
        at += 2 + usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
        at += 1 + usize::from(record[at]);
        at += 2;
        record[at + 2..at + 4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(server_name_range(&record), None);
        assert!(range.end <= record.len());
    }

    #[test]
    fn a_quic_decoy_starts_like_a_long_header_initial() {
        let noise = Noise {
            kind: NoiseKind::Quic,
            length_min: 5,
            length_max: 10,
            delay_min: 0,
            delay_max: 0,
            count: 1,
        };
        let packet = noise.generate().expect("draws");
        assert!(packet.len() >= 25);
        assert_eq!(packet[0] & 0xc0, 0xc0);
        assert_eq!(&packet[1..5], &1u32.to_be_bytes());
        assert_eq!(packet[5], 8);
        assert_eq!(packet[14], 8);
        assert_eq!(packet[23], 0);
    }
}

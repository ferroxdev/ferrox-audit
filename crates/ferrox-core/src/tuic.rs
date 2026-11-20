//! TUIC v5 framing: the authentication header, CONNECT streams, and fragmented PACKET datagrams.

use std::net::IpAddr;

pub const VERSION: u8 = 5;
pub const ALPN: &[u8] = b"h3";

pub const AUTHENTICATE: u8 = 0;
pub const CONNECT: u8 = 1;
pub const PACKET: u8 = 2;
pub const DISSOCIATE: u8 = 3;
pub const HEARTBEAT: u8 = 4;

pub const TOKEN_LEN: usize = 32;
pub const AUTH_LEN: usize = 2 + 16 + TOKEN_LEN;
pub const MAX_ADDRESS: usize = 255;
pub const CONTINUATION: u8 = 0xff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Short,
    BadVersion(u8),
    BadCommand(u8),
    BadAddress(u8),
    EmptyName,
    NameTooLong,
    TooManyFragments,
    BadFragment,
    Trailing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(&'a [u8]),
}

impl<'a> Address<'a> {
    #[must_use]
    pub fn of(host: &'a str) -> Option<Self> {
        let bytes = host.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(match ip {
                IpAddr::V4(ip) => Self::V4(ip.octets()),
                IpAddr::V6(ip) => Self::V6(ip.octets()),
            });
        }
        (bytes.len() <= MAX_ADDRESS).then_some(Self::Name(bytes))
    }

    #[must_use]
    pub const fn wire_len(self) -> usize {
        match self {
            Self::V4(_) => 5,
            Self::V6(_) => 17,
            Self::Name(bytes) => 2 + bytes.len(),
        }
    }

    pub fn encode_into(self, out: &mut Vec<u8>) {
        match self {
            Self::V4(octets) => {
                out.push(1);
                out.extend_from_slice(&octets);
            }
            Self::V6(octets) => {
                out.push(2);
                out.extend_from_slice(&octets);
            }
            Self::Name(bytes) => {
                out.push(0);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
        }
    }

    pub fn take(data: &'a [u8], at: &mut usize) -> Result<Self, FrameError> {
        let kind = *data.get(*at).ok_or(FrameError::Short)?;
        *at += 1;
        match kind {
            0 => {
                let len = usize::from(*data.get(*at).ok_or(FrameError::Short)?);
                *at += 1;
                let end = at.checked_add(len).ok_or(FrameError::Short)?;
                let name = data.get(*at..end).ok_or(FrameError::Short)?;
                *at = end;
                if name.is_empty() {
                    return Err(FrameError::EmptyName);
                }
                Ok(Self::Name(name))
            }
            1 => {
                let end = at.checked_add(4).ok_or(FrameError::Short)?;
                let octets: [u8; 4] = data
                    .get(*at..end)
                    .ok_or(FrameError::Short)?
                    .try_into()
                    .expect("four bytes");
                *at = end;
                Ok(Self::V4(octets))
            }
            2 => {
                let end = at.checked_add(16).ok_or(FrameError::Short)?;
                let octets: [u8; 16] = data
                    .get(*at..end)
                    .ok_or(FrameError::Short)?
                    .try_into()
                    .expect("sixteen bytes");
                *at = end;
                Ok(Self::V6(octets))
            }
            other => Err(FrameError::BadAddress(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub association: u16,
    pub packet: u16,
    pub total: u8,
    pub index: u8,
    pub destination: Option<(Address<'a>, u16)>,
    pub payload: &'a [u8],
}

pub fn parse_packet_prefix(data: &[u8]) -> Result<(Packet<'_>, usize), FrameError> {
    if data.len() < 10 {
        return Err(FrameError::Short);
    }
    let version = data[0];
    if version != VERSION {
        return Err(FrameError::BadVersion(version));
    }
    if data[1] != PACKET {
        return Err(FrameError::BadCommand(data[1]));
    }
    let association = u16::from_be_bytes([data[2], data[3]]);
    let packet = u16::from_be_bytes([data[4], data[5]]);
    let total = data[6];
    let index = data[7];
    if total == 0 || index >= total {
        return Err(FrameError::BadFragment);
    }
    let payload_len = usize::from(u16::from_be_bytes([data[8], data[9]]));
    let mut at = 10;
    let destination = if index == 0 {
        let address = Address::take(data, &mut at)?;
        let end = at.checked_add(2).ok_or(FrameError::Short)?;
        let port = data.get(at..end).ok_or(FrameError::Short)?;
        at = end;
        Some((address, u16::from_be_bytes([port[0], port[1]])))
    } else {
        let marker = *data.get(at).ok_or(FrameError::Short)?;
        if marker != CONTINUATION {
            return Err(FrameError::BadFragment);
        }
        at += 1;
        None
    };
    let end = at.checked_add(payload_len).ok_or(FrameError::Short)?;
    let payload = data.get(at..end).ok_or(FrameError::Short)?;
    Ok((
        Packet {
            association,
            packet,
            total,
            index,
            destination,
            payload,
        },
        end,
    ))
}

pub fn parse_packet(data: &[u8]) -> Result<Packet<'_>, FrameError> {
    let (packet, end) = parse_packet_prefix(data)?;
    if end != data.len() {
        return Err(FrameError::Trailing);
    }
    Ok(packet)
}

pub fn encode_auth(uuid: &[u8; 16], token: &[u8; TOKEN_LEN], out: &mut Vec<u8>) {
    out.reserve(AUTH_LEN);
    out.extend_from_slice(&[VERSION, AUTHENTICATE]);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
}

pub fn encode_connect(host: &str, port: u16, out: &mut Vec<u8>) -> Result<(), FrameError> {
    let address = Address::of(host).ok_or(FrameError::EmptyName)?;
    out.reserve(2 + address.wire_len() + 2);
    out.extend_from_slice(&[VERSION, CONNECT]);
    address.encode_into(out);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

pub fn encode_dissociate(association: u16, out: &mut Vec<u8>) {
    out.reserve(4);
    out.extend_from_slice(&[VERSION, DISSOCIATE]);
    out.extend_from_slice(&association.to_be_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentPlan {
    pub total: u8,
    pub first: usize,
    pub continuation: usize,
}

#[must_use]
pub fn fragment_plan(max: usize, address_len: usize, payload_len: usize) -> Option<FragmentPlan> {
    let first_overhead = 10usize.checked_add(address_len)?;
    if max <= first_overhead || max <= 11 {
        return None;
    }
    let first = max - first_overhead;
    let continuation = max - 11;
    let total = if payload_len <= first {
        1
    } else {
        1usize.checked_add((payload_len - first).div_ceil(continuation))?
    };
    let total = u8::try_from(total).ok()?;
    Some(FragmentPlan {
        total,
        first,
        continuation,
    })
}

pub fn encode_fragment(
    association: u16,
    packet: u16,
    total: u8,
    index: u8,
    address: &[u8],
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    out.clear();
    out.extend_from_slice(&[VERSION, PACKET]);
    out.extend_from_slice(&association.to_be_bytes());
    out.extend_from_slice(&packet.to_be_bytes());
    out.push(total);
    out.push(index);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if index == 0 {
        out.extend_from_slice(address);
    } else {
        out.push(CONTINUATION);
    }
    out.extend_from_slice(payload);
}

#[must_use]
pub fn address_port(host: &str, port: u16) -> Option<Vec<u8>> {
    let address = Address::of(host)?;
    let mut out = Vec::with_capacity(address.wire_len() + 2);
    address.encode_into(&mut out);
    out.extend_from_slice(&port.to_be_bytes());
    Some(out)
}

/// Writes one address and its port into a caller's buffer, so a packet that already holds the
/// destination needs no `Vec` behind it. The returned length is what `encode_fragment` takes.
pub fn address_port_into(address: Address<'_>, port: u16, out: &mut [u8]) -> Option<usize> {
    if let Address::Name(bytes) = address {
        if bytes.is_empty() || bytes.len() > MAX_ADDRESS {
            return None;
        }
    }
    let len = address.wire_len();
    let total = len.checked_add(2)?;
    if out.len() < total {
        return None;
    }
    match address {
        Address::V4(octets) => {
            out[0] = 1;
            out[1..5].copy_from_slice(&octets);
        }
        Address::V6(octets) => {
            out[0] = 2;
            out[1..17].copy_from_slice(&octets);
        }
        Address::Name(bytes) => {
            out[0] = 0;
            out[1] = bytes.len() as u8;
            out[2..len].copy_from_slice(bytes);
        }
    }
    out[len..total].copy_from_slice(&port.to_be_bytes());
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_and_port_write_into_a_borrowed_buffer() {
        for host in ["192.0.2.1", "2001:db8::1", "example.test"] {
            let address = Address::of(host).expect("an address");
            let expected = address_port(host, 443).expect("bytes");
            let mut out = [0u8; MAX_ADDRESS + 4];
            let written =
                address_port_into(address, 443, &mut out).expect("the buffer is wide enough");
            assert_eq!(&out[..written], expected.as_slice());
        }
        assert_eq!(
            address_port_into(Address::V4([192, 0, 2, 1]), 1, &mut [0u8; 4]),
            None
        );
        let mut out = [0u8; MAX_ADDRESS + 4];
        assert_eq!(address_port_into(Address::Name(&[]), 1, &mut out), None);
        let long = [b'a'; MAX_ADDRESS + 1];
        assert_eq!(address_port_into(Address::Name(&long), 1, &mut out), None);
    }

    #[test]
    fn the_three_address_families_match_the_wire() {
        let mut out = Vec::new();
        Address::V4([192, 0, 2, 1]).encode_into(&mut out);
        assert_eq!(out, [1, 192, 0, 2, 1]);

        out.clear();
        Address::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .encode_into(&mut out);
        assert_eq!(out[0], 2);
        assert_eq!(out.len(), 17);

        out.clear();
        Address::Name(b"dns.example").encode_into(&mut out);
        assert_eq!(&out[..2], &[0, 11]);
        assert_eq!(&out[2..], b"dns.example");
    }

    #[test]
    fn every_address_round_trips_through_its_own_bytes() {
        for host in ["192.0.2.53", "2001:db8::1", "dns.example", "localhost"] {
            let address = Address::of(host).expect("an address");
            let mut out = Vec::new();
            address.encode_into(&mut out);
            let mut at = 0;
            assert_eq!(Address::take(&out, &mut at), Ok(address));
            assert_eq!(at, out.len());
        }
    }

    #[test]
    fn an_empty_or_overlong_name_is_refused_not_truncated() {
        assert_eq!(Address::of(""), None);
        assert_eq!(fragment_plan(1200, 0, 0), Some(sample_plan()));
        let long = "d".repeat(MAX_ADDRESS + 1);
        assert_eq!(Address::of(&long), None);
    }

    fn sample_plan() -> FragmentPlan {
        FragmentPlan {
            total: 1,
            first: 1190,
            continuation: 1189,
        }
    }

    #[test]
    fn a_packet_round_trips_and_rejects_a_continuation_without_its_marker() {
        let address = address_port("dns.example", 53).expect("an address");
        let plan = fragment_plan(28, address.len(), 32).expect("a plan");
        assert!(plan.total > 1);
        let mut frame = Vec::new();
        encode_fragment(7, 9, plan.total, 0, &address, &[1, 2, 3], &mut frame);
        let packet = parse_packet(&frame).expect("a packet");
        assert_eq!((packet.association, packet.packet), (7, 9));
        assert_eq!(
            packet.destination,
            Some((Address::Name(b"dns.example"), 53))
        );
        assert_eq!(packet.payload, [1, 2, 3]);

        encode_fragment(7, 9, plan.total, 1, &address, &[4], &mut frame);
        let packet = parse_packet(&frame).expect("a continuation");
        assert_eq!(packet.destination, None);
        frame[10] = 0;
        assert_eq!(parse_packet(&frame), Err(FrameError::BadFragment));
        frame.truncate(10);
        assert_eq!(parse_packet_prefix(&frame), Err(FrameError::Short));
    }

    #[test]
    fn every_truncated_packet_is_short_and_never_panics() {
        for host in ["192.0.2.53", "2001:db8::1", "dns.example"] {
            let address = address_port(host, 443).expect("an address");
            for index in [0, 1] {
                let mut frame = Vec::new();
                encode_fragment(1, 2, 2, index, &address, &[7u8; 32], &mut frame);
                for end in 0..frame.len() {
                    assert_eq!(
                        parse_packet_prefix(&frame[..end]),
                        Err(FrameError::Short),
                        "{host} index {index} truncated to {end}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_prefix_stops_at_the_first_frame_boundary() {
        let address = address_port("192.0.2.1", 53).expect("an address");
        let mut first = Vec::new();
        encode_fragment(1, 2, 1, 0, &address, b"first", &mut first);
        let mut second = Vec::new();
        encode_fragment(1, 2, 1, 0, &address, b"second", &mut second);
        let first_len = first.len();
        let second_len = second.len();
        first.extend_from_slice(&second);

        let (packet, used) = parse_packet_prefix(&first).expect("a first packet");
        assert_eq!(used, first_len);
        assert_eq!(packet.payload, b"first");
        let (packet, used) = parse_packet_prefix(&first[used..]).expect("a second packet");
        assert_eq!(used, second_len);
        assert_eq!(packet.payload, b"second");
    }

    #[test]
    fn a_packet_with_trailing_bytes_is_refused() {
        let address = address_port("192.0.2.1", 53).expect("an address");
        let mut frame = Vec::new();
        encode_fragment(1, 2, 1, 0, &address, b"x", &mut frame);
        frame.push(0);
        assert_eq!(parse_packet(&frame), Err(FrameError::Trailing));
    }

    #[test]
    fn fragmentation_splits_at_the_negotiated_datagram_size() {
        let payload = [0u8; 40];
        let address = address_port("dns.example", 53).expect("an address");
        let plan = fragment_plan(28, address.len(), payload.len()).expect("a plan");
        assert!(plan.total > 1);
        let mut frame = Vec::new();
        let mut left = &payload[..];
        let mut sent = 0;
        for index in 0..plan.total {
            let take = left.len().min(if index == 0 {
                plan.first
            } else {
                plan.continuation
            });
            encode_fragment(1, 2, plan.total, index, &address, &left[..take], &mut frame);
            assert!(frame.len() <= 28);
            sent += parse_packet(&frame).expect("a fragment").payload.len();
            left = &left[take..];
        }
        assert_eq!(sent, payload.len());
    }
}

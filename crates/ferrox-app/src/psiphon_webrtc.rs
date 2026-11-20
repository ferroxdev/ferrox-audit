//! A str0m WebRTC data channel between the client and an in-proxy destination.

use crate::psiphon_broker::{Broker, Client, Destination, Front, Metrics, OfferSettings};
use crate::psiphon_ssh::dial_random;
use crate::psiphon_ssh::Identity;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::media::{Direction, MediaKind, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{RtpWrite, SeqNo};
use str0m::{Candidate, Event, Input, Output, Rtc};

const STUN_HEADER_LEN: usize = ferrox_core::stun::HEADER_LEN;
const MAX_DATAGRAM: usize = 65_536;
const PADDING_DONE: i64 = -1;
const MESSAGE_TIMEOUT: Duration = Duration::from_millis(5);
const STOP_POLL: Duration = Duration::from_millis(50);
const STREAM_MESSAGE: usize = 16 * 1024;
const NAT_DISCOVERY_ROUND_TRIP: Duration = Duration::from_secs(2);
const NAT_MAPPING_UNKNOWN: u64 = 0;
const NAT_MAPPING_ENDPOINT_INDEPENDENT: u64 = 1;
const NAT_MAPPING_ADDRESS_DEPENDENT: u64 = 2;
const NAT_MAPPING_ADDRESS_PORT_DEPENDENT: u64 = 3;
const NAT_FILTERING_UNKNOWN: u64 = 0;
const NAT_FILTERING_ENDPOINT_INDEPENDENT: u64 = 1;
const NAT_FILTERING_ADDRESS_DEPENDENT: u64 = 2;
const NAT_FILTERING_ADDRESS_PORT_DEPENDENT: u64 = 3;
const TRAFFIC_SHAPING_OFFER_CONTEXT: &[u8] = b"in-proxy-traffic-shaping-offer";
const MEDIA_PROPERTIES_OFFER_CONTEXT: &[u8] = b"in-proxy-media-track-properties-offer";
const MEDIA_MAX_RTP_PAYLOAD: usize = 1171;
const MEDIA_MAX_PADDING: usize = 254;
const MEDIA_MAX_ID: u64 = 256;
const MEDIA_CLOCK_RATE: u32 = 90_000;

/// The reference's data-channel traffic-shaping parameters, carried to the proxy in the offer.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TrafficShapingParameters {
    pub(crate) min_padded_messages: u64,
    pub(crate) max_padded_messages: u64,
    pub(crate) min_padding_size: u64,
    pub(crate) max_padding_size: u64,
    pub(crate) min_decoy_messages: u64,
    pub(crate) max_decoy_messages: u64,
    pub(crate) min_decoy_size: u64,
    pub(crate) max_decoy_size: u64,
    pub(crate) decoy_message_probability: f64,
}

impl Default for TrafficShapingParameters {
    fn default() -> Self {
        Self {
            min_padded_messages: 0,
            max_padded_messages: 10,
            min_padding_size: 0,
            max_padding_size: 1500,
            min_decoy_messages: 0,
            max_decoy_messages: 10,
            min_decoy_size: 1,
            max_decoy_size: 1500,
            decoy_message_probability: 0.5,
        }
    }
}

impl TrafficShapingParameters {
    /// The reference's media-track defaults, whose padding fits one RTP payload.
    pub(crate) fn media_default() -> Self {
        Self {
            max_padding_size: 254,
            max_decoy_size: 1200,
            ..Self::default()
        }
    }
}

/// One outbound media track and the plaintext RTP fields the reference varies.
struct MediaTrack {
    mid: Mid,
    pt: Option<Pt>,
    sequence: u16,
    timestamp: u32,
    timestamp_tick: u32,
    frame_range: (u64, u64),
    remaining_frame: u64,
    rng: MediaRng,
}

impl MediaTrack {
    fn next_sequence(&mut self) -> SeqNo {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        SeqNo::from(u64::from(sequence))
    }

    fn advance_frame(&mut self, sent: usize) {
        self.remaining_frame = self.remaining_frame.saturating_sub(sent as u64);
        if self.remaining_frame == 0 {
            self.timestamp = self.timestamp.wrapping_add(self.timestamp_tick);
            self.remaining_frame = self.rng.range(self.frame_range.0, self.frame_range.1);
        }
    }
}

/// A live WebRTC data channel or media track carrying in-proxy bytes.
pub(crate) struct WebRtc {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    pending: Option<SdpPendingOffer>,
    channel: Option<ChannelId>,
    media: Option<MediaTrack>,
    open: bool,
    buffer: Vec<u8>,
    events: VecDeque<Event>,
    peer: Option<IpAddr>,
    debug: bool,
    shaping: Option<(TrafficShapingParameters, [u8; 32])>,
    media_shaping: Option<Shaping>,
    send_timeout: Option<Duration>,
    stop: Option<Arc<AtomicBool>>,
}

impl WebRtc {
    /// Gather candidates, create the offer SDP, and return the pending answer.
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub(crate) fn offer(
        destination: IpAddr,
        stun_servers: &[String],
        disable_stun: bool,
        disable_ipv6_ice: bool,
        disable_inbound: bool,
        debug: bool,
        timeout: Duration,
        dns: &crate::psiphon_dns::Config,
        unreliable: bool,
        media_secret: Option<[u8; 32]>,
    ) -> Result<(Self, String), String> {
        let socket = bind_socket(destination)?;
        let local = socket
            .local_addr()
            .map_err(|error| format!("psiphon webrtc local: {error}"))?;
        let mut rtc = if media_secret.is_some() {
            Rtc::builder()
                .set_rtp_mode(true)
                .enable_h265(false)
                .enable_h266(false)
                .build(Instant::now())
        } else {
            Rtc::new(Instant::now())
        };
        if !(disable_ipv6_ice && local.is_ipv6()) {
            let host = Candidate::host(local, "udp")
                .map_err(|error| format!("psiphon webrtc candidate: {error}"))?;
            let _ = rtc.add_local_candidate(host);
        }
        if !disable_stun && !disable_inbound {
            if let Some(server) = choose_stun(stun_servers) {
                let stun_timeout = timeout.min(Duration::from_secs(3));
                if let Ok(Some(mapped)) = stun_binding(&socket, local, server, stun_timeout, dns) {
                    if !(disable_ipv6_ice && mapped.is_ipv6()) {
                        if let Ok(candidate) = Candidate::server_reflexive(mapped, local, "udp") {
                            let _ = rtc.add_local_candidate(candidate);
                        }
                    }
                }
            }
        }
        let mut changes = rtc.sdp_api();
        let (channel, media) = if let Some(secret) = media_secret {
            let mut properties = media_properties(secret);
            let mid = changes.add_media(
                MediaKind::Video,
                Direction::SendRecv,
                Some(std::mem::take(&mut properties.stream_id)),
                Some(std::mem::take(&mut properties.track_id)),
                None,
            );
            (
                None,
                Some(MediaTrack {
                    mid,
                    pt: None,
                    sequence: properties.sequence,
                    timestamp: properties.timestamp,
                    timestamp_tick: properties.timestamp_tick,
                    frame_range: properties.frame_range,
                    remaining_frame: properties.remaining_frame,
                    rng: MediaRng {
                        state: properties.rng_state,
                    },
                }),
            )
        } else {
            let config = ChannelConfig {
                label: label(),
                ordered: !unreliable,
                reliability: if unreliable {
                    Reliability::MaxRetransmits { retransmits: 0 }
                } else {
                    Reliability::Reliable
                },
                ..ChannelConfig::default()
            };
            (Some(changes.add_channel_with_config(config)), None)
        };
        let (offer, pending) = changes
            .apply()
            .ok_or_else(|| "psiphon webrtc: no offer".to_owned())?;
        Ok((
            Self {
                rtc,
                socket,
                local,
                pending: Some(pending),
                channel,
                media,
                open: false,
                buffer: vec![0u8; MAX_DATAGRAM],
                events: VecDeque::new(),
                peer: None,
                debug,
                shaping: None,
                media_shaping: None,
                send_timeout: Some(Duration::from_secs(30)),
                stop: None,
            },
            offer.to_sdp_string(),
        ))
    }

    /// Apply the broker's answer SDP.
    pub(crate) fn answer(&mut self, sdp: &str) -> Result<(), String> {
        let answer = SdpAnswer::from_sdp_string(sdp)
            .map_err(|error| format!("psiphon webrtc answer: {error}"))?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| "psiphon webrtc: already answered".to_owned())?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|error| format!("psiphon webrtc answer: {error}"))?;
        if let Some(media) = self.media.as_mut() {
            media.pt = self
                .rtc
                .media(media.mid)
                .and_then(|remote| remote.remote_pts().first().copied());
        }
        Ok(())
    }

    /// Drive ICE and DTLS until the data channel opens.
    pub(crate) fn await_channel(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let next = self.pump()?;
            let channel_open = self
                .channel
                .is_some_and(|channel| self.rtc.channel(channel).is_some());
            if self.open || channel_open {
                self.open = true;
                self.pump()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                let what = if self.media.is_some() {
                    "media track did not connect"
                } else {
                    "data channel did not open"
                };
                return Err(format!("psiphon webrtc: {what}"));
            }
            self.wait(next.min(deadline))?;
        }
    }

    /// Write one message on the data channel or one media-track packet.
    pub(crate) fn send(&mut self, data: &[u8]) -> Result<(), String> {
        if self.media.is_some() {
            return self.send_media(data);
        }
        let channel = self
            .channel
            .ok_or_else(|| "psiphon webrtc: data channel is closed".to_owned())?;
        let deadline = self.send_timeout.map(|timeout| Instant::now() + timeout);
        let tracked = self.stop.is_some();
        loop {
            if self
                .stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::Acquire))
            {
                return Err("psiphon webrtc: driver stopped".to_owned());
            }
            let accepted = self
                .rtc
                .channel(channel)
                .ok_or_else(|| "psiphon webrtc: data channel is closed".to_owned())?
                .write(true, data)
                .map_err(|error| format!("psiphon webrtc write: {error}"))?;
            let mut events = Vec::new();
            let next = self.pump_into(&mut events)?;
            self.events.extend(events);
            if accepted {
                return Ok(());
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err("psiphon webrtc write timed out".to_owned());
            }
            let until = deadline.map_or(next, |deadline| next.min(deadline));
            let until = if tracked {
                until.min(Instant::now() + STOP_POLL)
            } else {
                until
            };
            self.wait(until)?;
        }
    }

    fn send_media(&mut self, data: &[u8]) -> Result<(), String> {
        if data.len() > MEDIA_MAX_RTP_PAYLOAD - 1 {
            return Err(format!(
                "psiphon webrtc media write too large: {} + 1 header > {MEDIA_MAX_RTP_PAYLOAD}",
                data.len()
            ));
        }
        let payload = if let Some(shaping) = self.media_shaping.as_mut() {
            shaping.frame_media(data, MEDIA_MAX_RTP_PAYLOAD)
        } else {
            let mut payload = Vec::with_capacity(data.len() + 1);
            payload.push(0);
            payload.extend_from_slice(data);
            payload
        };
        self.write_media_payload(payload)
    }

    fn write_media_payload(&mut self, payload: Vec<u8>) -> Result<(), String> {
        let media = self
            .media
            .as_mut()
            .ok_or_else(|| "psiphon webrtc: no media track".to_owned())?;
        let pt = media.pt.ok_or_else(|| {
            "psiphon webrtc: media track has no negotiated payload type".to_owned()
        })?;
        let sequence = media.next_sequence();
        let timestamp = media.timestamp;
        let sent = payload.len();
        let mut direct = self.rtc.direct_api();
        let stream = direct
            .stream_tx_by_mid(media.mid, None)
            .ok_or_else(|| "psiphon webrtc: media track is not declared".to_owned())?;
        stream.write_rtp(RtpWrite::new(
            pt,
            sequence,
            timestamp,
            Instant::now(),
            payload,
        ));
        media.advance_frame(sent);
        Ok(())
    }

    fn send_media_decoy(&mut self) -> Result<(), String> {
        let Some(decoy) = self
            .media_shaping
            .as_mut()
            .and_then(|shaping| shaping.decoy_media(MEDIA_MAX_RTP_PAYLOAD))
        else {
            return Ok(());
        };
        self.write_media_payload(decoy)
    }

    /// Read the next message from the data channel, or `None` on timeout.
    pub(crate) fn receive(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = self.events.pop_front() {
                match event {
                    Event::ChannelData(data)
                        if self.channel.is_some_and(|channel| data.id == channel) =>
                    {
                        return Ok(Some(data.data))
                    }
                    Event::ChannelClose(id)
                        if self.channel.is_some_and(|channel| id == channel) =>
                    {
                        return Err("psiphon webrtc: data channel closed".to_owned())
                    }
                    Event::RtpPacket(packet) if self.media.is_some() => {
                        let payload = packet.payload.as_ref();
                        if payload.is_empty() {
                            return Err("psiphon webrtc: invalid media padding".to_owned());
                        }
                        let padding = usize::from(payload[0]);
                        if padding == 255 {
                            continue;
                        }
                        if payload.len() < 1 + padding {
                            return Err(format!(
                                "psiphon webrtc: invalid media padding {} < {}",
                                payload.len(),
                                1 + padding
                            ));
                        }
                        let data = payload[1 + padding..].to_vec();
                        self.send_media_decoy()?;
                        return Ok(Some(data));
                    }
                    Event::IceConnectionStateChange(str0m::IceConnectionState::Disconnected) => {
                        return Err("psiphon webrtc: ICE disconnected".to_owned())
                    }
                    _ => {}
                }
            } else {
                let mut events = Vec::new();
                let next = self.pump_into(&mut events)?;
                self.events.extend(events);
                if self.events.is_empty() {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    self.wait(next.min(deadline))?;
                }
            }
        }
    }

    /// Move buffered channel data ahead of a terminal send failure.
    fn take_received(
        &mut self,
        raw: bool,
        padding_done: &mut bool,
        backlog: &mut VecDeque<Result<Vec<u8>, String>>,
    ) {
        while let Some(event) = self.events.pop_front() {
            match event {
                Event::ChannelData(data)
                    if self.channel.is_some_and(|channel| data.id == channel) =>
                {
                    if raw {
                        if !data.data.is_empty() {
                            backlog.push_back(Ok(data.data));
                        }
                    } else if let Ok(Some(payload)) = unframe(data.data, padding_done) {
                        if !payload.is_empty() {
                            backlog.push_back(Ok(payload));
                        }
                    }
                }
                Event::RtpPacket(packet) if self.media.is_some() => {
                    let payload = packet.payload.as_ref();
                    let Some(padding) = payload.first().map(|byte| usize::from(*byte)) else {
                        continue;
                    };
                    if padding == 255 || payload.len() < 1 + padding {
                        continue;
                    }
                    let data = payload[1 + padding..].to_vec();
                    if !data.is_empty() {
                        backlog.push_back(Ok(data));
                    }
                }
                _ => {}
            }
        }
    }

    /// The address the last peer datagram came from.
    pub(crate) fn peer_ip(&self) -> Option<IpAddr> {
        self.peer
    }

    /// Set the traffic-shaping parameters and the root secret that seeds their PRNG.
    pub(crate) fn set_traffic_shaping(
        &mut self,
        parameters: TrafficShapingParameters,
        root_secret: [u8; 32],
    ) {
        if self.media.is_some() {
            self.media_shaping = Some(Shaping::new(parameters, root_secret));
        } else {
            self.shaping = Some((parameters, root_secret));
        }
    }

    /// Move the engine onto a driver thread and expose it as an `io` stream.
    pub(crate) fn into_stream(mut self, timeout: Duration) -> Result<WebRtcStream, String> {
        self.send_timeout = Some(timeout);
        WebRtcStream::spawn(self, timeout)
    }

    /// Drain engine output, sending every transmitted datagram.
    fn pump(&mut self) -> Result<Instant, String> {
        let mut events = Vec::new();
        let next = self.pump_into(&mut events)?;
        self.events.extend(events);
        Ok(next)
    }

    /// Drain engine output, sending datagrams and collecting events.
    fn pump_into(&mut self, events: &mut Vec<Event>) -> Result<Instant, String> {
        loop {
            match self
                .rtc
                .poll_output()
                .map_err(|error| format!("psiphon webrtc: {error}"))?
            {
                Output::Timeout(until) => return Ok(until),
                Output::Transmit(transmit) => {
                    let _ = self
                        .socket
                        .send_to(&transmit.contents, transmit.destination);
                }
                Output::Event(Event::ChannelOpen(id, _))
                    if self.channel.is_some_and(|channel| id == channel) =>
                {
                    self.open = true;
                }
                Output::Event(Event::Connected) if self.media.is_some() => {
                    self.open = true;
                }
                Output::Event(event) => {
                    if self.debug {
                        if let Event::ChannelData(data) = &event {
                            eprintln!(
                                "psiphon webrtc: channel {:?} data {} bytes",
                                data.id,
                                data.data.len()
                            );
                        } else {
                            eprintln!("psiphon webrtc: {event:?}");
                        }
                    }
                    events.push(event);
                }
            }
        }
    }

    /// Wait for one datagram or for the engine's next deadline.
    fn wait(&mut self, until: Instant) -> Result<(), String> {
        let wait = until
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        self.socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("psiphon webrtc timeout: {error}"))?;
        match self.socket.recv_from(&mut self.buffer) {
            Ok((length, source)) => {
                self.peer = Some(source.ip());
                let destination = self.local;
                let input =
                    Receive::new(Protocol::Udp, source, destination, &self.buffer[..length])
                        .map_or_else(
                            |_| Input::Timeout(Instant::now()),
                            |receive| Input::Receive(Instant::now(), receive),
                        );
                self.rtc
                    .handle_input(input)
                    .map_err(|error| format!("psiphon webrtc receive: {error}"))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
                ) =>
            {
                self.rtc
                    .handle_input(Input::Timeout(Instant::now()))
                    .map_err(|error| format!("psiphon webrtc timeout: {error}"))
            }
            Err(error) => Err(format!("psiphon webrtc receive: {error}")),
        }
    }
}

struct MediaProperties {
    stream_id: String,
    track_id: String,
    sequence: u16,
    timestamp: u32,
    timestamp_tick: u32,
    frame_range: (u64, u64),
    remaining_frame: u64,
    rng_state: u64,
}

struct MediaRng {
    state: u64,
}

impl MediaRng {
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn range(&mut self, min: u64, max: u64) -> u64 {
        if max <= min {
            return min;
        }
        min + self.next() % (max - min + 1)
    }

    fn id(&mut self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let length = usize::try_from(self.range(1, MEDIA_MAX_ID)).unwrap_or(1);
        let mut id = String::with_capacity(length * 2);
        for _ in 0..length {
            let byte = self.next() as u8;
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        id
    }
}

pub(crate) fn offers_media(sdp: &str) -> bool {
    sdp.lines()
        .any(|line| line.trim_start().starts_with("m=video"))
}

fn media_properties(secret: [u8; 32]) -> MediaProperties {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const FRAME_RANGES: [(u64, u64); 5] = [
        (KIB, 10 * KIB),
        (50 * KIB, 200 * KIB),
        (100 * KIB, 500 * KIB),
        (300 * KIB, MIB),
        (MIB, 4 * MIB),
    ];
    const FRAME_RATES: [u32; 3] = [25, 30, 60];
    let mut seed = [0u8; 32];
    let _ = Hkdf::<Sha256>::new(None, &secret).expand(MEDIA_PROPERTIES_OFFER_CONTEXT, &mut seed);
    let mut rng = MediaRng {
        state: u64::from_be_bytes(seed[..8].try_into().unwrap_or([0u8; 8])),
    };
    let frame_range = FRAME_RANGES[usize::try_from(rng.range(0, 4)).unwrap_or(0)];
    let frame_rate = FRAME_RATES[usize::try_from(rng.range(0, 2)).unwrap_or(0)];
    let remaining_frame = rng.range(frame_range.0, frame_range.1);
    MediaProperties {
        stream_id: rng.id(),
        track_id: rng.id(),
        sequence: u16::try_from(rng.range(0, u64::from(u16::MAX))).unwrap_or(0),
        timestamp: rng.next() as u32,
        timestamp_tick: MEDIA_CLOCK_RATE / frame_rate,
        frame_range,
        remaining_frame,
        rng_state: rng.state,
    }
}

/// Return a random lowercase hex data-channel label.
fn label() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let length = usize::from(u16::from_be_bytes(dial_random::<2>()) % 32) + 1;
    let mut label = String::with_capacity(length * 2);
    for byte in &dial_random::<32>()[..length] {
        label.push(char::from(HEX[usize::from(byte >> 4)]));
        label.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    label
}

/// Bind a UDP socket on the interface the destination routes through.
fn bind_socket(destination: IpAddr) -> Result<UdpSocket, String> {
    let unspecified = if destination.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let probe = UdpSocket::bind(SocketAddr::new(unspecified, 0))
        .map_err(|error| format!("psiphon webrtc probe: {error}"))?;
    probe
        .connect(SocketAddr::new(destination, 9))
        .map_err(|error| format!("psiphon webrtc route: {error}"))?;
    let local = probe
        .local_addr()
        .map_err(|error| format!("psiphon webrtc route: {error}"))?;
    drop(probe);
    UdpSocket::bind(SocketAddr::new(local.ip(), 0))
        .map_err(|error| format!("psiphon webrtc bind: {error}"))
}

/// The reference tries one STUN server per dial, drawn from the configured list.
fn random_unit() -> f64 {
    f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0
}

fn weighted(probability: f64, roll: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 {
        return false;
    }
    roll < probability
}

/// The reference's `SleepWithJitter`: `base` plus up to `base * jitter`.
fn retry_delay(base: Duration, jitter: f64, roll: f64) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let jitter = jitter.clamp(0.0, 1.0);
    base.saturating_add(base.mul_f64(jitter * roll))
}

fn choose_stun(servers: &[String]) -> Option<&str> {
    if servers.is_empty() {
        return None;
    }
    let bound = u64::try_from(servers.len()).unwrap_or(u64::MAX);
    let ceiling = u64::MAX - u64::MAX % bound;
    let draw = loop {
        let draw = u64::from_be_bytes(dial_random::<8>());
        if draw < ceiling {
            break draw;
        }
    };
    let index = usize::try_from(draw % bound).unwrap_or(0);
    servers.get(index).map(String::as_str)
}

/// Send one RFC 5389 binding request and return its mapped address.
fn stun_binding(
    socket: &UdpSocket,
    local: SocketAddr,
    server: &str,
    timeout: Duration,
    dns: &crate::psiphon_dns::Config,
) -> Result<Option<SocketAddr>, String> {
    let ipv6 = local.is_ipv6();
    let same_family = |address: &SocketAddr| address.is_ipv6() == ipv6;
    let (host, port) = if let Ok(address) = server.parse::<SocketAddr>() {
        (address.ip().to_string(), address.port())
    } else if let Ok(address) = server.parse::<IpAddr>() {
        (address.to_string(), 3478)
    } else if let Some((host, port)) = server.rsplit_once(':') {
        match port.parse::<u16>() {
            Ok(port) => (host.trim_matches(['[', ']']).to_owned(), port),
            Err(_) => (server.to_owned(), 3478),
        }
    } else {
        (server.to_owned(), 3478)
    };
    let deadline = Instant::now() + timeout;
    let target = crate::psiphon_dns::resolve_with_deadline(dns, &host, port, Some(deadline))
        .map_err(|error| format!("psiphon webrtc STUN {server}: {error}"))?
        .into_iter()
        .find(same_family)
        .ok_or_else(|| format!("psiphon webrtc STUN {server}: no address"))?;
    let transaction = dial_random::<12>();
    let mut request = [0u8; STUN_HEADER_LEN];
    let _ = ferrox_core::stun::binding_request_into(&mut request, &transaction);
    socket
        .send_to(&request, target)
        .map_err(|error| format!("psiphon webrtc STUN send: {error}"))?;
    let mut reply = [0u8; 512];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("psiphon webrtc STUN timeout: {error}"))?;
        let (length, source) = match socket.recv_from(&mut reply) {
            Ok(reply) => reply,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None)
            }
            Err(error) => return Err(format!("psiphon webrtc STUN receive: {error}")),
        };
        if source == target {
            if let Some(mapped) = parse_stun(&reply[..length], &transaction) {
                return Ok(Some(mapped));
            }
        }
    }
}

/// Decode a binding success and return its mapped address, borrowed from the core codec the realm
/// punch shares — the duplicate walk and unmask this function used to own are gone.
fn parse_stun(reply: &[u8], transaction: &[u8; 12]) -> Option<SocketAddr> {
    ferrox_core::stun::decode_binding_response(reply, transaction)
}

/// Run RFC 5780 mapping and filtering discovery against one configured server.
pub(crate) fn discover_nat_type(
    servers: &[String],
    local: IpAddr,
    deadline: Instant,
    dns: &crate::psiphon_dns::Config,
) -> Option<u64> {
    if Instant::now() >= deadline {
        return None;
    }
    let server = choose_stun(servers)?;
    let ipv6 = local.is_ipv6();
    let target = resolve_nat_server(server, ipv6, dns, deadline).ok()?;
    let family = if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let filtering = UdpSocket::bind(family).ok()?;
    let filtering = nat_filtering(&filtering, target, deadline).ok()?;
    let mapping = UdpSocket::bind(family).ok()?;
    let mapping = nat_mapping(&mapping, target, deadline).ok()?;
    if mapping == NAT_MAPPING_UNKNOWN || filtering == NAT_FILTERING_UNKNOWN {
        return None;
    }
    Some(mapping << 2 | filtering)
}

fn resolve_nat_server(
    server: &str,
    ipv6: bool,
    dns: &crate::psiphon_dns::Config,
    deadline: Instant,
) -> Result<SocketAddr, String> {
    let (host, port) = if let Ok(address) = server.parse::<SocketAddr>() {
        (address.ip().to_string(), address.port())
    } else if let Ok(address) = server.parse::<IpAddr>() {
        (address.to_string(), 3478)
    } else if let Some((host, port)) = server.rsplit_once(':') {
        match port.parse::<u16>() {
            Ok(port) => (host.trim_matches(['[', ']']).to_owned(), port),
            Err(_) => (server.to_owned(), 3478),
        }
    } else {
        (server.to_owned(), 3478)
    };
    crate::psiphon_dns::resolve_with_deadline(dns, &host, port, Some(deadline))
        .map_err(|error| format!("psiphon NAT discovery {server}: {error}"))?
        .into_iter()
        .find(|address| address.is_ipv6() == ipv6)
        .ok_or_else(|| format!("psiphon NAT discovery {server}: no address"))
}

fn nat_round_trip(
    socket: &UdpSocket,
    target: SocketAddr,
    change_ip: bool,
    change_port: bool,
    deadline: Instant,
) -> Result<Option<ferrox_core::stun::BindingResponse>, String> {
    let round_deadline = deadline.min(Instant::now() + NAT_DISCOVERY_ROUND_TRIP);
    let transaction = dial_random::<12>();
    let mut request = [0u8; 28];
    let length = ferrox_core::stun::binding_request_with_change_into(
        &mut request,
        &transaction,
        change_ip,
        change_port,
    )
    .ok_or_else(|| "psiphon NAT discovery: request buffer".to_owned())?;
    socket
        .send_to(&request[..length], target)
        .map_err(|error| format!("psiphon NAT discovery send: {error}"))?;
    let mut reply = [0u8; 1500];
    loop {
        let now = Instant::now();
        if now >= round_deadline {
            return Ok(None);
        }
        let wait = round_deadline
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("psiphon NAT discovery timeout: {error}"))?;
        let (length, _) = match socket.recv_from(&mut reply) {
            Ok(reply) => reply,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None)
            }
            Err(error) => return Err(format!("psiphon NAT discovery receive: {error}")),
        };
        if let Some(response) =
            ferrox_core::stun::decode_binding_attributes(&reply[..length], &transaction)
        {
            return Ok(Some(response));
        }
    }
}

fn nat_mapping(socket: &UdpSocket, target: SocketAddr, deadline: Instant) -> Result<u64, String> {
    let first = nat_round_trip(socket, target, false, false, deadline)?
        .ok_or_else(|| "psiphon NAT discovery: mapping test timed out".to_owned())?;
    let mapped = first
        .mapped
        .ok_or_else(|| "psiphon NAT discovery: no mapped address".to_owned())?;
    let other = first
        .other
        .ok_or_else(|| "psiphon NAT discovery: no other address".to_owned())?;
    if mapped == socket.local_addr().map_err(|error| error.to_string())? {
        return Ok(NAT_MAPPING_ENDPOINT_INDEPENDENT);
    }
    if is_bogon(other.ip()) {
        return Err("psiphon NAT discovery: other address is not public".to_owned());
    }
    let second_target = SocketAddr::new(other.ip(), target.port());
    let second = nat_round_trip(socket, second_target, false, false, deadline)?
        .ok_or_else(|| "psiphon NAT discovery: second mapping test timed out".to_owned())?;
    if second.mapped == Some(mapped) {
        return Ok(NAT_MAPPING_ENDPOINT_INDEPENDENT);
    }
    let third = nat_round_trip(socket, other, false, false, deadline)?
        .ok_or_else(|| "psiphon NAT discovery: third mapping test timed out".to_owned())?;
    if third.mapped == second.mapped {
        Ok(NAT_MAPPING_ADDRESS_DEPENDENT)
    } else {
        Ok(NAT_MAPPING_ADDRESS_PORT_DEPENDENT)
    }
}

fn nat_filtering(socket: &UdpSocket, target: SocketAddr, deadline: Instant) -> Result<u64, String> {
    let first = nat_round_trip(socket, target, false, false, deadline)?
        .ok_or_else(|| "psiphon NAT discovery: filtering test timed out".to_owned())?;
    if first.mapped.is_none() || first.other.is_none() {
        return Err("psiphon NAT discovery: server has no RFC 5780 support".to_owned());
    }
    if nat_round_trip(socket, target, true, true, deadline)?.is_some() {
        return Ok(NAT_FILTERING_ENDPOINT_INDEPENDENT);
    }
    match nat_round_trip(socket, target, false, true, deadline)? {
        Some(_) => Ok(NAT_FILTERING_ADDRESS_DEPENDENT),
        None => Ok(NAT_FILTERING_ADDRESS_PORT_DEPENDENT),
    }
}

/// The reference's `IsBogon`: an address no peer or steering IP should name.
pub(crate) fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_bogon_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return is_bogon_v4(ip);
            }
            let octets = ip.octets();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (octets[0] == 0x01 && octets[1] == 0x00 && octets[2..8] == [0; 6])
                || (octets[0] == 0x20 && octets[1] == 0x01 && octets[2] <= 1)
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
                || (octets[0] == 0x20 && octets[1] == 0x02)
        }
    }
}

fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0
        || ip.is_private()
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        || ip.is_loopback()
        || ip.is_link_local()
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || ip.is_documentation()
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        // RFC 2544, not the reference's 192.18 typo.
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        || ip.is_multicast()
        || octets[0] >= 240
}

type InputChannel = Arc<Mutex<Receiver<Result<Vec<u8>, String>>>>;

/// The sender-side traffic-shaping state: random padding counts and decoy messages.
#[derive(Clone)]
struct Shaping {
    parameters: TrafficShapingParameters,
    state: u64,
    padded_messages: u64,
    decoy_messages: u64,
    decoy_done: bool,
    done: bool,
}

impl Shaping {
    /// Build the state from the offer's root secret, so a replayed dial pads the same way.
    fn new(parameters: TrafficShapingParameters, root_secret: [u8; 32]) -> Self {
        let mut seed = [0u8; 32];
        let _ = Hkdf::<Sha256>::new(None, &root_secret)
            .expand(TRAFFIC_SHAPING_OFFER_CONTEXT, &mut seed);
        let state = u64::from_be_bytes(seed[..8].try_into().unwrap_or([0u8; 8]));
        let min_padded = parameters.min_padded_messages;
        let max_padded = parameters.max_padded_messages;
        let min_decoy = parameters.min_decoy_messages;
        let max_decoy = parameters.max_decoy_messages;
        let mut shaping = Self {
            parameters,
            state,
            padded_messages: 0,
            decoy_messages: 0,
            decoy_done: false,
            done: false,
        };
        shaping.padded_messages = shaping.range(min_padded, max_padded);
        shaping.decoy_messages = shaping.range(min_decoy, max_decoy);
        shaping
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn range(&mut self, min: u64, max: u64) -> u64 {
        if max <= min {
            return min;
        }
        min + self.next() % (max - min + 1)
    }

    #[allow(clippy::cast_precision_loss)]
    fn coin(&mut self, probability: f64) -> bool {
        if probability >= 1.0 {
            return true;
        }
        if probability <= 0.0 {
            return false;
        }
        (self.next() as f64) / (u64::MAX as f64) < probability
    }

    /// Frame one application message; once the `-1` header has gone out, payloads pass through.
    fn frame(&mut self, payload: &[u8], maximum: usize) -> Vec<u8> {
        if self.done {
            return payload.to_vec();
        }
        let padding = if self.padded_messages > 0 {
            let padding = self.range(
                self.parameters.min_padding_size,
                self.parameters.max_padding_size,
            );
            self.padded_messages -= 1;
            i64::try_from(padding).unwrap_or(i64::MAX)
        } else if !self.decoy_done && self.decoy_messages > 0 {
            0
        } else {
            self.done = true;
            -1
        };
        self.build(payload, padding, maximum)
    }

    /// Frame one media-track payload with a one-byte padding header, never a done marker.
    fn frame_media(&mut self, payload: &[u8], maximum: usize) -> Vec<u8> {
        let mut padding = 0;
        if self.padded_messages > 0 {
            padding = self.range(
                self.parameters.min_padding_size,
                self.parameters.max_padding_size,
            );
            padding = padding.min(MEDIA_MAX_PADDING as u64);
            let room = maximum.saturating_sub(payload.len() + 1);
            padding = padding.min(room as u64);
            self.padded_messages -= 1;
        }
        let mut message =
            Vec::with_capacity(payload.len() + usize::try_from(padding).unwrap_or(0) + 1);
        message.push(u8::try_from(padding).unwrap_or(0));
        for _ in 0..padding {
            message.push(self.next() as u8);
        }
        message.extend_from_slice(payload);
        message
    }

    /// Build one media-track decoy packet, whose first payload byte is 255.
    fn decoy_media(&mut self, maximum: usize) -> Option<Vec<u8>> {
        if self.decoy_done {
            return None;
        }
        if self.decoy_messages == 0 {
            self.decoy_done = true;
            return None;
        }
        if !self.coin(self.parameters.decoy_message_probability) {
            return None;
        }
        self.decoy_messages -= 1;
        if self.decoy_messages == 0 {
            self.decoy_done = true;
        }
        let mut size = self.range(
            self.parameters.min_decoy_size,
            self.parameters.max_decoy_size,
        );
        size = size.min((maximum.saturating_sub(1)) as u64);
        let mut message = Vec::with_capacity(usize::try_from(size).unwrap_or(0) + 1);
        message.push(255);
        for _ in 0..size {
            message.push(self.next() as u8);
        }
        Some(message)
    }

    /// Build one decoy message when the decoy budget and probability allow it.
    fn decoy(&mut self, maximum: usize) -> Option<Vec<u8>> {
        if self.done || self.decoy_done {
            return None;
        }
        if self.decoy_messages == 0 {
            self.decoy_done = true;
            return None;
        }
        if !self.coin(self.parameters.decoy_message_probability) {
            return None;
        }
        self.decoy_messages -= 1;
        if self.decoy_messages == 0 {
            self.decoy_done = true;
        }
        let padding = self.range(
            self.parameters.min_decoy_size,
            self.parameters.max_decoy_size,
        );
        Some(self.build(&[], i64::try_from(padding).unwrap_or(i64::MAX), maximum))
    }

    fn build(&mut self, payload: &[u8], padding: i64, maximum: usize) -> Vec<u8> {
        let done = padding < 0;
        let mut padding = usize::try_from(padding).unwrap_or(0);
        let room = maximum.saturating_sub(payload.len() + 10);
        padding = padding.min(room);
        let mut message = Vec::with_capacity(payload.len() + padding + 10);
        put_varint(
            &mut message,
            if done {
                -1
            } else {
                i64::try_from(padding).unwrap_or(i64::MAX)
            },
        );
        for _ in 0..padding {
            message.push(self.next() as u8);
        }
        message.extend_from_slice(payload);
        message
    }
}

/// One in-proxy stream: bytes framed onto the data channel by a driver thread.
pub(crate) struct WebRtcStream {
    out: SyncSender<Vec<u8>>,
    input: InputChannel,
    terminal: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pending: Arc<Mutex<(Vec<u8>, usize)>>,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    padding_sent: Arc<AtomicBool>,
    shaping: Option<Arc<Mutex<Shaping>>>,
    media: bool,
    read_timeout: Arc<Mutex<Option<Duration>>>,
    write_timeout: Arc<Mutex<Option<Duration>>>,
}

impl ferrox_core::tls::RecordAlignment for WebRtcStream {}

impl Clone for WebRtcStream {
    fn clone(&self) -> Self {
        Self {
            out: self.out.clone(),
            input: Arc::clone(&self.input),
            terminal: Arc::clone(&self.terminal),
            pending: Arc::clone(&self.pending),
            stop: Arc::clone(&self.stop),
            failure: Arc::clone(&self.failure),
            padding_sent: Arc::clone(&self.padding_sent),
            shaping: self.shaping.as_ref().map(Arc::clone),
            media: self.media,
            read_timeout: Arc::clone(&self.read_timeout),
            write_timeout: Arc::clone(&self.write_timeout),
        }
    }
}

impl WebRtcStream {
    /// Start the driver thread and the bounded queues.
    fn spawn(mut webrtc: WebRtc, timeout: Duration) -> Result<Self, String> {
        let (out, out_rx) = mpsc::sync_channel(64);
        let (input_tx, input) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let failure = Arc::new(Mutex::new(None));
        let thread_failure = Arc::clone(&failure);
        let media = webrtc.media.is_some();
        let shaping = webrtc
            .shaping
            .take()
            .map(|(parameters, secret)| Arc::new(Mutex::new(Shaping::new(parameters, secret))));
        let unframed = media;
        let padding_sent = Arc::new(AtomicBool::new(unframed));
        let write_timeout = Arc::new(Mutex::new(Some(timeout)));
        let thread_write_timeout = Arc::clone(&write_timeout);
        let driver_shaping = shaping.as_ref().map(Arc::clone);
        let terminal = Arc::new(Mutex::new(VecDeque::new()));
        let thread_terminal = Arc::clone(&terminal);
        webrtc.stop = Some(Arc::clone(&stop));
        thread::Builder::new()
            .name("psiphon-webrtc".to_owned())
            .spawn(move || {
                drive(
                    webrtc,
                    out_rx,
                    input_tx,
                    thread_stop,
                    thread_failure,
                    unframed,
                    driver_shaping,
                    thread_write_timeout,
                    thread_terminal,
                );
            })
            .map_err(|error| format!("psiphon webrtc driver: {error}"))?;
        Ok(Self {
            out,
            input: Arc::new(Mutex::new(input)),
            terminal,
            pending: Arc::new(Mutex::new((Vec::new(), 0))),
            stop,
            failure,
            padding_sent,
            shaping,
            media,
            read_timeout: Arc::new(Mutex::new(Some(timeout))),
            write_timeout,
        })
    }

    /// The largest datagram a media track carries, once its framing header is reserved.
    pub(crate) fn media_payload_limit(&self) -> Option<usize> {
        self.media.then_some(MEDIA_MAX_RTP_PAYLOAD - 1)
    }

    /// Set or clear the read and write timeout.
    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) {
        *lock(&self.read_timeout) = timeout;
        *lock(&self.write_timeout) = timeout;
    }

    /// Set or clear only the read timeout, leaving the write deadline in place.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) {
        *lock(&self.read_timeout) = timeout;
    }

    /// Set or clear only the write timeout, leaving the read deadline in place.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) {
        *lock(&self.write_timeout) = timeout;
    }

    /// End the driver and every clone of this stream.
    pub(crate) fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Read for WebRtcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut pending = lock(&self.pending);
        loop {
            if pending.1 < pending.0.len() {
                let taken = (pending.0.len() - pending.1).min(buf.len());
                buf[..taken].copy_from_slice(&pending.0[pending.1..pending.1 + taken]);
                pending.1 += taken;
                return Ok(taken);
            }
            pending.0.clear();
            pending.1 = 0;
            let input = lock(&self.input);
            match input.try_recv() {
                Ok(Ok(data)) => {
                    pending.0 = data;
                    continue;
                }
                Ok(Err(error)) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }
            if let Some(error) = lock(&self.failure).as_ref().cloned() {
                match input.try_recv() {
                    Ok(Ok(data)) => {
                        pending.0 = data;
                        pending.1 = 0;
                    }
                    Ok(Err(error)) => {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                    }
                    Err(_) => {
                        if let Some(data) = lock(&self.terminal).pop_front() {
                            pending.0 = data;
                            pending.1 = 0;
                        } else {
                            return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                        }
                    }
                }
                continue;
            }
            let timeout = *lock(&self.read_timeout);
            let received = match timeout {
                Some(timeout) => input.recv_timeout(timeout),
                None => input.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(Ok(data)) => {
                    pending.0 = data;
                }
                Ok(Err(error)) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    if let Some(data) = lock(&self.terminal).pop_front() {
                        pending.0 = data;
                        pending.1 = 0;
                        continue;
                    }
                    if let Some(error) = lock(&self.failure).as_ref().cloned() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                    }
                    return Err(io::Error::from(ErrorKind::UnexpectedEof));
                }
            }
        }
    }
}

impl WebRtcStream {
    /// Queue a packet built from several slices as one or more data-channel messages.
    pub(crate) fn write_parts(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        if total == 0 {
            return Ok(0);
        }
        let deadline = (*lock(&self.write_timeout)).map(|timeout| Instant::now() + timeout);
        if self.media {
            let mut packet = Vec::with_capacity(total);
            for buf in bufs {
                packet.extend_from_slice(buf);
            }
            self.send_until(packet, deadline)?;
            return Ok(total);
        }
        if let Some(shaping) = &self.shaping {
            let mut shaping = lock_write(shaping, deadline)?;
            let mut queued = 0;
            for buf in bufs {
                for chunk in buf.chunks(STREAM_MESSAGE) {
                    let saved = shaping.clone();
                    let message = shaping.frame(chunk, MAX_DATAGRAM);
                    if let Err(error) = self.send_until(message, deadline) {
                        *shaping = saved;
                        return if queued > 0 { Ok(queued) } else { Err(error) };
                    }
                    queued += chunk.len();
                }
            }
            return Ok(total);
        }
        let first = !self.padding_sent.swap(true, Ordering::AcqRel);
        let mut message = Vec::with_capacity(STREAM_MESSAGE + 2);
        let mut header_len = 0;
        let mut queued = 0;
        if first {
            put_varint(&mut message, PADDING_DONE);
            header_len = message.len();
        }
        for buf in bufs {
            let mut at = 0;
            while at < buf.len() {
                if message.len() - header_len >= STREAM_MESSAGE {
                    let have = message.len() - header_len;
                    if let Err(error) = self.send_until(std::mem::take(&mut message), deadline) {
                        return if queued > 0 { Ok(queued) } else { Err(error) };
                    }
                    queued += have;
                    message.reserve(STREAM_MESSAGE + 2);
                    header_len = 0;
                }
                let room = STREAM_MESSAGE - (message.len() - header_len);
                let take = room.min(buf.len() - at);
                message.extend_from_slice(&buf[at..at + take]);
                at += take;
            }
        }
        if message.len() > header_len {
            let have = message.len() - header_len;
            if let Err(error) = self.send_until(message, deadline) {
                return if queued > 0 { Ok(queued) } else { Err(error) };
            }
            queued += have;
        }
        Ok(queued)
    }

    /// Queue one framed message against a deadline fixed before the first of a batch.
    fn send_until(&self, mut message: Vec<u8>, deadline: Option<Instant>) -> io::Result<()> {
        if let Some(error) = lock(&self.failure).as_ref().cloned() {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
        }
        loop {
            match self.out.try_send(message) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(back)) => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(io::Error::from(ErrorKind::TimedOut));
                    }
                    message = back;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(io::Error::from(ErrorKind::BrokenPipe));
                }
            }
        }
    }
}

impl Write for WebRtcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_parts(&[buf])
    }

    /// The driver has no user-space buffer to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Move datagrams between the engine and the bounded stream queues.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn drive(
    mut webrtc: WebRtc,
    out: Receiver<Vec<u8>>,
    input: SyncSender<Result<Vec<u8>, String>>,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    unframed: bool,
    shaping: Option<Arc<Mutex<Shaping>>>,
    write_timeout: Arc<Mutex<Option<Duration>>>,
    terminal: Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    let mut peer_padding_done = false;
    let mut backlog: VecDeque<Result<Vec<u8>, String>> = VecDeque::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        webrtc.send_timeout = *lock(&write_timeout);
        let mut wrote = false;
        for _ in 0..16 {
            match out.try_recv() {
                Ok(data) if data.is_empty() => {}
                Ok(data) => {
                    if let Err(error) = webrtc.send(&data) {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        webrtc.take_received(unframed, &mut peer_padding_done, &mut backlog);
                        let mut buffered = lock(&terminal);
                        for data in backlog.drain(..).flatten() {
                            buffered.push_back(data);
                        }
                        drop(buffered);
                        *lock(&failure) = Some(error);
                        stop.store(true, Ordering::Release);
                        return;
                    }
                    wrote = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        while let Some(message) = backlog.pop_front() {
            match input.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(message)) => {
                    backlog.push_front(message);
                    break;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
        if !backlog.is_empty() {
            if let Err(error) = webrtc.pump() {
                backlog.clear();
                backlog.push_back(Err(error));
            }
            thread::sleep(MESSAGE_TIMEOUT);
            continue;
        }
        let timeout = if wrote {
            Duration::ZERO
        } else {
            MESSAGE_TIMEOUT
        };
        match webrtc.receive(timeout) {
            Ok(Some(data)) => {
                if unframed {
                    if !data.is_empty() {
                        backlog.push_back(Ok(data));
                    }
                } else {
                    match unframe(data, &mut peer_padding_done) {
                        Ok(Some(payload)) if !payload.is_empty() => backlog.push_back(Ok(payload)),
                        Ok(_) => {}
                        Err(error) => backlog.push_back(Err(error)),
                    }
                }
                if let Some(shaping) = &shaping {
                    if !wrote {
                        let decoy =
                            try_lock(shaping).and_then(|mut shaping| shaping.decoy(MAX_DATAGRAM));
                        if let Some(message) = decoy {
                            if let Err(error) = webrtc.send(&message) {
                                backlog.push_back(Err(error));
                            }
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(error) => backlog.push_back(Err(error)),
        }
    }
}

/// Encode one signed zigzag varint.
fn put_varint(out: &mut Vec<u8>, value: i64) {
    let mut word = (value as u64) << 1;
    if value < 0 {
        word = !word;
    }
    loop {
        let byte = (word & 0x7f) as u8;
        word >>= 7;
        if word == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode one signed zigzag varint and advance `at`.
fn take_varint(data: &[u8], at: &mut usize) -> Option<i64> {
    let mut word = 0u64;
    let mut shift = 0u32;
    for (offset, byte) in data[*at..].iter().enumerate() {
        if offset == 10 {
            return None;
        }
        word |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            *at += offset + 1;
            let value = (word >> 1).cast_signed();
            return Some(if word & 1 == 0 { value } else { !value });
        }
        shift += 7;
    }
    None
}

/// Skip the peer's padding header and bytes, or return the message payload in the buffer it arrived in.
fn unframe(mut data: Vec<u8>, done: &mut bool) -> Result<Option<Vec<u8>>, String> {
    if *done {
        return Ok(Some(data));
    }
    let mut at = 0;
    let padding = take_varint(&data, &mut at)
        .ok_or_else(|| "psiphon webrtc: invalid padding header".to_owned())?;
    if padding < 0 {
        *done = true;
        if at >= data.len() {
            return Ok(None);
        }
        data.drain(..at);
        return Ok(Some(data));
    }
    let skip = at
        .checked_add(usize::try_from(padding).unwrap_or(usize::MAX))
        .filter(|skip| *skip <= data.len())
        .ok_or_else(|| "psiphon webrtc: invalid padding length".to_owned())?;
    if skip >= data.len() {
        return Ok(None);
    }
    data.drain(..skip);
    Ok(Some(data))
}

/// Lock, recovering the data after a panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Try to lock without waiting; a producer shaping a batch keeps the driver draining.
fn try_lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// Lock without waiting past the write deadline, or block when there is none.
fn lock_write<T>(mutex: &Mutex<T>, deadline: Option<Instant>) -> io::Result<MutexGuard<'_, T>> {
    let Some(deadline) = deadline else {
        return Ok(lock(mutex));
    };
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
                thread::sleep(left.min(Duration::from_millis(1)));
            }
        }
    }
}

/// Lock without waiting past the offer deadline.
fn lock_until<T>(mutex: &Mutex<T>, deadline: Instant) -> Result<MutexGuard<'_, T>, String> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err("psiphon conduit: offer retry window expired".to_owned());
                }
                std::thread::sleep(left.min(Duration::from_millis(2)));
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        let base = address.trim().parse::<IpAddr>().ok()?;
        let prefix = prefix.trim().parse::<u8>().ok()?;
        let width = if base.is_ipv4() { 32 } else { 128 };
        (prefix <= width).then_some(Self { base, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                mask(u128::from(u32::from(base)), self.prefix, 32)
                    == mask(u128::from(u32::from(address)), self.prefix, 32)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                mask(u128::from(base), self.prefix, 128)
                    == mask(u128::from(address), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn mask(value: u128, prefix: u8, width: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        let bits = if width == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        value & (bits << (width - u32::from(prefix)))
    }
}

/// One broker and the fronts it answers on.
pub(crate) struct BrokerRoute {
    pub(crate) broker: Broker,
    pub(crate) fronts: Vec<Front>,
}

/// Everything one in-proxy dial needs: brokers, their fronts, and the compartments.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Conduit {
    routes: Vec<BrokerRoute>,
    common: Vec<[u8; 32]>,
    personal: Vec<[u8; 32]>,
    stun_servers: Vec<String>,
    rfc5780_stun_servers: Vec<String>,
    disable_stun: bool,
    discover_nat: f64,
    discover_nat_timeout: Duration,
    media_streams: f64,
    media_traffic_shaping: f64,
    media_traffic_shaping_parameters: TrafficShapingParameters,
    traffic_shaping: f64,
    traffic_shaping_parameters: TrafficShapingParameters,
    disable_ipv6_ice: bool,
    disable_inbound: bool,
    debug: bool,
    share_client: bool,
    front_timeouts: Vec<(String, Duration)>,
    protocols: Vec<String>,
    timeout: Duration,
    offer_timeout: Duration,
    offer_personal_timeout: Duration,
    offer_retry_delay: Duration,
    offer_retry_jitter: f64,
    relay_timeout: Duration,
    await_ready_timeout: Duration,
    no_match_failover: f64,
    no_match_failover_personal: f64,
    headers: Vec<(String, String)>,
    proxy: Option<crate::psiphon_ssh::Proxy>,
    dns_config: crate::psiphon_dns::Config,
    reject: Vec<Cidr>,
    geoip: Option<crate::psiphon_geoip::GeoIp>,
    nat_type: Mutex<Option<u64>>,
    clients: Mutex<Vec<(String, Arc<Mutex<Client>>)>>,
}

impl Conduit {
    /// Build a conduit from a tactics payload and the selected compartments.
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub(crate) fn new(
        routes: Vec<BrokerRoute>,
        common: Vec<[u8; 32]>,
        personal: Vec<[u8; 32]>,
        stun_servers: Vec<String>,
        rfc5780_stun_servers: Vec<String>,
        disable_stun: bool,
        discover_nat: f64,
        discover_nat_timeout: Duration,
        media_streams: f64,
        media_traffic_shaping: f64,
        media_traffic_shaping_parameters: TrafficShapingParameters,
        traffic_shaping: f64,
        traffic_shaping_parameters: TrafficShapingParameters,
        disable_ipv6_ice: bool,
        disable_inbound: bool,
        debug: bool,
        share_client: bool,
        front_timeouts: Vec<(String, Duration)>,
        protocols: Vec<String>,
        timeout: Duration,
        offer_timeout: Duration,
        offer_personal_timeout: Duration,
        offer_retry_delay: Duration,
        offer_retry_jitter: f64,
        relay_timeout: Duration,
        await_ready_timeout: Duration,
        no_match_failover: f64,
        no_match_failover_personal: f64,
        headers: Vec<(String, String)>,
        proxy: Option<crate::psiphon_ssh::Proxy>,
        dns_config: crate::psiphon_dns::Config,
        reject_cidrs: &[String],
        geoip: Option<crate::psiphon_geoip::GeoIp>,
    ) -> Self {
        let reject = reject_cidrs
            .iter()
            .filter_map(|text| {
                let cidr = Cidr::parse(text);
                if cidr.is_none() {
                    eprintln!("psiphon conduit: ignoring invalid CIDR {text:?}");
                }
                cidr
            })
            .collect();
        Self {
            routes,
            common,
            personal,
            stun_servers,
            rfc5780_stun_servers,
            disable_stun,
            discover_nat,
            discover_nat_timeout,
            media_streams,
            media_traffic_shaping,
            media_traffic_shaping_parameters,
            traffic_shaping,
            traffic_shaping_parameters,
            disable_ipv6_ice,
            disable_inbound,
            debug,
            share_client,
            front_timeouts,
            protocols,
            timeout,
            offer_timeout,
            offer_personal_timeout,
            offer_retry_delay,
            offer_retry_jitter,
            relay_timeout,
            await_ready_timeout,
            no_match_failover,
            no_match_failover_personal,
            headers,
            proxy,
            dns_config,
            reject,
            geoip,
            nat_type: Mutex::new(None),
            clients: Mutex::new(Vec::new()),
        }
    }

    /// One broker session per broker and front when the wait-to-share setting is on.
    fn shared_client(
        &self,
        broker: &Broker,
        front: &Front,
        budget: Duration,
        offer_timeout: Duration,
        offer_personal_timeout: Duration,
    ) -> Result<Arc<Mutex<Client>>, String> {
        if !self.share_client {
            return Ok(Arc::new(Mutex::new(Client::connect(
                broker.clone(),
                front,
                budget,
                self.proxy.as_ref(),
                &self.headers,
                &self.dns_config,
                offer_timeout,
                offer_personal_timeout,
                self.relay_timeout,
            )?)));
        }
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            broker.public_key,
            broker.root_secret,
            front.host,
            front.dial,
            front.port,
            front.disable_sni,
            front.provider_id.as_deref().unwrap_or("")
        );
        if let Some((_, client)) = lock(&self.clients).iter().find(|(known, _)| known == &key) {
            return Ok(Arc::clone(client));
        }
        let client = Arc::new(Mutex::new(Client::connect(
            broker.clone(),
            front,
            budget,
            self.proxy.as_ref(),
            &self.headers,
            &self.dns_config,
            offer_timeout,
            offer_personal_timeout,
            self.relay_timeout,
        )?));
        let mut clients = lock(&self.clients);
        if let Some((_, known)) = clients.iter().find(|(known, _)| known == &key) {
            return Ok(Arc::clone(known));
        }
        clients.push((key, Arc::clone(&client)));
        Ok(client)
    }

    /// Dial the destination through the first broker front that answers.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn open(
        &self,
        address: IpAddr,
        destination: &Destination,
        identity: &Identity<'_>,
        allowance: Duration,
    ) -> Result<(InproxyStream, Relay), String> {
        if !self.routes.iter().any(|route| !route.fronts.is_empty()) {
            return Err("psiphon conduit: no broker front".to_owned());
        }
        if !matches!(
            destination.base_protocol(),
            "OSSH"
                | "SSH"
                | "TLS-OSSH"
                | "SHADOWSOCKS-OSSH"
                | "QUIC-OSSH"
                | "UNFRONTED-MEEK-OSSH"
                | "UNFRONTED-MEEK-HTTPS-OSSH"
                | "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
                | "FRONTED-MEEK-OSSH"
                | "FRONTED-MEEK-HTTP-OSSH"
                | "FRONTED-MEEK-QUIC-OSSH"
        ) {
            return Err(format!(
                "psiphon conduit: {} is not carried by this lane",
                destination.protocol
            ));
        }
        if !self.protocols.is_empty()
            && !self
                .protocols
                .iter()
                .any(|protocol| protocol.eq_ignore_ascii_case(destination.protocol))
        {
            return Err(format!(
                "psiphon conduit: {} is not in the configured protocol list",
                destination.protocol
            ));
        }
        let deadline = Instant::now()
            + self
                .timeout
                .min(self.offer_timeout.saturating_add(self.await_ready_timeout))
                .min(allowance);
        let mut metrics = Metrics::from_identity(identity);
        let nat_deadline = deadline.min(Instant::now() + self.discover_nat_timeout);
        if Instant::now() < nat_deadline && weighted(self.discover_nat, random_unit()) {
            if let Some(nat) = discover_nat_type(
                &self.rfc5780_stun_servers,
                address,
                nat_deadline,
                &self.dns_config,
            ) {
                *lock(&self.nat_type) = Some(nat);
            }
        }
        if let Some(nat) = *lock(&self.nat_type) {
            metrics.set_nat_type(nat);
        }
        let personal = !self.personal.is_empty();
        let failover = if personal {
            self.no_match_failover_personal
        } else {
            self.no_match_failover
        };
        let front_total: usize = self.routes.iter().map(|route| route.fronts.len()).sum();
        let mut failed = 0;
        let mut route_index = 0;
        let mut front_index = 0;
        let mut why = String::new();
        loop {
            let route = &self.routes[route_index];
            if route.fronts.is_empty() {
                route_index = (route_index + 1) % self.routes.len();
                if route_index == 0 && front_index == 0 {
                    return Err(why);
                }
                continue;
            }
            let front = &route.fronts[front_index % route.fronts.len()];
            let (result, no_match) = match self.dial_front(
                address,
                destination,
                front,
                &route.broker,
                &metrics,
                deadline,
            ) {
                Ok(pair) => return Ok(pair),
                Err((error, no_match)) => (error, no_match),
            };
            why = result;
            if !no_match {
                failed += 1;
                if failed >= front_total {
                    return Err(why);
                }
            }
            let rotate_broker = no_match && weighted(failover, random_unit());
            if no_match {
                let delay = retry_delay(
                    self.offer_retry_delay,
                    self.offer_retry_jitter,
                    random_unit(),
                );
                if delay >= deadline.saturating_duration_since(Instant::now()) {
                    return Err(why);
                }
                thread::sleep(delay);
            }
            if rotate_broker {
                route_index = (route_index + 1) % self.routes.len();
                front_index = 0;
            } else {
                front_index += 1;
                if front_index >= route.fronts.len() {
                    front_index = 0;
                    route_index = (route_index + 1) % self.routes.len();
                }
            }
            if Instant::now() >= deadline {
                return Err(why);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn dial_front(
        &self,
        address: IpAddr,
        destination: &Destination,
        front: &Front,
        broker: &Broker,
        metrics: &Metrics,
        deadline: Instant,
    ) -> Result<(InproxyStream, Relay), (String, bool)> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((
                "psiphon conduit: offer retry window expired".to_owned(),
                false,
            ));
        }
        let unreliable = matches!(
            destination.base_protocol(),
            "QUIC-OSSH" | "FRONTED-MEEK-QUIC-OSSH"
        );
        let budget = self.timeout.min(remaining);
        let provider = front.provider_id.as_deref().unwrap_or("");
        let max_request = self
            .front_timeouts
            .iter()
            .find(|(known, _)| known == provider)
            .map(|(_, timeout)| *timeout)
            .filter(|timeout| !timeout.is_zero());
        let offer_timeout =
            max_request.map_or(self.offer_timeout, |max| self.offer_timeout.min(max));
        let offer_personal_timeout = max_request.map_or(self.offer_personal_timeout, |max| {
            self.offer_personal_timeout.min(max)
        });
        let client = self
            .shared_client(broker, front, budget, offer_timeout, offer_personal_timeout)
            .map_err(|error| (error, false))?;
        let offer_secret = crate::psiphon_ssh::random::<32>();
        let media_secret = weighted(self.media_streams, random_unit()).then_some(offer_secret);
        let (mut webrtc, sdp) = WebRtc::offer(
            address,
            &self.stun_servers,
            self.disable_stun,
            self.disable_ipv6_ice,
            self.disable_inbound,
            self.debug,
            budget,
            &self.dns_config,
            unreliable,
            media_secret,
        )
        .map_err(|error| (error, false))?;
        let shaping = if media_secret.is_some() {
            weighted(self.media_traffic_shaping, random_unit())
                .then(|| self.media_traffic_shaping_parameters.clone())
        } else {
            weighted(self.traffic_shaping, random_unit())
                .then(|| self.traffic_shaping_parameters.clone())
        };
        if let Some(parameters) = shaping.as_ref() {
            webrtc.set_traffic_shaping(parameters.clone(), offer_secret);
        }
        let settings = OfferSettings {
            secret: offer_secret,
            traffic_shaping: shaping,
            use_media_streams: offers_media(&sdp),
        };
        let offer = {
            let mut client = lock_until(&client, deadline).map_err(|error| (error, false))?;
            let offer_remaining = deadline.saturating_duration_since(Instant::now());
            if offer_remaining.is_zero() {
                return Err((
                    "psiphon conduit: offer retry window expired".to_owned(),
                    false,
                ));
            }
            client.set_offer_timeouts(
                offer_timeout.min(offer_remaining),
                offer_personal_timeout.min(offer_remaining),
                deadline,
            );
            client
                .client_offer(
                    destination,
                    &self.common,
                    &self.personal,
                    &sdp,
                    metrics,
                    &settings,
                )
                .map_err(|error| (error, false))?
        };
        if offer.answer_sdp.is_empty() {
            return Err((
                format!(
                    "psiphon conduit: broker returned no answer (limited {}, no match {}, upgrade {})",
                    offer.limited, offer.no_match, offer.must_upgrade
                ),
                offer.no_match,
            ));
        }
        webrtc
            .answer(&offer.answer_sdp)
            .map_err(|error| (error, false))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((
                "psiphon conduit: offer retry window expired".to_owned(),
                false,
            ));
        }
        webrtc
            .await_channel(self.await_ready_timeout.min(remaining))
            .map_err(|error| (error, false))?;
        if !self.reject.is_empty() || self.geoip.is_some() {
            let Some(peer) = webrtc.peer_ip() else {
                return Err((
                    String::from("psiphon conduit: peer address was not observed"),
                    false,
                ));
            };
            if self.reject.iter().any(|cidr| cidr.contains(peer))
                || self.geoip.as_ref().is_some_and(|geoip| geoip.rejects(peer))
            {
                return Err((format!("psiphon conduit: rejected in-proxy {peer}"), false));
            }
        }
        let media = webrtc.media.is_some();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((
                "psiphon conduit: offer retry window expired".to_owned(),
                false,
            ));
        }
        let stream = webrtc
            .into_stream(self.timeout.min(remaining))
            .map_err(|error| (error, false))?;
        let stream = if media && !unreliable {
            let handshake_remaining = deadline.saturating_duration_since(Instant::now());
            if handshake_remaining.is_zero() {
                return Err((
                    "psiphon conduit: offer retry window expired".to_owned(),
                    false,
                ));
            }
            InproxyStream::Reliable(
                crate::psiphon_quic::QuicStream::connect_inproxy_reliability(
                    SocketAddr::new(address, 0),
                    handshake_remaining,
                    stream,
                    offer_secret,
                )
                .map_err(|error| (error, false))?,
            )
        } else {
            InproxyStream::WebRtc(stream)
        };
        Ok((
            stream,
            Relay {
                client,
                connection_id: offer.connection_id,
                initial: offer.relay_packet_to_server,
            },
        ))
    }
}

/// The stream returned by a conduit: a data channel or a media-track QUIC layer.
pub(crate) enum InproxyStream {
    WebRtc(WebRtcStream),
    Reliable(crate::psiphon_quic::QuicStream),
}

/// The broker session attached to one live in-proxy stream.
pub(crate) struct Relay {
    client: Arc<Mutex<Client>>,
    connection_id: Vec<u8>,
    initial: Vec<u8>,
}

impl Relay {
    /// The initial broker-to-server packet the handshake carries.
    pub(crate) fn initial(&self) -> &[u8] {
        &self.initial
    }

    /// The raw connection id the handshake names.
    pub(crate) fn connection_id(&self) -> &[u8] {
        &self.connection_id
    }

    /// Relay one server packet with the configured relay timeout.
    pub(crate) fn relay(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        lock(&self.client).relay_packet(&self.connection_id, packet)
    }

    /// Relay one server packet, bounded by the handshake's absolute deadline.
    pub(crate) fn relay_until(
        &mut self,
        packet: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        lock_until(&self.client, deadline)?.relay_packet_until(
            &self.connection_id,
            packet,
            deadline,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Input queued before a terminal failure is returned before the terminal datagram.
    #[test]
    fn terminal_data_waits_behind_queued_input() {
        let (out, _out_rx) = mpsc::sync_channel(1);
        let (input_tx, input) = mpsc::sync_channel(16);
        input_tx.send(Ok(b"A".to_vec())).expect("queued input");
        let mut stream = WebRtcStream {
            out,
            input: Arc::new(Mutex::new(input)),
            terminal: Arc::new(Mutex::new(VecDeque::from([b"B".to_vec()]))),
            pending: Arc::new(Mutex::new((Vec::new(), 0))),
            stop: Arc::new(AtomicBool::new(false)),
            failure: Arc::new(Mutex::new(Some("failed".to_owned()))),
            padding_sent: Arc::new(AtomicBool::new(false)),
            shaping: None,
            media: false,
            read_timeout: Arc::new(Mutex::new(Some(Duration::from_secs(1)))),
            write_timeout: Arc::new(Mutex::new(Some(Duration::from_secs(1)))),
        };
        let mut byte = [0u8; 1];
        assert_eq!(stream.read(&mut byte).expect("first"), 1);
        assert_eq!(&byte, b"A");
        assert_eq!(stream.read(&mut byte).expect("second"), 1);
        assert_eq!(&byte, b"B");
        assert!(stream.read(&mut byte).is_err());
        drop(input_tx);
    }

    #[test]
    fn a_framed_media_packet_fits_the_maximum() {
        let mut shaping = Shaping::new(TrafficShapingParameters::media_default(), [0u8; 32]);
        let payload = vec![0u8; MEDIA_MAX_RTP_PAYLOAD - 1];
        assert_eq!(
            shaping.frame_media(&payload, MEDIA_MAX_RTP_PAYLOAD).len(),
            MEDIA_MAX_RTP_PAYLOAD
        );
    }

    #[test]
    fn a_weighted_coin_keeps_the_inclusive_endpoints() {
        assert!(weighted(1.0, 0.99));
        assert!(!weighted(0.0, 0.0));
        assert!(weighted(0.5, 0.49));
        assert!(!weighted(0.5, 0.5));
    }

    #[test]
    fn an_offer_retry_delay_adds_only_its_jitter_share() {
        assert_eq!(
            retry_delay(Duration::from_millis(100), 0.5, 0.0),
            Duration::from_millis(100)
        );
        assert_eq!(
            retry_delay(Duration::from_millis(100), 0.5, 1.0),
            Duration::from_millis(150)
        );
        assert_eq!(retry_delay(Duration::ZERO, 0.5, 1.0), Duration::ZERO);
    }

    #[test]
    fn a_cidr_matches_only_its_own_family_and_prefix() {
        let cidr = Cidr::parse("192.0.2.0/24").expect("CIDR");
        assert!(cidr.contains("192.0.2.55".parse().expect("IP")));
        assert!(!cidr.contains("198.51.100.1".parse().expect("IP")));
        assert!(!cidr.contains("2001:db8::1".parse().expect("IP")));
        let cidr = Cidr::parse("2001:db8::/32").expect("CIDR");
        assert!(cidr.contains("2001:db8:1::1".parse().expect("IP")));
        assert!(!cidr.contains("2001:db9::1".parse().expect("IP")));
        assert!(Cidr::parse("192.0.2.0/33").is_none());
    }

    #[test]
    fn an_xor_mapped_address_is_unmasked() {
        let transaction = [7u8; 12];
        let port = 0x1f40u16 ^ 0x2112;
        let mut value = vec![0, 1, port.to_be_bytes()[0], port.to_be_bytes()[1]];
        let cookie = ferrox_core::stun::COOKIE.to_be_bytes();
        value.extend_from_slice(&[
            0xc0 ^ cookie[0],
            cookie[1],
            0x02 ^ cookie[2],
            0x01 ^ cookie[3],
        ]);
        let mut reply = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
        reply.extend_from_slice(&transaction);
        reply.extend_from_slice(&ferrox_core::stun::XOR_MAPPED_ADDRESS.to_be_bytes());
        reply.extend_from_slice(&8u16.to_be_bytes());
        reply.extend_from_slice(&value);
        assert_eq!(
            parse_stun(&reply, &transaction),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                8000
            ))
        );
    }

    #[test]
    fn a_signed_padding_header_round_trips() {
        for value in [-1i64, 0, 1, 63, 64, 300, i64::from(i32::MIN)] {
            let mut encoded = Vec::new();
            put_varint(&mut encoded, value);
            let mut at = 0;
            assert_eq!(take_varint(&encoded, &mut at), Some(value));
            assert_eq!(at, encoded.len());
        }
    }

    #[test]
    fn a_padding_header_marks_done_and_hides_decoy_messages() {
        let mut done = false;
        let mut header = Vec::new();
        put_varint(&mut header, -1);
        header.extend_from_slice(b"hello");
        assert_eq!(unframe(header, &mut done), Ok(Some(b"hello".to_vec())));
        assert!(done);

        let mut done = false;
        let mut decoy = Vec::new();
        put_varint(&mut decoy, 3);
        decoy.extend_from_slice(b"xxx");
        assert_eq!(unframe(decoy, &mut done), Ok(None));
        assert!(!done);
    }

    #[test]
    fn an_unframed_payload_keeps_the_message_allocation() {
        let mut done = false;
        let mut data = Vec::new();
        put_varint(&mut data, 2);
        data.extend_from_slice(b"xxpayload");
        let base = data.as_ptr();
        let capacity = data.capacity();
        let (payload, counts) = ferrox_core::alloc_count::measure(|| unframe(data, &mut done));
        let payload = payload.expect("payload").expect("a kept message");
        assert_eq!(payload.as_slice(), b"payload");
        assert_eq!(counts.allocs, 0, "the header is skipped in place");
        assert_eq!(payload.as_ptr(), base, "the message buffer does not move");
        assert_eq!(payload.capacity(), capacity, "the capacity does not grow");
    }

    #[test]
    fn a_loopback_peer_opens_the_data_channel() {
        let (mut client, offer) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            &crate::psiphon_dns::Config::from_servers(&[]),
            false,
            None,
        )
        .expect("offer");
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("remote socket");
        let local = socket.local_addr().expect("remote local");
        let mut remote = Rtc::new(Instant::now());
        let _ = remote.add_local_candidate(Candidate::host(local, "udp").expect("candidate"));
        let offer = str0m::change::SdpOffer::from_sdp_string(&offer).expect("offer sdp");
        let answer = remote.sdp_api().accept_offer(offer).expect("answer");
        client
            .answer(&answer.to_sdp_string())
            .expect("accept answer");
        let remote = std::thread::spawn(move || {
            let mut remote = remote;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut channel = None;
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("timeout");
            while Instant::now() < deadline {
                let mut events = Vec::new();
                pump(&mut remote, &socket, &mut events);
                for event in events {
                    match event {
                        Event::ChannelOpen(id, _) => channel = Some(id),
                        Event::ChannelData(data) => {
                            let id = channel.expect("open");
                            let accepted = remote
                                .channel(id)
                                .expect("channel")
                                .write(true, &data.data)
                                .expect("echo");
                            if accepted {
                                pump(&mut remote, &socket, &mut Vec::new());
                                return;
                            }
                        }
                        _ => {}
                    }
                }
                let mut buffer = [0u8; 2048];
                if let Ok((length, source)) = socket.recv_from(&mut buffer) {
                    let destination = socket.local_addr().expect("local");
                    if let Ok(receive) =
                        Receive::new(Protocol::Udp, source, destination, &buffer[..length])
                    {
                        remote
                            .handle_input(Input::Receive(Instant::now(), receive))
                            .expect("input");
                    }
                }
            }
            panic!("remote never received data");
        });
        client
            .await_channel(Duration::from_secs(5))
            .expect("channel");
        client.send(b"hello").expect("send");
        assert_eq!(
            client.receive(Duration::from_secs(5)),
            Ok(Some(b"hello".to_vec()))
        );
        remote.join().expect("remote");
    }

    fn pump(rtc: &mut Rtc, socket: &UdpSocket, events: &mut Vec<Event>) {
        loop {
            match rtc.poll_output().expect("output") {
                Output::Timeout(_) => return,
                Output::Transmit(transmit) => {
                    socket
                        .send_to(&transmit.contents, transmit.destination)
                        .expect("transmit");
                }
                Output::Event(event) => events.push(event),
            }
        }
    }

    #[test]
    fn traffic_shaping_pads_then_ends_and_passes_payloads_through() {
        let parameters = TrafficShapingParameters {
            min_padded_messages: 1,
            max_padded_messages: 1,
            min_padding_size: 0,
            max_padding_size: 0,
            min_decoy_messages: 0,
            max_decoy_messages: 0,
            min_decoy_size: 1,
            max_decoy_size: 1,
            decoy_message_probability: 0.0,
        };
        let mut shaping = Shaping::new(parameters, [7u8; 32]);
        let mut done = false;
        let first = shaping.frame(b"hello", MAX_DATAGRAM);
        assert_eq!(
            unframe(first, &mut done).expect("first"),
            Some(b"hello".to_vec())
        );
        assert!(!done);
        let second = shaping.frame(b"world", MAX_DATAGRAM);
        assert_eq!(
            unframe(second, &mut done).expect("second"),
            Some(b"world".to_vec())
        );
        assert!(done, "the negative header ends framing");
        let third = shaping.frame(b"raw", MAX_DATAGRAM);
        assert_eq!(third, b"raw");
        assert_eq!(
            unframe(third, &mut done).expect("third"),
            Some(b"raw".to_vec())
        );
    }

    #[test]
    fn a_decoy_is_generated_only_from_the_read_path_budget() {
        let parameters = TrafficShapingParameters {
            min_padded_messages: 0,
            max_padded_messages: 0,
            min_padding_size: 0,
            max_padding_size: 0,
            min_decoy_messages: 1,
            max_decoy_messages: 1,
            min_decoy_size: 2,
            max_decoy_size: 2,
            decoy_message_probability: 1.0,
        };
        let mut shaping = Shaping::new(parameters, [7u8; 32]);
        let mut done = false;
        let carried = shaping.frame(b"hello", MAX_DATAGRAM);
        assert_eq!(
            unframe(carried, &mut done).expect("carried"),
            Some(b"hello".to_vec())
        );
        let decoy = shaping.decoy(MAX_DATAGRAM).expect("a decoy");
        assert_eq!(unframe(decoy, &mut done).expect("decoy"), None);
        let end = shaping.frame(b"bye", MAX_DATAGRAM);
        assert_eq!(unframe(end, &mut done).expect("end"), Some(b"bye".to_vec()));
        assert!(done);
    }

    #[test]
    fn a_disabled_stun_offer_omits_a_server_reflexive_candidate() {
        let (_, sdp) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &["192.0.2.1:3478".to_owned()],
            true,
            false,
            false,
            false,
            Duration::from_secs(1),
            &crate::psiphon_dns::Config::from_servers(&[]),
            false,
            None,
        )
        .expect("offer");
        assert!(!sdp.contains("srflx"), "STUN is disabled: {sdp}");
    }

    #[test]
    fn a_stun_choice_draws_only_from_the_configured_list() {
        assert_eq!(choose_stun(&[]), None);
        let servers = ["first.example".to_owned(), "second.example".to_owned()];
        let chosen = choose_stun(&servers).expect("a server");
        assert!(servers.iter().any(|server| server == chosen));
    }

    #[test]
    fn a_private_offer_names_a_data_channel() {
        let (webrtc, sdp) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            &crate::psiphon_dns::Config::from_servers(&[]),
            false,
            None,
        )
        .expect("offer");
        assert!(sdp.contains("m=application"));
        assert!(!offers_media(&sdp));
        assert!(webrtc.socket.local_addr().is_ok());
    }

    #[test]
    fn a_media_offer_names_a_video_track() {
        let (_, sdp) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            &crate::psiphon_dns::Config::from_servers(&[]),
            false,
            Some([7u8; 32]),
        )
        .expect("offer");
        assert!(offers_media(&sdp));
        assert!(!sdp.contains("m=application"));
    }

    #[test]
    fn the_reference_bogon_table_is_covered() {
        for bogon in [
            [0, 1, 2, 3],
            [10, 0, 0, 1],
            [100, 64, 0, 1],
            [127, 0, 0, 1],
            [169, 254, 0, 1],
            [172, 16, 0, 1],
            [192, 0, 0, 1],
            [192, 0, 2, 1],
            [192, 88, 99, 1],
            [198, 18, 0, 1],
            [198, 51, 100, 1],
            [203, 0, 113, 1],
            [224, 0, 0, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            assert!(is_bogon(Ipv4Addr::from(bogon).into()), "{bogon:?}");
        }
        for bogon in [
            "::",
            "::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_bogon(bogon.parse().expect("address")), "{bogon}");
        }
        let mapped = Ipv4Addr::from([192, 0, 2, 1]).to_ipv6_mapped();
        assert!(is_bogon(mapped.into()));
        for public in [[1, 1, 1, 1], [8, 8, 8, 8], [192, 18, 0, 1]] {
            assert!(!is_bogon(Ipv4Addr::from(public).into()), "{public:?}");
        }
        let public: IpAddr = "2606:4700:4700::1111".parse().expect("address");
        assert!(!is_bogon(public), "{public}");
    }
}

#[cfg(test)]
use super::protocol::write_long;
#[cfg(test)]
use super::protocol::Packet;
use super::protocol::{
    encode_packet, read_long, read_varint, read_varint_with_length, varint_size, write_string,
    write_varint, MAX_PACKET_BODY_LENGTH, MAX_PACKET_DATA_LENGTH, MAX_STRING_LENGTH,
};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const CHANNEL: &str = "xmc:data";
pub const CLIENTBOUND_CUSTOM_PAYLOAD: i32 = 0x01;
pub const SERVERBOUND_CUSTOM_PAYLOAD: i32 = 0x02;
pub const KEEPALIVE_PACKET: i32 = 0x04;
pub const MAX_PACKET_DATA: usize = 24 * 1024;
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(15);

const KEEPALIVE_POLL: Duration = Duration::from_millis(100);
const KEEPALIVE_POLLS: usize = 150;

fn retryable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn queue_keepalive(frame: &mut WriteBuffer, id: i64) -> io::Result<()> {
    frame.bytes = encode_packet(KEEPALIVE_PACKET, &id.to_be_bytes())?;
    frame.pos = 0;
    Ok(())
}

pub struct PacketStream<R, W> {
    reader: Mutex<ReadState<R>>,
    writer: Arc<Mutex<W>>,
    write_buffer: Arc<Mutex<WriteBuffer>>,
    is_client: bool,
    stop: Arc<AtomicBool>,
    keepalive: Option<JoinHandle<()>>,
    /// A keep-alive answer whose frame drain was refused, kept so the next read retries it.
    pending_keepalive: Mutex<Option<PendingKeepalive>>,
    has_pending_keepalive: AtomicBool,
}

#[derive(Clone, Copy)]
struct PendingKeepalive {
    id: i64,
    queued: bool,
}

#[derive(Default)]
struct WriteBuffer {
    bytes: Vec<u8>,
    pos: usize,
}

struct ReadState<R> {
    reader: R,
    buffer: Vec<u8>,
    buffer_at: usize,
    pending_start: usize,
    pending_end: usize,
    pending_total: usize,
    chunk: [u8; 8192],
}

enum Event {
    Payload(usize),
    KeepAlive(i64),
}

enum NextError {
    Frame(io::Error),
    Payload(io::Error),
}

impl<R: Read> ReadState<R> {
    fn next_event(&mut self, output: &mut [u8], remote_id: i32) -> Result<Event, NextError> {
        loop {
            let available = &self.buffer[self.buffer_at..];
            let mut body = available;
            let (length, prefix) = match read_varint_with_length(&mut body) {
                Ok(field) => field,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.refill().map_err(NextError::Frame)?;
                    continue;
                }
                Err(error) => return Err(NextError::Frame(error)),
            };
            if length < 1 || length as usize > MAX_PACKET_BODY_LENGTH {
                return Err(NextError::Frame(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("read packet: bad length: {length}"),
                )));
            }
            let total = prefix + length as usize;
            if available.len() < total {
                self.refill().map_err(NextError::Frame)?;
                continue;
            }
            let mut body = &available[prefix..total];
            let id = read_varint(&mut body).map_err(NextError::Frame)?;
            if body.len() > MAX_PACKET_DATA_LENGTH {
                return Err(NextError::Frame(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("read packet: bad length: {}", body.len()),
                )));
            }
            if id == remote_id {
                let payload = match parse_custom_payload_data(&mut body) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => {
                        self.advance(total);
                        continue;
                    }
                    Err(error) => return Err(NextError::Payload(error)),
                };
                if payload.is_empty() {
                    self.advance(total);
                    continue;
                }
                let taken = output.len().min(payload.len());
                output[..taken].copy_from_slice(&payload[..taken]);
                if taken < payload.len() {
                    let start = payload.as_ptr() as usize - self.buffer.as_ptr() as usize;
                    self.pending_start = start + taken;
                    self.pending_end = start + payload.len();
                    self.pending_total = total;
                } else {
                    self.advance(total);
                }
                return Ok(Event::Payload(taken));
            }
            if id == KEEPALIVE_PACKET {
                let id = read_long(&mut body).map_err(|error| {
                    NextError::Payload(io::Error::other(format!(
                        "read minecraft keep-alive: {error}"
                    )))
                })?;
                self.advance(total);
                return Ok(Event::KeepAlive(id));
            }
            self.advance(total);
        }
    }

    fn advance(&mut self, length: usize) {
        self.buffer_at += length;
        if self.buffer_at == self.buffer.len() {
            self.buffer.clear();
            self.buffer_at = 0;
        } else if self.buffer_at >= 4096 || self.buffer_at * 2 >= self.buffer.len() {
            self.buffer.copy_within(self.buffer_at.., 0);
            self.buffer.truncate(self.buffer.len() - self.buffer_at);
            self.buffer_at = 0;
        }
    }

    fn refill(&mut self) -> io::Result<()> {
        loop {
            match self.reader.read(&mut self.chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "minecraft packet stream closed",
                    ))
                }
                Ok(read) => {
                    self.buffer.extend_from_slice(&self.chunk[..read]);
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl<R, W> PacketStream<R, W>
where
    W: Write + Send + 'static,
{
    pub fn new(reader: R, writer: W, is_client: bool) -> Self {
        let writer = Arc::new(Mutex::new(writer));
        let write_buffer = Arc::new(Mutex::new(WriteBuffer::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let keepalive = if is_client {
            None
        } else {
            Some(spawn_keepalive(
                Arc::clone(&writer),
                Arc::clone(&write_buffer),
                Arc::clone(&stop),
            ))
        };
        Self {
            reader: Mutex::new(ReadState {
                reader,
                buffer: Vec::new(),
                buffer_at: 0,
                pending_start: 0,
                pending_end: 0,
                pending_total: 0,
                chunk: [0; 8192],
            }),
            writer,
            write_buffer,
            is_client,
            stop,
            keepalive,
            pending_keepalive: Mutex::new(None),
            has_pending_keepalive: AtomicBool::new(false),
        }
    }
}

impl<R, W> PacketStream<R, W> {
    /// Stop the keepalive thread without waiting on a writer lock it may never get back: the stop
    /// flag ends the loop, and the handle is detached so a stalled socket cannot hold the close.
    fn stop_keepalive(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.keepalive.take();
    }
}

impl<R, W: Write> PacketStream<R, W> {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn shutdown(&mut self) {
        self.stop_keepalive();
    }

    fn local_custom_payload_id(&self) -> i32 {
        if self.is_client {
            SERVERBOUND_CUSTOM_PAYLOAD
        } else {
            CLIENTBOUND_CUSTOM_PAYLOAD
        }
    }

    fn remote_custom_payload_id(&self) -> i32 {
        if self.is_client {
            CLIENTBOUND_CUSTOM_PAYLOAD
        } else {
            SERVERBOUND_CUSTOM_PAYLOAD
        }
    }

    fn flush_pending_keepalive(&self) -> io::Result<()> {
        if !self.has_pending_keepalive.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut slot = self
            .pending_keepalive
            .lock()
            .map_err(|_| io::Error::other("packet stream keepalive poisoned"))?;
        let Some(pending) = slot.as_mut() else {
            self.has_pending_keepalive.store(false, Ordering::Release);
            return Ok(());
        };
        let result = self.write_keepalive(pending);
        if !matches!(&result, Err(error) if retryable(error.kind())) {
            *slot = None;
            self.has_pending_keepalive.store(false, Ordering::Release);
        }
        result
    }

    fn write_keepalive(&self, pending: &mut PendingKeepalive) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        let mut frame = self
            .write_buffer
            .lock()
            .map_err(|_| io::Error::other("packet stream write buffer poisoned"))?;
        flush_frame(&mut *writer, &mut frame)
            .map_err(|error| io::Error::new(error.kind(), format!("flush frame: {error}")))?;
        if !pending.queued {
            queue_keepalive(&mut frame, pending.id).map_err(|error| {
                io::Error::new(error.kind(), format!("write minecraft keep-alive: {error}"))
            })?;
            pending.queued = true;
        }
        flush_frame(&mut *writer, &mut frame).map_err(|error| {
            io::Error::new(error.kind(), format!("write minecraft keep-alive: {error}"))
        })?;
        writer.flush().map_err(|error| {
            io::Error::new(error.kind(), format!("flush minecraft keep-alive: {error}"))
        })
    }

    #[cfg(test)]
    pub(crate) fn send_keepalive(&self, id: i64) -> io::Result<()> {
        self.write_keepalive(&mut PendingKeepalive { id, queued: false })
    }
}

impl<R: Read, W: Write> Read for &PacketStream<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.flush_pending_keepalive()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("packet stream reader poisoned"))?;
        self.flush_pending_keepalive()?;
        if reader.pending_end > reader.pending_start {
            let taken = output.len().min(reader.pending_end - reader.pending_start);
            output[..taken].copy_from_slice(
                &reader.buffer[reader.pending_start..reader.pending_start + taken],
            );
            reader.pending_start += taken;
            if reader.pending_start == reader.pending_end {
                reader.pending_start = 0;
                reader.pending_end = 0;
                let total = std::mem::take(&mut reader.pending_total);
                reader.advance(total);
            }
            return Ok(taken);
        }

        loop {
            let event = reader
                .next_event(output, self.remote_custom_payload_id())
                .map_err(|error| match error {
                    NextError::Frame(error) => io::Error::new(
                        error.kind(),
                        format!("read minecraft packet stream: {error}"),
                    ),
                    NextError::Payload(error) => error,
                })?;
            match event {
                Event::Payload(taken) => return Ok(taken),
                Event::KeepAlive(id) => {
                    if self.is_client {
                        *self
                            .pending_keepalive
                            .lock()
                            .map_err(|_| io::Error::other("packet stream keepalive poisoned"))? =
                            Some(PendingKeepalive { id, queued: false });
                        self.has_pending_keepalive.store(true, Ordering::Release);
                        self.flush_pending_keepalive()?;
                    }
                }
            }
        }
    }
}

impl<R: Read, W: Write> Read for PacketStream<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        (&*self).read(output)
    }
}

impl<R, W: Write> Write for &PacketStream<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
            let mut frame = self
                .write_buffer
                .lock()
                .map_err(|_| io::Error::other("packet stream write buffer poisoned"))?;
            return flush_frame(&mut *writer, &mut frame).map(|()| 0);
        }

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        let mut frame = self
            .write_buffer
            .lock()
            .map_err(|_| io::Error::other("packet stream write buffer poisoned"))?;
        if frame.pos < frame.bytes.len() {
            flush_frame(&mut *writer, &mut frame).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("write minecraft custom payload: {error}"),
                )
            })?;
        }
        let mut written = 0;
        while written < input.len() {
            let end = (written + MAX_PACKET_DATA).min(input.len());
            let id = self.local_custom_payload_id();
            let body = varint_size(id) + varint_size(8) + CHANNEL.len() + end - written;
            let body = i32::try_from(body)
                .map_err(|_| io::Error::other("packet length exceeds a varint"))?;
            frame.bytes.clear();
            frame.pos = 0;
            write_varint(&mut frame.bytes, body)?;
            write_varint(&mut frame.bytes, id)?;
            write_string(&mut frame.bytes, CHANNEL)?;
            frame.bytes.extend_from_slice(&input[written..end]);
            if let Err(error) = flush_frame(&mut *writer, &mut frame) {
                if retryable(error.kind()) || frame.pos > 0 {
                    return Ok(end);
                }
                frame.bytes.clear();
                return if written > 0 { Ok(written) } else { Err(error) };
            }
            written = end;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        let mut frame = self
            .write_buffer
            .lock()
            .map_err(|_| io::Error::other("packet stream write buffer poisoned"))?;
        flush_frame(&mut *writer, &mut frame)?;
        writer.flush()
    }
}

impl<R, W: Write> Write for PacketStream<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        (&*self).write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl<R, W> Drop for PacketStream<R, W> {
    fn drop(&mut self) {
        self.stop_keepalive();
    }
}

impl<R, W> std::fmt::Debug for PacketStream<R, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PacketStream")
            .field("is_client", &self.is_client)
            .field(
                "pending",
                &self
                    .reader
                    .try_lock()
                    .map(|reader| reader.pending_end.saturating_sub(reader.pending_start))
                    .ok(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
fn parse_custom_payload(packet: &Packet) -> io::Result<Option<&[u8]>> {
    parse_custom_payload_data(&mut packet.data.as_slice())
}

fn parse_custom_payload_data<'a>(data: &mut &'a [u8]) -> io::Result<Option<&'a [u8]>> {
    let channel = read_channel(data).map_err(|error| {
        io::Error::other(format!("read minecraft custom payload channel: {error}"))
    })?;
    if channel != CHANNEL {
        return Ok(None);
    }
    Ok(Some(*data))
}

fn read_channel<'a>(data: &mut &'a [u8]) -> io::Result<&'a str> {
    let (length, _) = read_varint_with_length(data)?;
    if !(0..=MAX_STRING_LENGTH).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read string: bad length: {length}"),
        ));
    }
    let length = length as usize;
    if length > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ));
    }
    let (channel, rest) = data.split_at(length);
    *data = rest;
    std::str::from_utf8(channel)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "read string: invalid utf-8"))
}

fn flush_frame<W: Write>(writer: &mut W, frame: &mut WriteBuffer) -> io::Result<()> {
    while frame.pos < frame.bytes.len() {
        match writer.write(&frame.bytes[frame.pos..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(taken) => frame.pos += taken,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn spawn_keepalive<W: Write + Send + 'static>(
    writer: Arc<Mutex<W>>,
    frame: Arc<Mutex<WriteBuffer>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let id = AtomicI64::new(0);
        loop {
            for _ in 0..KEEPALIVE_POLLS {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(KEEPALIVE_POLL);
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(mut writer) = writer.lock() else {
                return;
            };
            let Ok(mut frame) = frame.lock() else {
                return;
            };
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if let Err(error) = flush_frame(&mut *writer, &mut frame) {
                if retryable(error.kind()) {
                    continue;
                }
                return;
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let value = id.fetch_add(1, Ordering::Relaxed) + 1;
            if queue_keepalive(&mut frame, value).is_err() {
                return;
            }
            if let Err(error) = flush_frame(&mut *writer, &mut frame) {
                if retryable(error.kind()) {
                    continue;
                }
                return;
            }
            if let Err(error) = writer.flush() {
                if retryable(error.kind()) {
                    continue;
                }
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::protocol::{encode_packet, read_packet, read_varint_with_length};
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct Pipe {
        bytes: Arc<Mutex<VecDeque<u8>>>,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                bytes: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn push(&self, data: &[u8]) {
            self.bytes.lock().expect("pipe").extend(data);
        }

        fn collected(&self) -> Vec<u8> {
            self.bytes.lock().expect("pipe").drain(..).collect()
        }
    }

    impl Read for Pipe {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().expect("pipe");
            let taken = output.len().min(bytes.len());
            for (slot, byte) in output.iter_mut().zip(bytes.drain(..taken)) {
                *slot = byte;
            }
            Ok(taken)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.push(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn frame(id: i32, data: &[u8]) -> Vec<u8> {
        encode_packet(id, data).expect("frame")
    }

    struct FlushTimesOut;

    impl Write for FlushTimesOut {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn a_blocked_keepalive_keeps_its_retryable_kind() {
        let stream = PacketStream::new(std::io::Cursor::new(Vec::<u8>::new()), FlushTimesOut, true);
        assert_eq!(
            stream
                .send_keepalive(7)
                .expect_err("flush timed out")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    struct FailsBeforeTheSecondFrame {
        bytes: Arc<Mutex<Vec<u8>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl Write for FailsBeforeTheSecondFrame {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let mut calls = self.calls.lock().expect("calls");
            *calls += 1;
            if *calls == 2 {
                return Err(io::ErrorKind::Other.into());
            }
            self.bytes.lock().expect("bytes").extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct PartialThenStall {
        bytes: Vec<u8>,
        calls: usize,
    }

    impl Write for PartialThenStall {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            match self.calls {
                1 => {
                    let take = input.len().min(3);
                    self.bytes.extend_from_slice(&input[..take]);
                    Ok(take)
                }
                2 => Err(io::ErrorKind::WouldBlock.into()),
                _ => {
                    self.bytes.extend_from_slice(input);
                    Ok(input.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushTimesOutOnce {
        bytes: Vec<u8>,
        failed: bool,
    }

    impl Write for FlushTimesOutOnce {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.failed {
                return Ok(());
            }
            self.failed = true;
            Err(io::ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn a_retried_keepalive_resumes_instead_of_replying_twice() {
        let expected = frame(KEEPALIVE_PACKET, &7i64.to_be_bytes());

        let partial = PacketStream::new(
            std::io::Cursor::new(Vec::<u8>::new()),
            PartialThenStall {
                bytes: Vec::new(),
                calls: 0,
            },
            true,
        );
        *partial.pending_keepalive.lock().expect("pending") = Some(PendingKeepalive {
            id: 7,
            queued: false,
        });
        partial.has_pending_keepalive.store(true, Ordering::Release);
        assert_eq!(
            partial
                .flush_pending_keepalive()
                .expect_err("the frame stalls")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        partial.flush_pending_keepalive().expect("resumes");
        let writer = partial.writer.lock().expect("writer");
        assert_eq!(*writer.bytes, expected);

        let flush = PacketStream::new(
            std::io::Cursor::new(Vec::<u8>::new()),
            FlushTimesOutOnce {
                bytes: Vec::new(),
                failed: false,
            },
            true,
        );
        *flush.pending_keepalive.lock().expect("pending") = Some(PendingKeepalive {
            id: 7,
            queued: false,
        });
        flush.has_pending_keepalive.store(true, Ordering::Release);
        assert_eq!(
            flush
                .flush_pending_keepalive()
                .expect_err("the flush stalls")
                .kind(),
            io::ErrorKind::TimedOut
        );
        flush.flush_pending_keepalive().expect("flushes");
        let writer = flush.writer.lock().expect("writer");
        assert_eq!(writer.bytes, expected);
    }

    #[test]
    fn an_unaccepted_frame_is_not_replayed_with_the_next_write() {
        let sink = FailsBeforeTheSecondFrame {
            bytes: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(0)),
        };
        let observed = Arc::clone(&sink.bytes);
        let stream = PacketStream::new(std::io::Cursor::new(Vec::<u8>::new()), sink, true);
        let payload: Vec<u8> = (0..MAX_PACKET_DATA + 9).map(|index| index as u8).collect();
        let mut write = &stream;
        assert_eq!(
            write.write(&payload).expect("the first frame is accepted"),
            MAX_PACKET_DATA
        );
        assert_eq!(write.write(&payload[MAX_PACKET_DATA..]).expect("retry"), 9);

        let bytes = observed.lock().expect("bytes");
        let mut wire = bytes.as_slice();
        let mut recovered = Vec::new();
        while !wire.is_empty() {
            let (length, _) = read_varint_with_length(&mut wire).expect("length");
            let body = &wire[..length as usize];
            wire = &wire[length as usize..];
            let mut body_reader = body;
            let _ = read_varint_with_length(&mut body_reader).expect("id");
            let packet = Packet {
                id: body[0] as i32,
                data: body[1..].to_vec(),
            };
            let payload = parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel");
            recovered.extend_from_slice(payload);
        }
        assert_eq!(recovered, payload, "the nine-byte tail is sent once");
    }

    #[test]
    fn writes_split_at_the_payload_limit_and_round_trip_both_ways() {
        let client_out = Pipe::new();
        let server_out = Pipe::new();
        let mut client = PacketStream::new(server_out.clone(), client_out.clone(), true);
        let mut server = PacketStream::new(client_out.clone(), server_out.clone(), false);

        let client_payload: Vec<u8> = (0..60_000).map(|index| (index % 251) as u8).collect();
        let server_payload: Vec<u8> = (0..50_000).map(|index| (index % 239) as u8).collect();

        client.write_all(&client_payload).expect("client writes");
        let mut received = vec![0; client_payload.len()];
        server.read_exact(&mut received).expect("server reads");
        assert_eq!(received, client_payload);

        server.write_all(&server_payload).expect("server writes");
        let mut received = vec![0; server_payload.len()];
        client.read_exact(&mut received).expect("client reads");
        assert_eq!(received, server_payload);

        client.shutdown();
        server.shutdown();
    }

    #[test]
    fn a_write_over_the_limit_becomes_several_frames() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        let payload = vec![7u8; MAX_PACKET_DATA * 2 + 1];
        assert_eq!(stream.write(&payload).expect("writes"), payload.len());

        let wire = out.collected();
        let mut data = wire.as_slice();
        let mut frames = 0;
        let mut recovered = Vec::new();
        while !data.is_empty() {
            let (length, prefix) = read_varint_with_length(&mut data).expect("length");
            let body = &data[..length as usize];
            data = &data[length as usize..];
            let mut body_reader = body;
            let _ = read_varint_with_length(&mut body_reader).expect("id");
            let _ = prefix;
            let packet = Packet {
                id: body[0] as i32,
                data: body[1..].to_vec(),
            };
            let payload = parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel");
            recovered.extend_from_slice(payload);
            frames += 1;
        }
        assert_eq!(frames, 3);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn a_blocked_frame_resumes_after_the_bytes_the_sink_took() {
        #[derive(Clone)]
        struct Stalling {
            bytes: Arc<Mutex<Vec<u8>>>,
            calls: Arc<Mutex<usize>>,
        }

        impl Write for Stalling {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let mut calls = self.calls.lock().expect("calls");
                *calls += 1;
                let call = *calls;
                drop(calls);
                match call {
                    1 => {
                        let take = buf.len().min(7);
                        self.bytes
                            .lock()
                            .expect("bytes")
                            .extend_from_slice(&buf[..take]);
                        Ok(take)
                    }
                    2 => Err(io::ErrorKind::WouldBlock.into()),
                    _ => {
                        self.bytes.lock().expect("bytes").extend_from_slice(buf);
                        Ok(buf.len())
                    }
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let sink = Stalling {
            bytes: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(0)),
        };
        let observed = Arc::clone(&sink.bytes);
        let stream = PacketStream::new(std::io::Cursor::new(Vec::<u8>::new()), sink, true);
        let payload = vec![0x44u8; MAX_PACKET_DATA + 9];
        let mut write = &stream;
        let mut at = 0usize;
        while at < payload.len() {
            match write.write(&payload[at..]) {
                Ok(0) => panic!("the writer made no progress"),
                Ok(taken) => at += taken,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("write: {error}"),
            }
        }

        let bytes = observed.lock().expect("bytes");
        let mut data = bytes.as_slice();
        let mut recovered = Vec::new();
        while !data.is_empty() {
            let (length, _) = read_varint_with_length(&mut data).expect("length");
            let body = &data[..length as usize];
            data = &data[length as usize..];
            let mut body_reader = body;
            let _ = read_varint_with_length(&mut body_reader).expect("id");
            let packet = Packet {
                id: body[0] as i32,
                data: body[1..].to_vec(),
            };
            let chunk = parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel");
            recovered.extend_from_slice(chunk);
        }
        assert_eq!(recovered, payload, "no frame is replayed or lost");
    }

    #[test]
    fn the_frame_buffer_holds_its_capacity() {
        let stream = PacketStream::new(
            std::io::Cursor::new(Vec::<u8>::new()),
            std::io::sink(),
            true,
        );
        let mut write = &stream;
        let input = vec![0x33u8; MAX_PACKET_DATA];
        write.write_all(&input).expect("writes");
        let capacity = stream.write_buffer.lock().expect("buffer").bytes.capacity();
        for _ in 0..4 {
            write.write_all(&input).expect("writes");
            assert_eq!(
                stream.write_buffer.lock().expect("buffer").bytes.capacity(),
                capacity,
                "the frame buffer does not grow again"
            );
        }
    }

    #[test]
    fn a_custom_payload_is_a_slice_of_its_frame() {
        let mut data = Vec::new();
        write_string(&mut data, CHANNEL).expect("channel");
        data.extend_from_slice(b"hello");
        let packet = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data,
        };
        let (payload, counts) = crate::alloc_count::measure(|| {
            parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel")
        });
        assert_eq!(payload, b"hello");
        assert_eq!(
            payload.as_ptr(),
            packet.data[packet.data.len() - payload.len()..].as_ptr(),
            "the payload is the frame's own bytes"
        );
        assert_eq!(counts.allocs, 0, "reading the channel takes no heap");
    }

    #[test]
    fn a_payload_tail_is_the_frames_own_bytes() {
        let out = Pipe::new();
        let payload: Vec<u8> = (0..MAX_PACKET_DATA)
            .map(|index| (index % 241) as u8)
            .collect();
        let mut body = Vec::new();
        write_string(&mut body, CHANNEL).expect("channel");
        body.extend_from_slice(&payload);
        let wire = frame(CLIENTBOUND_CUSTOM_PAYLOAD, &body);

        let mut client = PacketStream::new(Pipe::new(), out, true);
        client
            .reader
            .lock()
            .expect("reader")
            .buffer
            .extend_from_slice(&wire);
        let mut got = vec![0; payload.len()];
        let mut first = [0u8; 4096];
        let (read, counts) = crate::alloc_count::measure(|| client.read(&mut first));
        assert_eq!(read.expect("the first read"), first.len());
        assert_eq!(counts.allocs, 0, "the tail is not staged in a fresh buffer");
        got[..first.len()].copy_from_slice(&first);
        let base = client.reader.lock().expect("reader").buffer.as_ptr();
        let capacity = client.reader.lock().expect("reader").buffer.capacity();
        {
            let state = client.reader.lock().expect("reader");
            assert!(
                state.pending_start < state.pending_end && state.pending_end <= state.buffer.len(),
                "the tail is a span of the frame buffer"
            );
        }
        let mut at = first.len();
        while at < got.len() {
            let take = (got.len() - at).min(4096);
            client.read_exact(&mut got[at..at + take]).expect("reads");
            at += take;
            let state = client.reader.lock().expect("reader");
            assert_eq!(
                state.buffer.as_ptr(),
                base,
                "the frame buffer does not move"
            );
            assert_eq!(
                state.buffer.capacity(),
                capacity,
                "the tail pays no reallocation"
            );
        }
        assert_eq!(got, payload);
        assert_eq!(
            client.reader.lock().expect("reader").pending_end,
            0,
            "the tail drains before another event is parsed"
        );
        client.shutdown();
    }

    #[test]
    fn a_read_does_not_wait_for_an_empty_keepalive_slot() {
        let mut body = Vec::new();
        write_string(&mut body, CHANNEL).expect("channel");
        body.extend_from_slice(b"hello");
        let wire = frame(CLIENTBOUND_CUSTOM_PAYLOAD, &body);
        let stream = PacketStream::new(std::io::Cursor::new(wire), Pipe::new(), true);
        let reader_stream = &stream;

        let result = std::thread::scope(|scope| {
            let pending = stream.pending_keepalive.lock().expect("pending");
            let (sender, receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                let mut output = [0u8; 5];
                let mut reader = reader_stream;
                let _ = sender.send(reader.read(&mut output).map(|read| (read, output)));
            });
            let result = receiver.recv_timeout(Duration::from_secs(1));
            drop(pending);
            result
        });

        let (read, output) = result
            .expect("a read waited on an empty keepalive slot")
            .expect("the read succeeds");
        assert_eq!(read, 5);
        assert_eq!(&output[..read], b"hello");
    }

    #[test]
    fn a_custom_payload_channel_keeps_the_string_rules() {
        let invalid_utf8 = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![1, 0xff],
        };
        let error = parse_custom_payload(&invalid_utf8).expect_err("invalid utf-8");
        assert!(error.to_string().contains("read string: invalid utf-8"));

        let too_long = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![0x81, 0x20],
        };
        let error = parse_custom_payload(&too_long).expect_err("length over the string cap");
        assert!(error.to_string().contains("read string: bad length: 4097"));

        let truncated = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![8, b'x'],
        };
        let error = parse_custom_payload(&truncated).expect_err("short channel");
        assert!(error.to_string().contains("failed to fill whole buffer"));

        let overlong = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![0x88, 0x00],
        };
        assert!(
            parse_custom_payload(&overlong).is_err(),
            "a non-canonical length is still refused"
        );
    }

    #[test]
    fn a_client_echoes_keepalives_and_skips_other_payloads() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 42).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut foreign = Vec::new();
        write_string(&mut foreign, "minecraft:brand").expect("channel");
        foreign.extend_from_slice(b"ignored");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &foreign));

        let mut empty = Vec::new();
        write_string(&mut empty, CHANNEL).expect("channel");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &empty));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"hello");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &payload));

        let mut client = PacketStream::new(input, out.clone(), true);
        let mut received = [0; 5];
        client.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"hello");

        let echoed = out.collected();
        let mut data = echoed.as_slice();
        let (length, _) = read_varint_with_length(&mut data).expect("length");
        let body = &data[..length as usize];
        let mut body_reader = body;
        assert_eq!(
            read_varint_with_length(&mut body_reader).expect("id").0,
            KEEPALIVE_PACKET
        );
        assert_eq!(read_long(&mut body_reader).expect("id"), 42);
        assert_eq!(data.len(), length as usize, "only the keepalive is echoed");

        client.shutdown();
    }

    #[test]
    fn a_server_can_send_a_keepalive() {
        let out = Pipe::new();
        let mut server = PacketStream::new(Pipe::new(), out.clone(), false);
        server.send_keepalive(9).expect("keepalive");

        let wire = out.collected();
        let mut data = wire.as_slice();
        let packet = read_packet(&mut data).expect("packet");
        assert_eq!(packet.id, KEEPALIVE_PACKET);
        let mut body = packet.data.as_slice();
        assert_eq!(read_long(&mut body).expect("id"), 9);
        assert_eq!(data, b"");

        server.shutdown();
    }

    #[test]
    fn a_server_ignores_inbound_keepalives() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 7).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"data");
        input.push(&frame(SERVERBOUND_CUSTOM_PAYLOAD, &payload));

        let mut server = PacketStream::new(input, out.clone(), false);
        let mut received = [0; 4];
        server.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"data");
        assert!(out.collected().is_empty(), "a server does not echo");

        server.shutdown();
    }

    #[test]
    fn channel_frames_are_plain_minecraft_framing() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        stream.write_all(b"hello").expect("writes");
        assert_eq!(
            out.collected(),
            [
                0x0f, 0x02, 0x08, b'x', b'm', b'c', b':', b'd', b'a', b't', b'a', b'h', b'e', b'l',
                b'l', b'o'
            ]
        );
        stream.shutdown();
    }
}

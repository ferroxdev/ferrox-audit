//! The post-TLS TCP mask chain: what the pinned reference wraps around a stream *below* the TLS
//! layer (`transport/internet/finalmask`, `fragment/conn.go`), so the records a handshake emits
//! reach the wire as the pieces the config asked for.
//!
//! [`Fragment`] cuts session writes, [`Sudoku`] replaces each plaintext octet with four hint octets
//! in both directions, and [`HeaderCustom`] runs a configured ping-pong handshake before them, and `xmc`
//! runs a Minecraft login and CFB8 session. A fragment mask rewrites nothing: the
//! octets a session writes are the octets the peer reads, cut at different record ends. Splitting a
//! handshake record is legal TLS — a handshake message may span records — so the peer's own stack
//! reassembles it, which is what the pinned interop rows assert.
//!
//! Stages compose in config order on the write path: the first configured entry sees the session's
//! whole, and what it hands on is the next stage's whole, the last stage nearest the socket. That is
//! the reference's reverse-then-wrap order read from the other end. The read path runs the same
//! stages from the socket end, so a codec's bytes are unwrapped before the stage above it sees them.

mod go_rand;
mod header_custom;
mod sudoku;

pub mod xmc;

pub use header_custom::{Expr, ExprArg, HeaderCustom, HeaderRun, Item, Sequence};
pub use sudoku::Sudoku;
pub use xmc::cfb8::Cfb8;
pub use xmc::derivation::{derive_rsa_key, private_key_der, public_key_der};
pub use xmc::packet_stream::PacketStream;
pub use xmc::profile::{find_profile, read_login_success, Profile};

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// The side a connection plays. Sudoku's directions are asymmetric and a header handshake expects
/// the other side's sequences, so the same config must be armed differently on a dial and an accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskRole {
    Client,
    Server,
}

/// The record type a handshake rides, and the width of a TLS record header.
const HANDSHAKE: u8 = 22;
const HEADER: usize = 5;

/// Draws served from one `getrandom` until the cache runs dry: a hello cut at random widths
/// needs a draw per bound, piece and delay, and a syscall each was the reference's, not a law.
/// A smaller draw could not feed the same modulo, so the draws are the same shape either way.
#[derive(Debug, Clone, Copy)]
struct Entropy {
    cache: [u64; 4],
    at: usize,
    #[cfg(test)]
    refills: usize,
}

impl Entropy {
    fn new() -> Self {
        Self {
            cache: [0; 4],
            at: 4,
            #[cfg(test)]
            refills: 0,
        }
    }

    /// The next draw, refilling the cache with one `getrandom` when dry.
    fn draw(&mut self) -> Option<u64> {
        if self.at == 4 {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).ok()?;
            let array = raw.as_chunks::<8>().0;
            self.cache = [
                u64::from_le_bytes(array[0]),
                u64::from_le_bytes(array[1]),
                u64::from_le_bytes(array[2]),
                u64::from_le_bytes(array[3]),
            ];
            self.at = 0;
            #[cfg(test)]
            {
                self.refills += 1;
            }
        }
        let draw = self.cache[self.at];
        self.at += 1;
        Some(draw)
    }
}

/// Records one gathered write carries: two slices each, a list narrow enough for every platform's
/// vectored write. A merged run past this width pays another call rather than a body copy.
const GATHERED_RECORDS: usize = 32;

/// One `Int32Range` from the config, its ends already ordered by [`Range::ordered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub low: i64,
    pub high: i64,
}

impl Range {
    /// The reference's `ensureOrder`: a config may spell a range either way, and the reader puts it
    /// right before anything draws from it.
    pub fn ordered(low: i64, high: i64) -> Self {
        Self {
            low: low.min(high),
            high: low.max(high),
        }
    }

    /// The reference's `RandBetween`: a span of 0 or 1 always answers its low end, a wider span
    /// draws `min .. max` — the top of a range is never emitted, so `11-37` means thirty-six at
    /// most.
    pub fn pick(&self) -> Option<i64> {
        self.pick_from(&mut Entropy::new())
    }

    /// The same draw off a cached supply; the span test and the modulo are `pick`'s unchanged.
    fn pick_from(&self, ent: &mut Entropy) -> Option<i64> {
        let span = i128::from(self.high) - i128::from(self.low);
        if span < 2 {
            return Some(self.low);
        }
        let step = i128::from(ent.draw()? % span as u64);
        i64::try_from(i128::from(self.low) + step).ok()
    }
}

/// The `fragment` mask: `packets` picks which writes are cut, `lengths` the piece widths, `delays`
/// the waits between them, and `max_split` how many records one write may become.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub packets_from: u64,
    pub packets_to: u64,
    pub lengths: Vec<Range>,
    pub delays: Vec<Range>,
    pub max_split: Range,
    /// Cut inside every label of the hello's server name, one record per piece. The widths are
    /// unused here; `tlsSettings.recordFragment` is what arms it.
    sni: bool,
    /// The hello this stage already cut; decoy records before it spend no slot, and handshake
    /// records after it (a `KeyUpdate`) are not mistaken for a second hello.
    hello_done: bool,
    /// The octets still to come of a handshake record whose head already went out uncut; shaping
    /// resumes only past them, so a continuation is never read as a hello of its own.
    hello_skip: usize,
    ent: Entropy,
    count: u64,
    gathered: Option<Gathered>,
}

/// The part of a merged hello already built but not yet accepted by the sink, so a refused write
/// resumes at that octet instead of replaying the cuts and the cipher's draw.
#[derive(Debug, Clone)]
struct Gathered {
    bytes: Vec<u8>,
    at: usize,
    /// Byte offsets where the configured delay between two retained records falls due.
    parks: Vec<(usize, i64)>,
}

impl Fragment {
    /// A mask the config can actually drive: an empty width or delay list cuts nothing, a negative
    /// width is a slice the reference cannot even form, and a last width entry of 0 is the one shape
    /// that never advances — every later segment clamps to it, so each piece would be empty forever.
    pub fn new(
        packets_from: u64,
        packets_to: u64,
        lengths: Vec<Range>,
        delays: Vec<Range>,
        max_split: Range,
    ) -> Option<Self> {
        if lengths.is_empty()
            || delays.is_empty()
            || lengths.iter().any(|width| width.low < 0)
            || lengths.last()?.low <= 0
        {
            return None;
        }
        Some(Self {
            packets_from,
            packets_to,
            lengths,
            delays,
            max_split,
            sni: false,
            hello_done: false,
            hello_skip: 0,
            ent: Entropy::new(),
            count: 0,
            gathered: None,
        })
    }

    /// The same stage with the server-name cut: one record boundary inside every label, which a
    /// filter that reconstructs each record on its own cannot rejoin into a name.
    #[must_use]
    pub fn sni(mut self) -> Self {
        self.sni = true;
        self
    }

    /// The write the chain hands this stage, answered with how much of it reached the wire.
    pub fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        if let Some(mut gathered) = self.gathered.take() {
            if let Err(error) = flush_gathered(raw, &mut gathered) {
                self.gathered = Some(gathered);
                return Err(error);
            }
            if p.is_empty() {
                return Ok(0);
            }
        }
        self.count += 1;
        if self.packets_from == 0 && self.packets_to == 1 {
            if self.hello_done {
                return raw.write(p);
            }
            if self.hello_skip > 0 {
                self.hello_skip = self.hello_skip.saturating_sub(p.len());
                return raw.write(p);
            }
            let Some(record_len) = Self::hello_shape(p) else {
                self.forward_unshaped(p);
                return raw.write(p);
            };
            if record_len != HEADER || p.len() == HEADER {
                self.hello_done = true;
                return if self.sni {
                    self.write_sni(raw, p, record_len)
                } else {
                    self.write_hello(raw, p, record_len)
                };
            }
            return self.write_past_decoys(raw, p);
        }
        if self.packets_from != 0
            && (self.count < self.packets_from || self.count > self.packets_to)
        {
            return raw.write(p);
        }
        self.write_pieces(raw, p)
    }

    /// An empty handshake record ahead of the hello in the same write is a decoy: it goes out
    /// untouched and the slot the hello needs stays open for what follows it.
    fn write_past_decoys<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        let mut done = 0usize;
        let mut rest = p;
        loop {
            let mut sent = 0usize;
            while sent < HEADER {
                match raw.write(&rest[sent..HEADER]) {
                    Ok(0) if sent > 0 => return Ok(done + sent),
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(written) => sent += written,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    // The octets that did land stay counted, so a retry resumes after them.
                    Err(_) if sent > 0 => return Ok(done + sent),
                    Err(error) => return Err(error),
                }
            }
            done += HEADER;
            rest = &rest[HEADER..];
            if rest.is_empty() {
                return Ok(done);
            }
            let Some(record_len) = Self::hello_shape(rest) else {
                self.forward_unshaped(rest);
                return Ok(done + raw.write(rest)?);
            };
            if record_len != HEADER || rest.len() == HEADER {
                self.hello_done = true;
                let taken = if self.sni {
                    self.write_sni(raw, rest, record_len)?
                } else {
                    self.write_hello(raw, rest, record_len)?
                };
                return Ok(done + taken);
            }
        }
    }

    /// Put the retained burst on the wire without a new plaintext write.
    fn flush<W: Write>(&mut self, raw: &mut W) -> io::Result<()> {
        if let Some(mut gathered) = self.gathered.take() {
            if let Err(error) = flush_gathered(raw, &mut gathered) {
                self.gathered = Some(gathered);
                return Err(error);
            }
        }
        Ok(())
    }

    /// The segment's width, or the body's last octet once `max_split` has taken its bound: the run
    /// always ends on the whole, so a bounded hello is a short hello, never a lost one.
    fn cut(&mut self, segment: usize, from: usize, end: usize, bound: usize) -> Option<usize> {
        let width = self.lengths[segment.min(self.lengths.len() - 1)].pick_from(&mut self.ent)?;
        let last = bound != 0 && segment + 1 >= bound;
        let to = from.saturating_add(width as usize);
        Some(if last || to > end { end } else { to })
    }

    /// The reference parks between pieces when its delay range can answer above zero, and so does
    /// this: a mask that cut faster would look like a different schedule to anything watching the
    /// wire. One draw of the cached supply decides both the test and the duration.
    /// The delay between two records, after the record before it has left every stage below this
    /// one: a stage that retained it would otherwise sleep and then send it beside the next.
    fn park_after<W: Write>(&mut self, raw: &mut W, segment: usize) -> io::Result<()> {
        let Some(ms) = self
            .delay_at(segment)
            .pick_from(&mut self.ent)
            .filter(|ms| *ms > 0)
        else {
            return Ok(());
        };
        match raw.flush() {
            Ok(()) => std::thread::sleep(Duration::from_millis(ms as u64)),
            // The record before this delay is out; a full socket only costs the spacing.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Why this write is not a hello the mask may cut: too short for a header, not a handshake
    /// record, or a record whose body has not all arrived.
    fn hello_shape(p: &[u8]) -> Option<usize> {
        if p.len() <= HEADER || p[0] != HANDSHAKE {
            return None;
        }
        let record_len = HEADER + usize::from(u16::from_be_bytes([p[3], p[4]]));
        (p.len() >= record_len).then_some(record_len)
    }

    /// A write this stage will not cut: a decoy (the empty record, an alert) leaves the hello slot
    /// open, while a handshake record whose body is still arriving is forwarded to its declared end
    /// and then closed, so its continuation cannot pass for a hello.
    fn forward_unshaped(&mut self, p: &[u8]) {
        if p.len() < HEADER {
            if p.first() == Some(&HANDSHAKE) {
                self.hello_done = true;
            }
        } else if p[0] == HANDSHAKE && p.len() > HEADER {
            let declared = HEADER + usize::from(u16::from_be_bytes([p[3], p[4]]));
            self.hello_skip = declared.saturating_sub(p.len());
            if self.hello_skip == 0 {
                self.hello_done = true;
            }
        }
    }

    /// The `tlshello` mode: the first handshake record, once every record of it has arrived, becomes
    /// records of its own — the original type, version and this piece's width in the header. One draw of
    /// `max_split` bounds the run, and a single zero delay merges the records into one write, which
    /// is what makes the run a single burst on the socket.
    fn write_hello<W: Write>(
        &mut self,
        raw: &mut W,
        p: &[u8],
        record_len: usize,
    ) -> io::Result<usize> {
        let Some(bound) = self.max_split.pick_from(&mut self.ent) else {
            // No entropy for the bound: the hello goes out as the one record it was.
            return raw.write_all(p).map(|()| p.len());
        };
        // A drawn bound above zero caps the run; every other value is the reference's "no bound".
        let bound = if bound > 0 {
            usize::try_from(bound).unwrap_or(usize::MAX)
        } else {
            0
        };
        let merged = self.delays.len() == 1 && self.delays[0].high == 0;
        if merged {
            self.write_gathered(raw, p, record_len, bound)?;
            if self.gathered.is_some() {
                return Ok(p.len());
            }
        } else {
            let mut from = HEADER;
            let mut segment = 0usize;
            while from < record_len {
                let Some(to) = self.cut(segment, from, record_len, bound) else {
                    // No entropy for a width: the rest goes out as the one record it is.
                    write_record(raw, &head_of(p, record_len - from), &p[from..record_len])?;
                    break;
                };
                write_record(raw, &head_of(p, to - from), &p[from..to])?;
                self.park_after(raw, segment)?;
                from = to;
                segment += 1;
            }
        }
        self.finish_hello(raw, p, record_len)
    }

    /// A record that rode in behind the hello keeps its own write, whole or partial; a sink that
    /// refuses it still reports the hello it already took, so the caller retries only the tail.
    fn finish_hello<W: Write>(
        &mut self,
        raw: &mut W,
        p: &[u8],
        record_len: usize,
    ) -> io::Result<usize> {
        if p.len() == record_len {
            return Ok(p.len());
        }
        loop {
            match raw.write(&p[record_len..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(taken) if taken == p.len() - record_len => return Ok(p.len()),
                Ok(taken) => {
                    self.gathered = Some(Gathered {
                        bytes: p[record_len + taken..].to_vec(),
                        at: 0,
                        parks: Vec::new(),
                    });
                    return Ok(p.len());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.gathered = Some(Gathered {
                        bytes: p[record_len..].to_vec(),
                        at: 0,
                        parks: Vec::new(),
                    });
                    return Ok(p.len());
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn gather_remaining(
        &mut self,
        p: &[u8],
        mut from: usize,
        mut segment: usize,
        record_len: usize,
        bound: usize,
        out: &mut Vec<u8>,
    ) {
        while from < record_len {
            let origin = from;
            let mut heads = [0u8; GATHERED_RECORDS * HEADER];
            let mut count = 0usize;
            while count < GATHERED_RECORDS && from < record_len {
                let to = self
                    .cut(segment, from, record_len, bound)
                    .unwrap_or(record_len);
                heads[count * HEADER..][..HEADER].copy_from_slice(&head_of(p, to - from));
                from = to;
                segment += 1;
                count += 1;
            }
            let mut at = origin;
            for head in heads[..count * HEADER].as_chunks::<HEADER>().0 {
                let width = usize::from(u16::from_be_bytes([head[3], head[4]]));
                out.extend_from_slice(head);
                out.extend_from_slice(&p[at..at + width]);
                at += width;
            }
        }
    }

    /// The `tlssni` mode: one record boundary inside every label of the server name, so a filter
    /// that reads a name out of a single record never finds one whole. Every piece is a complete
    /// handshake record and the server reassembles the handshake exactly as it would any hello.
    /// A write with no name falls back to the width cut, which still splits the record.
    fn write_sni<W: Write>(
        &mut self,
        raw: &mut W,
        p: &[u8],
        record_len: usize,
    ) -> io::Result<usize> {
        let Some(name) = crate::evasion::server_name_range(&p[..record_len]) else {
            return self.write_hello(raw, p, record_len);
        };
        let mut cuts = crate::evasion::label_cuts(&p[name.clone()]);
        for at in &mut cuts {
            *at += name.start;
        }
        cuts.retain(|at| *at > HEADER && *at < record_len);
        let Some(bound) = self.max_split.pick_from(&mut self.ent) else {
            return write_progress(raw, p);
        };
        if bound > 0 {
            cuts.truncate(usize::try_from(bound - 1).unwrap_or(usize::MAX));
        }
        cuts.push(record_len);

        let merged = self.delays.len() == 1 && self.delays[0].high == 0;
        if merged {
            let mut heads = Vec::with_capacity(cuts.len());
            let mut from = HEADER;
            for to in &cuts {
                heads.push(head_of(p, to - from));
                from = *to;
            }
            let mut parts = Vec::with_capacity(heads.len() * 2 + 1);
            let mut from = HEADER;
            for (head, to) in heads.iter().zip(&cuts) {
                parts.push(io::IoSlice::new(head));
                parts.push(io::IoSlice::new(&p[from..*to]));
                from = *to;
            }
            if p.len() > record_len {
                parts.push(io::IoSlice::new(&p[record_len..]));
            }
            let mut parts = &mut parts[..];
            let before = parts.len();
            if let Err(error) = write_iovecs(raw, &mut parts) {
                let progressed = parts.len() < before;
                if !progressed
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
                {
                    return Err(error);
                }
                let mut bytes = Vec::new();
                for part in parts.iter() {
                    bytes.extend_from_slice(part);
                }
                if !bytes.is_empty() {
                    self.gathered = Some(Gathered {
                        bytes,
                        at: 0,
                        parks: Vec::new(),
                    });
                }
                return Ok(p.len());
            }
            return Ok(p.len());
        }
        let mut from = HEADER;
        for (segment, to) in cuts.iter().enumerate() {
            let head = head_of(p, to - from);
            let mut parts = [io::IoSlice::new(&head), io::IoSlice::new(&p[from..*to])];
            let mut parts = &mut parts[..];
            if let Err(error) = write_iovecs(raw, &mut parts) {
                let progressed = parts.len() < 2;
                if !progressed
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
                {
                    return Err(error);
                }
                return Ok(self.retain_sni(p, parts, &cuts, segment, *to, record_len));
            }
            if segment + 1 < cuts.len() {
                self.park_after(raw, segment)?;
            }
            from = *to;
        }
        self.finish_hello(raw, p, record_len)
    }

    /// The burst a sink refused, rebuilt as one buffer: the unsent part first, then every record
    /// behind it, with the delay the config asked for noted where it falls so the retry keeps the
    /// spacing instead of sending the retained burst flat out.
    fn retain_sni(
        &mut self,
        p: &[u8],
        parts: &[io::IoSlice<'_>],
        cuts: &[usize],
        segment: usize,
        to: usize,
        record_len: usize,
    ) -> usize {
        let mut bytes = Vec::new();
        let mut waits = Vec::new();
        for part in parts {
            bytes.extend_from_slice(part);
        }
        let mut next = to;
        for (offset, later) in cuts[segment + 1..].iter().enumerate() {
            let wait = self.delay_at(segment + offset).pick_from(&mut self.ent);
            waits.push((bytes.len(), wait.unwrap_or(0)));
            bytes.extend_from_slice(&head_of(p, later - next));
            bytes.extend_from_slice(&p[next..*later]);
            next = *later;
        }
        bytes.extend_from_slice(&p[record_len..]);
        if !bytes.is_empty() {
            self.gathered = Some(Gathered {
                bytes,
                at: 0,
                parks: waits,
            });
        }
        p.len()
    }

    /// The merged hello: every record's header goes into a bounded stack scratch and each body is
    /// the caller's own slice, so one `writev` puts the burst out without copying the hello. The
    /// part a sink refuses is the one copy, kept only so a retry resumes instead of re-cutting.
    fn write_gathered<W: Write>(
        &mut self,
        raw: &mut W,
        p: &[u8],
        record_len: usize,
        bound: usize,
    ) -> io::Result<()> {
        let mut from = HEADER;
        let mut segment = 0usize;
        loop {
            if from >= record_len {
                return Ok(());
            }
            let origin = from;
            let mut heads = [0u8; GATHERED_RECORDS * HEADER];
            let mut count = 0usize;
            while count < GATHERED_RECORDS && from < record_len {
                // No entropy for a width: the run ends on the whole, never on a lost octet.
                let to = self
                    .cut(segment, from, record_len, bound)
                    .unwrap_or(record_len);
                let head = head_of(p, to - from);
                heads[count * HEADER..][..HEADER].copy_from_slice(&head);
                from = to;
                segment += 1;
                count += 1;
            }
            let mut parts = [io::IoSlice::new(&[]); GATHERED_RECORDS * 2];
            let mut at = origin;
            for (index, head) in heads[..count * HEADER]
                .as_chunks::<HEADER>()
                .0
                .iter()
                .enumerate()
            {
                let width = usize::from(u16::from_be_bytes([head[3], head[4]]));
                parts[index * 2] = io::IoSlice::new(head);
                parts[index * 2 + 1] = io::IoSlice::new(&p[at..at + width]);
                at += width;
            }
            let mut parts = &mut parts[..count * 2];
            let before = parts.len();
            if let Err(error) = write_iovecs(raw, &mut parts) {
                let progressed = parts.len() < before;
                if !progressed
                    && origin == HEADER
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
                {
                    return Err(error);
                }
                let mut bytes = Vec::new();
                for part in parts.iter() {
                    bytes.extend_from_slice(part);
                }
                self.gather_remaining(p, from, segment, record_len, bound, &mut bytes);
                bytes.extend_from_slice(&p[record_len..]);
                self.gathered = Some(Gathered {
                    bytes,
                    at: 0,
                    parks: Vec::new(),
                });
                return Ok(());
            }
        }
    }

    fn delay_at(&self, segment: usize) -> Range {
        self.delays[segment.min(self.delays.len() - 1)]
    }

    /// The `packets` modes that are not `tlshello`: the whole goes out as pieces of the drawn
    /// widths, each advance measured by what the socket actually took.
    fn write_pieces<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        let Some(bound) = self.max_split.pick_from(&mut self.ent) else {
            return write_progress(raw, p);
        };
        let bound = if bound > 0 {
            usize::try_from(bound).unwrap_or(usize::MAX)
        } else {
            0
        };
        let mut from = 0usize;
        let mut segment = 0usize;
        loop {
            let Some(to) = self.cut(segment, from, p.len(), bound) else {
                return write_progress(raw, &p[from..]).map(|written| from + written);
            };
            if from == to {
                self.park_after(raw, segment)?;
                segment += 1;
                continue;
            }
            let written = match raw.write(&p[from..to]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if from > 0
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                {
                    return Ok(from);
                }
                Err(error) => return Err(error),
            };
            from += written;
            self.park_after(raw, segment)?;
            segment += 1;
            if from >= p.len() {
                return Ok(from);
            }
        }
    }
}

/// Write as much of `p` as a nonblocking sink will take in one call, answering the progress made
/// before it blocked so the caller drains exactly those octets rather than sending them twice.
fn write_progress<W: Write>(raw: &mut W, mut p: &[u8]) -> io::Result<usize> {
    let mut written = 0usize;
    while !p.is_empty() {
        match raw.write(p) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(taken) => {
                written += taken;
                p = &p[taken..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if written > 0
                    && matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                return Ok(written);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(written)
}

/// A record's header, re-headed from the hello's type, version and this piece's width.
fn head_of(p: &[u8], width: usize) -> [u8; HEADER] {
    [p[0], p[1], p[2], (width >> 8) as u8, width as u8]
}

/// A record's header and its body go out as one gathered write, so the body never lands in a buffer
/// of its own the way the reference's scratch does.
fn write_record<W: Write>(raw: &mut W, head: &[u8], body: &[u8]) -> io::Result<()> {
    let mut parts = [io::IoSlice::new(head), io::IoSlice::new(body)];
    let mut parts = &mut parts[..];
    write_iovecs(raw, &mut parts)
}

fn flush_gathered<W: Write>(raw: &mut W, gathered: &mut Gathered) -> io::Result<()> {
    while gathered.at < gathered.bytes.len() {
        let end = gathered
            .parks
            .first()
            .map_or(gathered.bytes.len(), |(offset, _)| {
                (*offset).min(gathered.bytes.len())
            });
        while gathered.at < end {
            match raw.write(&gathered.bytes[gathered.at..end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(taken) => gathered.at += taken,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if let Some((_, wait)) = gathered.parks.first().copied() {
            gathered.parks.remove(0);
            if wait > 0 {
                std::thread::sleep(Duration::from_millis(wait as u64));
            }
        }
    }
    gathered.at = 0;
    gathered.bytes.clear();
    Ok(())
}

/// Hand the list to the sink in as few vectored calls as it takes, advancing the list on a short
/// call so every part stays where the caller put it. A refused call leaves the list at the first
/// octet the sink did not take.
#[allow(
    clippy::mut_mut,
    reason = "the list is advanced in place so a refused call leaves the unsent parts for the retry"
)]
fn write_iovecs<W: Write>(raw: &mut W, parts: &mut &mut [io::IoSlice<'_>]) -> io::Result<()> {
    while !parts.is_empty() {
        match raw.write_vectored(parts) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(taken) => io::IoSlice::advance_slices(parts, taken),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A source-address allow/deny list applied where a transport accepts a connection or reads a
/// datagram; it writes no byte, so it never enters the chain's write path.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SourceFilter {
    blocked: IpSets,
    allowed: IpSets,
}

impl SourceFilter {
    pub fn new(blocked: IpSets, allowed: IpSets) -> Self {
        Self { blocked, allowed }
    }

    /// A blocked match rejects; when an allowlist is present, an address outside it — or a source
    /// the transport cannot name — is rejected.
    pub fn rejects(&self, source: Option<IpAddr>) -> bool {
        let Some(source) = source else {
            return !self.allowed.is_empty();
        };
        self.blocked.matches(source) || (!self.allowed.is_empty() && !self.allowed.matches(source))
    }
}

/// The positive and negative range sets one filter list parsed into, each with the reference's
/// reverse flag.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpSets {
    sets: Vec<(Vec<(IpAddr, IpAddr)>, bool)>,
}

impl IpSets {
    pub fn new(sets: Vec<(Vec<(IpAddr, IpAddr)>, bool)>) -> Self {
        Self { sets }
    }

    pub fn is_empty(&self) -> bool {
        self.sets.iter().all(|(ranges, _)| ranges.is_empty())
    }

    fn matches(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.sets.iter().any(|(ranges, reverse)| {
            let family = ranges
                .iter()
                .any(|(start, _)| same_family(ip, start.to_canonical()));
            family && ranges.iter().any(|(start, end)| between(ip, *start, *end)) != *reverse
        })
    }
}

fn same_family(ip: IpAddr, other: IpAddr) -> bool {
    matches!(
        (ip, other),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn between(ip: IpAddr, start: IpAddr, end: IpAddr) -> bool {
    let (ip, start, end) = (ip.to_canonical(), start.to_canonical(), end.to_canonical());
    match (ip, start, end) {
        (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
            u32::from(ip) >= u32::from(start) && u32::from(ip) <= u32::from(end)
        }
        (IpAddr::V6(ip), IpAddr::V6(start), IpAddr::V6(end)) => {
            u128::from(ip) >= u128::from(start) && u128::from(ip) <= u128::from(end)
        }
        _ => false,
    }
}

/// The chain one TCP stream carries: the stages in config order, the first of which sees the
/// session's whole and the last of which is nearest the socket.
#[derive(Debug, Default, Clone)]
pub struct Chain {
    stages: Vec<Stage>,
    filters: Vec<SourceFilter>,
    header: Option<Arc<HeaderCustom>>,
    xmc: Option<Arc<xmc::Config>>,
}

/// One configured stage. `fragment` is write-only, `sudoku` carries a reader too.
#[derive(Debug, Clone)]
enum Stage {
    Fragment(Fragment),
    Sudoku(Sudoku),
}

impl Stage {
    fn is_codec(&self) -> bool {
        matches!(self, Self::Sudoku(_))
    }

    fn opened(&self, role: MaskRole, write: bool) -> Self {
        match self {
            Self::Fragment(stage) => Self::Fragment(stage.clone()),
            Self::Sudoku(stage) => Self::Sudoku(if write {
                stage.open_write(role)
            } else {
                stage.open_read(role)
            }),
        }
    }

    fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        match self {
            Self::Fragment(stage) => stage.write(raw, p),
            Self::Sudoku(stage) => stage.write(raw, p),
        }
    }

    fn flush<W: Write>(&mut self, raw: &mut W) -> io::Result<()> {
        match self {
            Self::Fragment(stage) => stage.flush(raw),
            Self::Sudoku(stage) => stage.flush(raw),
        }
    }

    fn read<R: Read>(&mut self, inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fragment(_) => inner.read(buf),
            Self::Sudoku(stage) => stage.read_from(inner, buf),
        }
    }

    fn peek_from<R: Read + PeekRead>(
        &mut self,
        inner: &mut R,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        match self {
            Self::Fragment(_) => inner.peek(buf),
            Self::Sudoku(stage) => stage.peek_from(inner, buf),
        }
    }
}

/// A stream that can look ahead without consuming: a TCP socket serves this with `MSG_PEEK`, which
/// is what a header sniff needs when a codec lies between it and the socket.
pub trait PeekRead: Read {
    fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

impl PeekRead for &std::net::TcpStream {
    fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        std::net::TcpStream::peek(self, buf)
    }
}

/// One connection's opened chains: the writer always, the reader only when a codec stage needs one.
#[derive(Debug)]
pub struct OpenChain {
    pub write: Chain,
    pub read: Option<Chain>,
}

impl Chain {
    /// One more stage, appended in config order.
    pub fn push(&mut self, stage: Fragment) {
        self.stages.push(Stage::Fragment(stage));
    }

    /// The same chain with `stage` in front, where it sees the session's whole before every
    /// configured stage: the TLS cut runs on the `ClientHello`, not on what a mask below made of it.
    #[must_use]
    pub fn with_front(&self, stage: &Fragment) -> Self {
        let mut chain = self.clone();
        chain.stages.insert(0, Stage::Fragment(stage.clone()));
        chain
    }

    /// One more codec stage.
    pub fn push_sudoku(&mut self, stage: Sudoku) {
        self.stages.push(Stage::Sudoku(stage));
    }

    pub fn is_empty(&self) -> bool {
        self.stages.is_empty() && self.header.is_none() && self.xmc.is_none()
    }

    /// One `header-custom` handshake outside the byte stages; the first entry owns it.
    pub fn push_header_custom(&mut self, header: HeaderCustom) {
        self.header = Some(Arc::new(header));
    }

    /// The handshake the config armed, if any.
    pub fn header(&self) -> Option<&HeaderCustom> {
        self.header.as_deref()
    }

    /// One `xmc` handshake outside the byte stages; the first entry owns it.
    pub fn set_xmc(&mut self, config: xmc::Config) {
        self.xmc = Some(Arc::new(config));
    }

    /// The xmc handshake the config armed, if any.
    pub fn xmc(&self) -> Option<&xmc::Config> {
        self.xmc.as_deref()
    }

    /// The same chain without its handshake, which the byte stages own separately.
    #[must_use]
    pub fn without_header(&self) -> Self {
        Self {
            stages: self.stages.clone(),
            filters: self.filters.clone(),
            header: None,
            xmc: None,
        }
    }

    /// Attach one more source filter; every stage's verdict is a separate gate.
    pub fn set_filter(&mut self, filter: SourceFilter) {
        self.filters.push(filter);
    }

    pub fn filters(&self) -> &[SourceFilter] {
        &self.filters
    }

    /// A source is refused when any filter stage refuses it.
    pub fn rejects(&self, source: Option<IpAddr>) -> bool {
        self.filters.iter().any(|filter| filter.rejects(source))
    }

    /// The same chain for one connection: every codec opens a reader and writer for the side this
    /// connection plays, while the template stays untouched so the next connection counts from zero.
    pub fn open(&self, role: MaskRole) -> OpenChain {
        let write = Chain {
            stages: self.stages.iter().map(|s| s.opened(role, true)).collect(),
            filters: Vec::new(),
            header: None,
            xmc: None,
        };
        let read = self.stages.iter().any(Stage::is_codec).then(|| Chain {
            stages: self.stages.iter().map(|s| s.opened(role, false)).collect(),
            filters: Vec::new(),
            header: None,
            xmc: None,
        });
        OpenChain { write, read }
    }

    /// The write the stream was asked to make, answered with how much of it reached the wire.
    pub fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        drive(&mut self.stages, raw, p)
    }

    /// Put every retained piece on the wire, nearest the socket first.
    pub fn flush<W: Write>(&mut self, raw: &mut W) -> io::Result<()> {
        flush_drive(&mut self.stages, raw)
    }

    /// One read through every codec stage: the last configured stage sees the socket, and each
    /// stage above it reads that stage's output.
    pub fn read<R: Read>(&mut self, raw: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        read_drive(&mut self.stages, raw, buf)
    }

    /// One look-ahead that leaves the plaintext for the read: a codec fills its own pending bytes
    /// from the socket, and a stage above it peeks through that pending rather than past it.
    pub fn peek<R: Read + PeekRead>(&mut self, raw: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        peek_drive(&mut self.stages, raw, buf)
    }
}

// The first stage sees the whole and hands its pieces to the next; the depth is the config's stage count.
fn drive<W: Write>(stages: &mut [Stage], raw: &mut W, p: &[u8]) -> io::Result<usize> {
    let Some((first, rest)) = stages.split_first_mut() else {
        return raw.write(p);
    };
    if rest.is_empty() {
        return first.write(raw, p);
    }
    let mut pipe = Pipe { stages: rest, raw };
    first.write(&mut pipe, p)
}

fn flush_drive<W: Write>(stages: &mut [Stage], raw: &mut W) -> io::Result<()> {
    let Some((first, rest)) = stages.split_first_mut() else {
        return raw.flush();
    };
    if rest.is_empty() {
        first.flush(raw)?;
        return raw.flush();
    }
    {
        let mut pipe = Pipe {
            stages: &mut *rest,
            raw: &mut *raw,
        };
        first.flush(&mut pipe)?;
    }
    flush_drive(rest, raw)
}

fn read_drive<R: Read>(stages: &mut [Stage], raw: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let Some((first, rest)) = stages.split_first_mut() else {
        return raw.read(buf);
    };
    if rest.is_empty() {
        return first.read(raw, buf);
    }
    let mut pipe = ReadPipe { stages: rest, raw };
    first.read(&mut pipe, buf)
}

fn peek_drive<R: Read + PeekRead>(
    stages: &mut [Stage],
    raw: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let Some((first, rest)) = stages.split_first_mut() else {
        return raw.peek(buf);
    };
    if rest.is_empty() {
        return first.peek_from(raw, buf);
    }
    let mut pipe = ReadPipe { stages: rest, raw };
    first.peek_from(&mut pipe, buf)
}

struct Pipe<'a, W> {
    stages: &'a mut [Stage],
    raw: &'a mut W,
}

impl<W: Write> Write for Pipe<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        drive(self.stages, &mut *self.raw, buf)
    }

    // A stage reads one `&[u8]`, so a gathered write reaches it as one run or its count lands on the header and body separately.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match bufs {
            [] => Ok(0),
            [one] => self.write(one),
            _ => {
                let mut whole = Vec::with_capacity(bufs.iter().map(|part| part.len()).sum());
                for part in bufs {
                    whole.extend_from_slice(part);
                }
                self.write(&whole)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_drive(&mut *self.stages, &mut *self.raw)
    }
}

struct ReadPipe<'a, R> {
    stages: &'a mut [Stage],
    raw: &'a mut R,
}

impl<R: Read> Read for ReadPipe<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_drive(self.stages, &mut *self.raw, buf)
    }
}

impl<R: Read + PeekRead> PeekRead for ReadPipe<'_, R> {
    fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        peek_drive(self.stages, &mut *self.raw, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: i64, max: i64) -> Range {
        Range::ordered(min, max)
    }

    fn fragment_count(stage: &Stage) -> u64 {
        match stage {
            Stage::Fragment(fragment) => fragment.count,
            Stage::Sudoku(_) => panic!("a fragment stage"),
        }
    }

    /// A handshake record of `body` octets, every one of them distinct.
    fn hello(body: usize) -> Vec<u8> {
        let mut p = vec![HANDSHAKE, 3, 1];
        p.extend_from_slice(&(body as u16).to_be_bytes());
        p.extend((0..body).map(|i| (i % 251) as u8));
        p
    }

    /// One `ClientHello` record carrying `name`, with the lengths a server reassembles from.
    fn client_hello(name: &str) -> Vec<u8> {
        let mut server = vec![0, 0, 0];
        server.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server.extend_from_slice(name.as_bytes());
        server[0..2].copy_from_slice(&((name.len() + 3) as u16).to_be_bytes());
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

    /// The wire as a peer sees it: every write call, the runs it was made of, and the octets.
    #[derive(Default)]
    struct Wire {
        calls: usize,
        widths: Vec<usize>,
        segments: Vec<(usize, usize)>,
        bytes: Vec<u8>,
        /// When set, each call takes at most this many octets, like a socket under buffer pressure.
        takes: usize,
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            let take = if self.takes == 0 {
                buf.len()
            } else {
                buf.len().min(self.takes)
            };
            self.widths.push(take);
            self.segments.push((buf.as_ptr() as usize, take));
            self.bytes.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            self.calls += 1;
            let live: Vec<&[u8]> = bufs.iter().map(|part| &part[..]).collect();
            let whole: usize = live.iter().map(|part| part.len()).sum();
            let take = if self.takes == 0 {
                whole
            } else {
                whole.min(self.takes)
            };
            self.widths.push(take);
            let mut left = take;
            for part in live {
                let run = part.len().min(left);
                self.segments.push((part.as_ptr() as usize, run));
                self.bytes.extend_from_slice(&part[..run]);
                left -= run;
            }
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_reversed_set_does_not_match_the_other_family() {
        let v4 = |start: &str, end: &str| {
            (
                vec![(
                    start.parse::<IpAddr>().expect("start"),
                    end.parse::<IpAddr>().expect("end"),
                )],
                true,
            )
        };
        let set = IpSets::new(vec![v4("192.0.2.0", "192.0.2.255")]);
        assert!(!set.matches("2001:db8::1".parse().expect("ip")));
        assert!(set.matches("198.51.100.1".parse().expect("ip")));
        assert!(!set.matches("192.0.2.5".parse().expect("ip")));
    }

    #[test]
    fn every_filter_stage_is_a_gate() {
        let allow = |start: &str, end: &str| {
            SourceFilter::new(
                IpSets::default(),
                IpSets::new(vec![(
                    vec![(
                        start.parse::<IpAddr>().expect("start"),
                        end.parse::<IpAddr>().expect("end"),
                    )],
                    false,
                )]),
            )
        };
        let mut chain = Chain::default();
        chain.set_filter(allow("192.0.2.0", "192.0.2.255"));
        chain.set_filter(allow("198.51.100.0", "198.51.100.255"));
        assert!(chain.rejects(Some("192.0.2.5".parse().expect("ip"))));
        assert!(chain.rejects(Some("198.51.100.5".parse().expect("ip"))));
    }

    /// What a peer's record walk finds: the widths of the records emitted, and the message between
    /// them. This is the loop the pinned interop observer runs.
    fn records(wire: &[u8]) -> (Vec<usize>, Vec<u8>) {
        let mut widths = Vec::new();
        let mut message = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            assert_eq!(wire[at], HANDSHAKE, "every piece is a handshake record");
            let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
            widths.push(len);
            message.extend_from_slice(&wire[at + HEADER..at + HEADER + len]);
            at += HEADER + len;
        }
        (widths, message)
    }

    struct Stalling {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for Stalling {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.bytes.len() >= self.limit {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let take = buf.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct InterruptedOnce {
        bytes: Vec<u8>,
        interrupted: bool,
    }

    impl Write for InterruptedOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct InterruptsBody {
        bytes: Vec<u8>,
        calls: usize,
    }

    impl Write for InterruptsBody {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_vectored(&[io::IoSlice::new(buf)])
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 2 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let part = bufs
                .iter()
                .find(|part| !part.is_empty())
                .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
            self.bytes.extend_from_slice(part);
            Ok(part.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_interrupted_record_body_is_retried_without_replaying_the_header() {
        let mut sink = InterruptsBody {
            bytes: Vec::new(),
            calls: 0,
        };
        write_record(&mut sink, &[HANDSHAKE, 3, 1, 0, 3], b"abc").expect("retries the body");
        assert_eq!(
            sink.bytes,
            [HANDSHAKE, 3, 1, 0, 3, b'a', b'b', b'c'],
            "the header is written once and the body follows it"
        );
    }

    #[test]
    fn an_interrupted_write_is_retried_without_losing_progress() {
        let mut sink = InterruptedOnce {
            bytes: Vec::new(),
            interrupted: false,
        };
        assert_eq!(write_progress(&mut sink, b"abc").expect("retries"), 3);
        assert_eq!(sink.bytes, b"abc");
    }

    #[test]
    fn zero_width_pieces_are_skipped_and_empty_input_writes_nothing() {
        let mut mask = Fragment::new(
            0,
            0,
            vec![range(0, 0), range(4, 4)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole: Vec<u8> = (0..10).collect();
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(wire.bytes, whole);
        assert_eq!(mask.write(&mut wire, b"").expect("empty"), 0);
        assert_eq!(wire.bytes.len(), whole.len(), "empty input writes nothing");
    }

    #[test]
    fn a_blocked_piece_returns_the_octets_it_already_wrote() {
        let mut mask = Fragment::new(0, 0, vec![range(4, 4)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let whole: Vec<u8> = (0..20).collect();
        let mut sink = Stalling {
            bytes: Vec::new(),
            limit: 6,
        };
        let written = mask.write(&mut sink, &whole).expect("progress");
        assert_eq!(
            written, 6,
            "the caller learns exactly what reached the sink"
        );
        assert_eq!(sink.bytes, whole[..6], "and only those octets were sent");
    }

    #[test]
    fn a_blocked_hello_resumes_at_the_refused_octet() {
        struct BlocksOnce {
            bytes: Vec<u8>,
            blocked: bool,
        }

        impl Write for BlocksOnce {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if !self.bytes.is_empty() && !self.blocked {
                    self.blocked = true;
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let config = || {
            Fragment::new(
                0,
                1,
                vec![range(11, 11), range(37, 37)],
                vec![range(0, 0)],
                range(24, 24),
            )
            .expect("valid")
        };
        let whole = hello(60);
        let mut expected = Wire::default();
        config().write(&mut expected, &whole).expect("writes");

        let mut mask = config();
        let mut sink = BlocksOnce {
            bytes: Vec::new(),
            blocked: false,
        };
        assert_eq!(
            mask.write(&mut sink, &whole).expect("accepts the hello"),
            whole.len(),
            "a blocked burst is retained, not dropped"
        );
        assert_eq!(
            mask.write(&mut sink, &[]).expect("drains the empty retry"),
            0,
            "an empty retry only drains the retained output"
        );
        assert_eq!(
            sink.bytes, expected.bytes,
            "the retry continues the burst instead of replaying its cuts"
        );
    }

    #[test]
    fn a_permanent_hello_error_is_not_reported_as_sent() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }

            fn write_vectored(&mut self, _: &[io::IoSlice<'_>]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        assert_eq!(
            mask.write(&mut Broken, &hello(60))
                .expect_err("a permanent error is not a send")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn a_hello_record_is_cut_into_records_of_the_configured_widths() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37), range(40, 40)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(300);
        let mut wire = Wire::default();
        assert_eq!(
            mask.write(&mut wire, &whole).expect("writes"),
            whole.len(),
            "the mask answers the whole it was handed"
        );
        assert_eq!(
            wire.calls, 1,
            "one zero delay merges the run into a single write"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths,
            vec![11, 37, 40, 40, 40, 40, 40, 40, 12],
            "the drawn widths, the last clamped to the body's end"
        );
        assert_eq!(message, whole[HEADER..], "and the hello arrives whole");
        assert_eq!(
            wire.bytes.len(),
            whole.len() + (widths.len() - 1) * HEADER,
            "the hello's own header is reused, and only one is added per extra record"
        );
    }

    #[test]
    fn an_sni_record_is_cut_inside_the_name_and_arrives_whole() {
        let whole = client_hello("www.example.co.uk");
        let name = crate::evasion::server_name_range(&whole).expect("a name");
        let mut mask = Fragment::new(0, 1, vec![range(1, 32_768)], vec![range(0, 0)], range(0, 0))
            .expect("valid")
            .sni();
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(wire.calls, 1, "one zero delay merges the records");
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths.len(), 5, "one record per label and the tail");
        assert_eq!(message, whole[HEADER..], "the handshake arrives whole");
        let mut at = 0usize;
        for width in widths {
            let body = &wire.bytes[at + HEADER..at + HEADER + width];
            assert!(
                !body
                    .windows(name.len())
                    .any(|window| window == &whole[name.clone()]),
                "no record carries the whole name"
            );
            at += HEADER + width;
        }
    }

    #[test]
    fn a_hello_without_a_name_falls_back_to_the_width_cut() {
        let whole = hello(300);
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid")
        .sni();
        let mut plain = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let mut sni_wire = Wire::default();
        let mut plain_wire = Wire::default();
        mask.write(&mut sni_wire, &whole).expect("writes");
        plain.write(&mut plain_wire, &whole).expect("writes");
        assert_eq!(sni_wire.bytes, plain_wire.bytes);
    }

    #[test]
    fn a_delayed_piece_hands_the_body_over_where_it_lies() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 1)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(48);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(
            wire.calls, 2,
            "a delay past zero emits each record on its own"
        );
        assert_eq!(
            wire.segments[1],
            (whole[HEADER..HEADER + 11].as_ptr() as usize, 11),
            "the first piece is the hello's own octets, not a copy of them"
        );
        assert_eq!(
            wire.segments[3],
            (whole[HEADER + 11..].as_ptr() as usize, 37),
            "and the second's"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths, vec![11, 37]);
        assert_eq!(message, whole[HEADER..]);
        assert_eq!(
            mask.ent.refills, 0,
            "a fixed config answers its low ends and never reaches the supply at all"
        );
    }

    #[test]
    fn a_random_piece_draws_once_from_the_cached_supply() {
        // The one random draw here is the first width, 11..20; the bound, second width and delay all answer their fixed low ends.
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 20), range(37, 37)],
            vec![range(0, 1)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(48);
        let mut wire = Wire::default();
        mask.write(&mut wire, &whole).expect("writes");
        assert_eq!(
            mask.ent.refills, 1,
            "the draw came from the supply, refilled once and never again"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths.len(), 2, "a cut and the clamped rest");
        assert!((11..20).contains(&widths[0]), "the drawn width");
        assert_eq!(message, whole[HEADER..]);
    }

    #[test]
    fn a_merged_run_gathers_the_callers_body_without_restaging_it() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(400);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(wire.calls, 1, "the run leaves in one gathered write");
        let (widths, message) = records(&wire.bytes);
        let mut at = HEADER;
        for (index, width) in widths.iter().enumerate() {
            let (pointer, took) = wire.segments[index * 2 + 1];
            assert_eq!(
                pointer,
                whole[at..at + width].as_ptr() as usize,
                "piece {index}'s body is the caller's own octets, not a copy"
            );
            assert_eq!(took, *width);
            at += width;
        }
        assert_eq!(message, whole[HEADER..], "and the hello arrives whole");
        assert_eq!(
            mask.ent.refills, 0,
            "a fixed config answers its low ends and never draws at all"
        );
    }

    #[test]
    fn a_merged_run_survives_a_socket_that_takes_a_little_at_a_time() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(400);
        let mut wire = Wire {
            takes: 7,
            ..Wire::default()
        };
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert!(wire.calls > 1, "a short-take socket is handed the rest");
        let (_, message) = records(&wire.bytes);
        assert_eq!(message, whole[HEADER..], "no octet is lost or replayed");
    }

    #[test]
    fn a_merged_run_past_the_gather_width_keeps_every_octet() {
        let mut mask =
            Fragment::new(0, 1, vec![range(1, 1)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let whole = hello(96);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(
            wire.calls, 3,
            "ninety-six one-octet records take three batches of thirty-two"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(widths, vec![1; 96]);
        assert_eq!(message, whole[HEADER..], "the batching loses no octet");
    }

    #[test]
    fn a_second_tlshello_stage_sees_the_merged_records_whole() {
        let outer = Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(0, 0))
            .expect("valid");
        let inner =
            Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut chain = Chain::default();
        chain.push(outer);
        chain.push(inner);
        let whole = hello(30);
        let mut wire = Wire::default();
        assert_eq!(chain.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(
            fragment_count(&chain.stages[1]),
            1,
            "the gathered run reaches the next stage as one write, not one per slice"
        );
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths,
            vec![3, 3, 3, 2, 11, 8],
            "the second stage cut the first outer body to its width and passed the rest through"
        );
        assert_eq!(message, whole[HEADER..], "the two stages lose no octet");
    }

    #[test]
    fn a_random_merged_hello_draws_only_the_random_widths_from_the_supply() {
        // Two random widths, then a fixed 100 governs every later segment and the bound closes the run at ten records: only the two random segments reach the supply, and one getrandom feeds both.
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(50, 150), range(50, 150), range(100, 100)],
            vec![range(0, 0)],
            range(10, 10),
        )
        .expect("valid");
        let whole = hello(1000);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths.len(),
            10,
            "the bound closed the run on exactly ten records"
        );
        assert!(
            (50..150).contains(&widths[0]) && (50..150).contains(&widths[1]),
            "the two random segments drew their width"
        );
        assert_eq!(
            &widths[2..9],
            &[100; 7],
            "the fixed width governs every later segment and never draws"
        );
        assert!(widths[9] > 0, "the last record carries the clamped rest");
        assert_eq!(message, whole[HEADER..], "and the hello arrives whole");
        assert_eq!(mask.ent.refills, 1, "two draws ride one getrandom, not two");
    }

    #[test]
    fn a_max_split_ends_the_run_on_the_whole_hello() {
        for bound in [1i64, 2, 5] {
            let mut mask = Fragment::new(
                0,
                1,
                vec![range(11, 11)],
                vec![range(0, 0)],
                range(bound, bound),
            )
            .expect("valid");
            let whole = hello(300);
            let mut wire = Wire::default();
            mask.write(&mut wire, &whole).expect("writes");
            let (widths, message) = records(&wire.bytes);
            assert_eq!(
                widths.len(),
                bound as usize,
                "a bound of {bound} emits exactly that many records"
            );
            assert_eq!(message, whole[HEADER..], "the last record carries the rest");
        }
    }

    #[test]
    fn a_decoy_record_ahead_of_the_hello_spends_no_hello_slot() {
        let mut mask =
            Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let decoy = [0x16, 3, 3, 0, 0];
        let whole = hello(30);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &decoy).expect("writes"), decoy.len());
        assert_eq!(wire.bytes, decoy, "the decoy goes out untouched");
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let (widths, message) = records(&wire.bytes[decoy.len()..]);
        assert_eq!(
            widths,
            vec![3; 10],
            "the hello behind the decoy is still cut"
        );
        assert_eq!(message, whole[HEADER..]);
        let update = [0x16, 3, 3, 0, 4, 9, 9, 9, 9];
        let before = wire.bytes.len();
        assert_eq!(
            mask.write(&mut wire, &update).expect("writes"),
            update.len()
        );
        assert_eq!(
            &wire.bytes[before..],
            &update,
            "a handshake record after the hello is not cut a second time"
        );
    }

    #[test]
    fn a_decoy_sharing_the_write_leaves_the_hello_cut() {
        let mut mask =
            Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut whole = [0x16, 3, 3, 0, 0].to_vec();
        let hello = hello(30);
        whole.extend_from_slice(&hello);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert_eq!(&wire.bytes[..HEADER], &whole[..HEADER], "the decoy is sent");
        let (widths, message) = records(&wire.bytes[HEADER..]);
        assert_eq!(widths, vec![3; 10], "the hello beside it is still cut");
        assert_eq!(message, hello[HEADER..]);
    }

    #[test]
    fn a_delay_waits_for_the_stage_below_to_send() {
        let sni = Fragment::new(0, 1, vec![range(3, 3)], vec![range(20, 20)], range(0, 0))
            .expect("valid")
            .sni();
        let below =
            Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut chain = Chain::default();
        chain.push(below);
        let mut chain = chain.with_front(&sni);
        let mut wire = RefuseOnce {
            wire: Wire::default(),
            left: 1,
        };
        let p = client_hello("retained.example");
        assert_eq!(chain.write(&mut wire, &p).expect("writes"), p.len());
        assert!(
            wire.wire.bytes.len() >= HEADER,
            "the record the delay separated left before the delay"
        );
    }

    /// A wire that refuses the first write with `WouldBlock`, so a stage below retains it.
    struct RefuseOnce {
        wire: Wire,
        left: usize,
    }

    impl Write for RefuseOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.left > 0 {
                self.left -= 1;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.wire.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_continuation_of_a_forwarded_hello_is_not_shaped_again() {
        let mut mask =
            Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut whole = hello(40);
        whole[HEADER + 2..HEADER + 7].copy_from_slice(&[0x16, 3, 3, 0, 2]);
        let mut wire = Wire::default();
        let split = HEADER + 2;
        assert_eq!(
            mask.write(&mut wire, &whole[..split]).expect("writes"),
            split
        );
        let rest = &whole[split..];
        assert_eq!(
            mask.write(&mut wire, rest).expect("writes"),
            rest.len(),
            "the rest of the already-forwarded hello is taken"
        );
        assert_eq!(
            wire.bytes, whole,
            "the tail of a forwarded hello is finished as it came, never re-headed"
        );
    }

    #[test]
    fn a_max_split_of_one_bounds_a_name_cut_to_one_record() {
        let mut mask = Fragment::new(0, 1, vec![range(3, 3)], vec![range(0, 0)], range(1, 1))
            .expect("valid")
            .sni();
        let whole = client_hello("www.example.com");
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let (widths, message) = records(&wire.bytes);
        assert_eq!(
            widths.len(),
            1,
            "a bound of one is one record, not every label"
        );
        assert_eq!(message, whole[HEADER..]);
    }

    #[test]
    fn a_refused_delayed_record_keeps_the_rest_for_the_next_write() {
        struct RefusingOnce {
            refused: bool,
            bytes: Vec<u8>,
        }
        impl Write for RefusingOnce {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if !self.refused {
                    self.refused = true;
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
                if !self.refused {
                    self.refused = true;
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let mut taken = 0;
                for part in bufs {
                    self.bytes.extend_from_slice(part);
                    taken += part.len();
                }
                Ok(taken)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(3, 3)],
            vec![range(0, 0), range(0, 0)],
            range(0, 0),
        )
        .expect("valid")
        .sni();
        let whole = client_hello("www.example.com");
        let mut wire = RefusingOnce {
            refused: false,
            bytes: Vec::new(),
        };
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        assert!(wire.bytes.is_empty(), "the sink took nothing");
        assert!(mask.gathered.is_some(), "the unsent records are kept");
        mask.flush(&mut wire).expect("flushes");
        let (_, message) = records(&wire.bytes);
        assert_eq!(message, whole[HEADER..], "the retry loses no octet");
    }

    #[test]
    fn the_last_configured_width_governs_every_later_segment() {
        let mut mask = Fragment::new(
            1,
            4,
            vec![range(3, 3), range(9, 9)],
            vec![range(0, 0)],
            range(0, 0),
        )
        .expect("valid");
        let mut wire = Wire {
            takes: 0,
            ..Wire::default()
        };
        let body = vec![1u8; 40];
        assert_eq!(mask.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(
            wire.widths,
            vec![3, 9, 9, 9, 9, 1],
            "the first segment is 3, then the last entry governs"
        );
        assert_eq!(wire.bytes, body);
    }

    #[test]
    fn a_timed_split_advances_only_by_what_the_socket_took() {
        let mut mask = Fragment::new(1, 1, vec![range(20, 20)], vec![range(0, 0)], range(0, 0))
            .expect("valid");
        let mut wire = Wire {
            takes: 7,
            ..Wire::default()
        };
        let body = vec![7u8; 50];
        assert_eq!(mask.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.bytes, body, "the whole arrives, cut and refilled");
        assert_eq!(
            wire.calls, 8,
            "a 20-octet piece across a socket that takes seven at a time"
        );
    }

    #[test]
    fn a_write_that_is_not_a_whole_hello_leaves_the_slot_open() {
        let mut mask = Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let mut wire = Wire::default();
        // Not a handshake record.
        let alert = vec![23u8, 3, 1, 0, 2, 1, 0];
        assert_eq!(mask.write(&mut wire, &alert).expect("writes"), alert.len());
        assert_eq!(wire.bytes, alert);
        wire.bytes.clear();
        // Too short to hold a header.
        let short = vec![HANDSHAKE, 3, 1];
        assert_eq!(mask.write(&mut wire, &short).expect("writes"), short.len());
        assert_eq!(wire.bytes, short);
        wire.bytes.clear();
        // A record whose body is still arriving is forwarded to its declared end, continuation and all.
        let split = hello(60);
        let partial = split[..HEADER + 20].to_vec();
        assert_eq!(
            mask.write(&mut wire, &partial).expect("writes"),
            partial.len()
        );
        assert_eq!(wire.bytes, partial);
        wire.bytes.clear();
        let again = hello(60);
        assert_eq!(mask.write(&mut wire, &again).expect("writes"), again.len());
        assert_eq!(
            wire.bytes, again,
            "a continuation is finished as it came, never re-headed"
        );
        wire.bytes.clear();
        let update = [0x16, 3, 3, 0, 4, 1, 2, 3, 4];
        assert_eq!(
            mask.write(&mut wire, &update).expect("writes"),
            update.len()
        );
        assert_eq!(
            wire.bytes, update,
            "a record after the hello keeps its own bytes"
        );
    }

    #[test]
    fn a_record_behind_the_hello_keeps_its_own_write_and_its_own_bytes() {
        let mut mask = Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(24, 24))
            .expect("valid");
        let mut whole = hello(40);
        let next = vec![23u8, 3, 3, 0, 4, 1, 2, 3, 4];
        whole.extend_from_slice(&next);
        let mut wire = Wire::default();
        assert_eq!(mask.write(&mut wire, &whole).expect("writes"), whole.len());
        let hello_len = wire.bytes.len() - next.len();
        let (widths, message) = records(&wire.bytes[..hello_len]);
        assert_eq!(widths, vec![11, 11, 11, 7], "the hello's records");
        assert_eq!(message, whole[HEADER..HEADER + 40]);
        assert_eq!(
            &wire.bytes[hello_len..],
            next.as_slice(),
            "and the record behind it"
        );
    }

    #[test]
    fn writes_outside_the_packet_window_pass_through() {
        let mut mask =
            Fragment::new(2, 3, vec![range(4, 4)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut wire = Wire::default();
        let body = vec![9u8; 9];
        assert_eq!(mask.write(&mut wire, &body).expect("first"), body.len());
        assert_eq!(wire.widths, vec![9], "the first write is outside 2..3");
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[8u8; 9]).expect("second"),
            9,
            "inside the window"
        );
        assert_eq!(
            wire.widths,
            vec![4, 4, 1],
            "and cut at the configured width"
        );
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[7u8; 9]).expect("third"),
            9,
            "still inside"
        );
        assert_eq!(wire.widths, vec![4, 4, 1]);
        wire.widths.clear();
        assert_eq!(
            mask.write(&mut wire, &[6u8; 9]).expect("fourth"),
            9,
            "past the window again"
        );
        assert_eq!(wire.widths, vec![9]);
    }

    #[test]
    fn a_pick_never_answers_the_top_of_a_range() {
        for _ in 0..256 {
            let drawn = range(11, 37).pick().expect("entropy");
            assert!(
                (11..37).contains(&drawn),
                "the top of a half-open range is never drawn: {drawn}"
            );
        }
        assert_eq!(
            range(11, 12).pick(),
            Some(11),
            "a span of one is its low end"
        );
        assert_eq!(range(5, 5).pick(), Some(5));
        assert_eq!(
            Range::ordered(37, 11),
            range(11, 37),
            "a swapped pair is ordered"
        );
    }

    #[test]
    fn a_range_spanning_the_whole_i64_does_not_overflow() {
        let whole = Range::ordered(i64::MIN, i64::MAX);
        for _ in 0..64 {
            let drawn = whole.pick().expect("entropy");
            assert!((i64::MIN..i64::MAX).contains(&drawn));
        }
        assert!(Range::ordered(-i64::MAX, 1).pick().is_some());
    }

    #[test]
    fn a_config_that_could_spin_is_refused() {
        assert!(Fragment::new(0, 1, vec![range(11, 11)], vec![range(0, 0)], range(1, 1)).is_some());
        assert!(
            Fragment::new(
                0,
                1,
                vec![range(11, 11), range(0, 9)],
                vec![range(0, 0)],
                range(0, 0)
            )
            .is_none(),
            "a last width entry of 0 never advances"
        );
        assert!(Fragment::new(0, 1, Vec::new(), vec![range(0, 0)], range(0, 0)).is_none());
        assert!(Fragment::new(0, 1, vec![range(11, 11)], Vec::new(), range(0, 0)).is_none());
        assert!(
            Fragment::new(
                0,
                1,
                vec![range(11, 11), range(-4, 4)],
                vec![range(0, 0)],
                range(0, 0)
            )
            .is_none(),
            "a width that can answer negative is a slice the reference cannot even form"
        );
    }

    #[test]
    fn a_chain_applies_its_stages_in_config_order() {
        let outer =
            Fragment::new(1, 2, vec![range(8, 8)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let inner =
            Fragment::new(1, 2, vec![range(3, 3)], vec![range(0, 0)], range(0, 0)).expect("valid");
        let mut chain = Chain::default();
        chain.push(outer);
        chain.push(inner);
        let mut wire = Wire::default();
        let body = vec![5u8; 10];
        assert_eq!(chain.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.bytes, body, "a chain adds nothing and loses nothing");
        assert_eq!(
            wire.widths,
            vec![3, 3, 2, 2],
            "the first stage cut the whole at 8, the last cut each of its pieces at 3"
        );
        assert_eq!(
            fragment_count(&chain.stages[0]),
            1,
            "each stage counts its own writes"
        );
        assert_eq!(fragment_count(&chain.stages[1]), 2);
    }

    #[test]
    fn a_codec_chain_decodes_in_reverse_stage_order() {
        let stage =
            |password: &str| Sudoku::new(password, "", "", &[], 0, 0).expect("a driveable stage");
        let mut chain = Chain::default();
        chain.push_sudoku(stage("outer"));
        chain.push_sudoku(stage("inner"));
        let plain: Vec<u8> = (0..=255u8).cycle().take(777).collect();
        let mut client = chain.open(MaskRole::Client);
        let mut server = chain.open(MaskRole::Server);
        let mut wire = Vec::new();
        client
            .write
            .write(&mut wire, &plain)
            .expect("encodes both stages");
        let mut input = wire.as_slice();
        let mut decoded = vec![0u8; plain.len()];
        let mut got = 0usize;
        while got < decoded.len() {
            let n = server
                .read
                .as_mut()
                .expect("a codec reader")
                .read(&mut input, &mut decoded[got..])
                .expect("decodes both stages");
            assert_ne!(n, 0);
            got += n;
        }
        assert_eq!(
            decoded, plain,
            "the stage nearest the socket decodes first, as the write order reverses"
        );
    }

    #[test]
    fn an_empty_chain_writes_through() {
        let mut chain = Chain::default();
        assert!(chain.is_empty());
        let mut wire = Wire::default();
        let body = vec![3u8; 12];
        assert_eq!(chain.write(&mut wire, &body).expect("writes"), body.len());
        assert_eq!(wire.widths, vec![12]);
    }

    /// A sink that takes a whole gathered write in one call and keeps nothing, so a count here is
    /// the mask's own work rather than a buffer copy the harness would make.
    struct Discard;

    impl Write for Discard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            Ok(bufs.iter().map(|part| part.len()).sum())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// 256 fixed hellos through the merged path: the frame `scripts/count-ops.sh` prices.
    #[inline(never)]
    fn merged_hello_probe(mask: &mut Fragment, raw: &mut Discard, whole: &[u8]) -> usize {
        let mut total = 0usize;
        for _ in 0..256 {
            mask.count = 0;
            mask.hello_done = false;
            mask.hello_skip = 0;
            total += std::hint::black_box(
                mask.write(raw, std::hint::black_box(whole))
                    .expect("the sink always takes the whole"),
            );
        }
        total
    }

    #[test]
    fn the_merged_hello_costs_the_cuts_and_the_gather() {
        let mut mask = Fragment::new(
            0,
            1,
            vec![range(11, 11), range(37, 37)],
            vec![range(0, 0)],
            range(24, 24),
        )
        .expect("valid");
        let whole = hello(300);
        let mut sink = Discard;
        assert_eq!(
            merged_hello_probe(&mut mask, &mut sink, &whole),
            256 * whole.len(),
            "every turn answers the hello it was handed"
        );
    }

    #[test]
    fn a_delay_range_whose_top_is_zero_draws_zero() {
        let mut mask =
            Fragment::new(1, 2, vec![range(4, 4)], vec![range(0, 1)], range(0, 0)).expect("valid");
        let mut wire = Wire::default();
        mask.write(&mut wire, &[1u8; 40]).expect("writes");
        assert_eq!(wire.widths.len(), 10, "and the run really was cut");
        assert_eq!(
            range(0, 1).pick(),
            Some(0),
            "so every park draws zero, which is the span a stall detector would catch"
        );
    }
}

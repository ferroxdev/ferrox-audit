#![allow(
    clippy::cast_precision_loss,
    reason = "counters become floats only to be printed; no gate reads the rounded value"
)]
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use ferrox_core::aesgcm::Aes128Gcm;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

const LENGTHS: [usize; 3] = [16_383, 8_192, 4_096];
const BYTE_BUDGET: u64 = 32 * 1024 * 1024;
const SLICES: usize = 4;
const ROUNDS: usize = 5;

fn main() {
    let engine = Aes128Gcm::new(&[7u8; 16]);
    let rows: Vec<Row> = LENGTHS.into_iter().map(row).collect();
    println!(
        "gate 10b reported: {} record-aead rows against ring, ciphertext and tag identical, printed only",
        rows.len()
    );
    let table = report(&rows, engine.backend());
    print!("{table}");
    let path = std::path::Path::new("target/bench-report.md");
    if let Ok(mut existing) = std::fs::read_to_string(path) {
        existing.push_str(&table);
        let _ = std::fs::write(path, existing);
    }
}

struct Row {
    name: String,
    bytes: usize,
    base: f64,
    ours: f64,
}

impl Row {
    fn ratio(&self) -> f64 {
        self.base / self.ours
    }
}

fn row(len: usize) -> Row {
    let key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(7));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(9));
    let aad = [0x17_u8, 0x03, 0x03, (len >> 8) as u8, len as u8];

    let ours = Aes128Gcm::new(&key);
    let reference = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key).expect("key"));
    let plain: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(11))
        .collect();

    let mut ours_buf = plain.clone();
    let tag = ours.seal_in_place(&nonce, &aad, &mut ours_buf);
    let mut reference_buf = plain.clone();
    reference
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad[..]),
            &mut reference_buf,
        )
        .expect("seals");
    assert_eq!(&ours_buf[..], &reference_buf[..len], "{len}: ciphertext");
    assert_eq!(&tag[..], &reference_buf[len..], "{len}: tag");
    assert_eq!(
        ours.open_in_place(&nonce, &aad, &mut ours_buf, &tag),
        Some(len),
        "{len}: opens"
    );
    assert_eq!(ours_buf, plain, "{len}: the same bytes back");

    let iters = (BYTE_BUDGET / len.max(1) as u64).clamp(64, 200_000);
    let mut ours_buf = plain.clone();
    let mut ours_run = || {
        let tag = ours.seal_in_place(black_box(&nonce), &aad, black_box(&mut ours_buf));
        ours.open_in_place(&nonce, &aad, black_box(&mut ours_buf), &tag)
            .expect("opens")
    };
    let mut reference_buf = plain.clone();
    let mut reference_run = || {
        reference
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(black_box(&aad[..])),
                black_box(&mut reference_buf),
            )
            .expect("seals");
        let opened = {
            let opened = reference
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(black_box(&aad[..])),
                    black_box(&mut reference_buf[..]),
                )
                .expect("opens");
            opened.len()
        };
        reference_buf.truncate(opened);
        opened
    };

    let (base, ours) = paired(iters, &mut reference_run, &mut ours_run);
    Row {
        name: format!("tls record, {len}B"),
        bytes: len,
        base,
        ours,
    }
}

fn paired(
    iters: u64,
    base: &mut dyn FnMut() -> usize,
    ours: &mut dyn FnMut() -> usize,
) -> (f64, f64) {
    let slice = (iters / SLICES as u64).max(1);
    let calls = (slice * SLICES as u64) as f64;
    let mut rounds = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        let mut base_seconds = 0.0;
        let mut ours_seconds = 0.0;
        for index in 0..SLICES {
            if (round + index) % 2 == 0 {
                base_seconds += seconds(slice, base);
                ours_seconds += seconds(slice, ours);
            } else {
                ours_seconds += seconds(slice, ours);
                base_seconds += seconds(slice, base);
            }
        }
        rounds.push((base_seconds / calls, ours_seconds / calls));
    }
    rounds.sort_by(|a, b| (a.0 / a.1).total_cmp(&(b.0 / b.1)));
    rounds[rounds.len() / 2]
}

fn seconds(iters: u64, f: &mut dyn FnMut() -> usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    start.elapsed().as_secs_f64()
}

fn report(rows: &[Row], engine_backend: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 10b — the record layer's AEAD\n");
    let _ = writeln!(
        out,
        "What the TLS record layer seals with, `ring`'s AES-128-GCM, against the fused\n\
         engine, at the plaintext sizes a record carries (16 KiB is the TLS 1.3 maximum).\n\
         Each row asserts equal ciphertext and equal tag before either side is timed, and\n\
         the buffers are sealed and opened in place so neither side pays a staging copy. The\n\
         reference appends its tag in place and truncates the buffer for the next round, the only\n\
         shape `ring` offers and the one rustls runs, while the fused engine returns the tag\n\
         detached: the asymmetry favours the fused engine, and its loss stands with it.\n\
         These rows are printed only: a platform where `ring` wins is a platform where\n\
         the provider stays as it is, and that decision is read from this table. It runs in\n\
         its own binary (`--bin record-aead`) so linking `ring` cannot move the gated rows\n\
         `ferrox-bench` itself judges.\n\
         \n\
         | | |\n\
         | --- | --- |\n\
         | reference | `ring 0.17 / aes-128-gcm` |\n\
         | ferrox | `{engine_backend}` |\n"
    );
    let _ = writeln!(
        out,
        "\n| comparison | bytes | reference ns | ferrox ns | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
    }
    out
}

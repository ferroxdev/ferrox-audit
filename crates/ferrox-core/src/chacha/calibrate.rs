use std::sync::OnceLock;
use std::time::Instant;

use super::{base, base_state, portable, xor_groups_impl, Wide};

static ONE_BLOCK: OnceLock<bool> = OnceLock::new();

const TIE: f64 = 0.95;

const REPS: usize = 3;

const BLOCKS: usize = 64;

#[inline]
pub(super) fn verdict() -> bool {
    *ONE_BLOCK.get_or_init(measure)
}

fn measure() -> bool {
    let key = [0x5bu8; 32];
    let nonce = [0xa7u8; 12];
    let state = base_state(&key, &nonce);
    let mut lanes = [0u8; 64 * BLOCKS];
    let mut scalar = [0u8; 64 * BLOCKS];

    let mut lanes_time = f64::MAX;
    let mut scalar_time = f64::MAX;
    for _ in 0..REPS {
        // This path is one block with nothing to issue beside it, so each call counts from the previous word: a dependent chain, not the throughput this path is never asked for.
        let mut ctr = 0u32;
        let start = Instant::now();
        for block in 0..BLOCKS {
            let mut out = [0u8; 64];
            xor_groups_impl::<Wide, 1, false>(&base::<Wide>(&state), ctr, &[], &mut out, None);
            core::hint::black_box(&out);
            ctr = u32::from_le_bytes(out[..4].try_into().expect("four bytes"));
            lanes[block * 64..block * 64 + 64].copy_from_slice(&out);
        }
        lanes_time = lanes_time.min(start.elapsed().as_secs_f64());

        let mut ctr = 0u32;
        let start = Instant::now();
        for block in 0..BLOCKS {
            let mut out = [0u8; 64];
            portable::xor_block(&state, ctr, &mut out);
            core::hint::black_box(&out);
            ctr = u32::from_le_bytes(out[..4].try_into().expect("four bytes"));
            scalar[block * 64..block * 64 + 64].copy_from_slice(&out);
        }
        scalar_time = scalar_time.min(start.elapsed().as_secs_f64());
    }

    debug_assert_eq!(
        lanes, scalar,
        "the one-block cores disagree, so this measurement is timing a bug"
    );
    scalar_time > 0.0 && lanes_time < scalar_time * TIE
}

#[cfg(test)]
mod tests {
    use super::{base, base_state, portable, verdict, xor_groups_impl, Wide, ONE_BLOCK};
    use crate::chacha::one_block_impl;

    #[test]
    fn the_verdict_is_published_once_for_every_caller() {
        let first = verdict();
        for _ in 0..8 {
            assert_eq!(verdict(), first, "the verdict changed between calls");
        }
        assert_eq!(
            ONE_BLOCK.get(),
            Some(&first),
            "the first winner was published"
        );
    }

    #[test]
    fn either_verdict_writes_the_same_keystream() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let state = base_state(&key, &nonce);
        let mut chosen = [0u8; 64];
        assert_eq!(one_block_impl::<false>(&state, 9, &[], &mut chosen), 1);
        let mut scalar = [0u8; 64];
        portable::xor_block(&state, 9, &mut scalar);
        assert_eq!(chosen, scalar, "the chosen core wrote something else");
    }

    #[test]
    fn the_two_one_block_cores_agree_at_every_tested_counter() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let state = base_state(&key, &nonce);
        for ctr in [0u32, 1, 3, 7, u32::MAX - 1, u32::MAX] {
            let mut lanes = [0u8; 64];
            let mut scalar = [0u8; 64];
            xor_groups_impl::<Wide, 1, false>(&base::<Wide>(&state), ctr, &[], &mut lanes, None);
            portable::xor_block(&state, ctr, &mut scalar);
            assert_eq!(lanes, scalar, "counter {ctr}: the two cores disagree");
        }
    }
}

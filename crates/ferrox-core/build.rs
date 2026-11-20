use std::fs;
use std::path::PathBuf;

const GRID_COUNT: usize = 288;
const SLOTS: usize = 1024;
const MASK: usize = SLOTS - 1;

fn main() {
    let grids = grids();
    let terms = rank_terms();
    let patterns = base_patterns(&grids, &terms);
    let total: usize = patterns.iter().map(Vec::len).sum();
    let mut offsets = Vec::with_capacity(GRID_COUNT + 1);
    let mut running = 0u16;
    for list in &patterns {
        offsets.push(running);
        running += u16::try_from(list.len()).expect("a clue list fits an offset");
    }
    offsets.push(running);

    let mut blob = Vec::with_capacity(4 + grids.len() * 16 + offsets.len() * 2 + total * 4);
    blob.extend_from_slice(&(total as u32).to_le_bytes());
    for grid in &grids {
        blob.extend_from_slice(grid);
    }
    for offset in &offsets {
        blob.extend_from_slice(&offset.to_le_bytes());
    }
    for list in &patterns {
        for clue in list {
            blob.extend_from_slice(clue);
        }
    }

    let path =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("sudoku_patterns.bin");
    fs::write(path, blob).expect("write sudoku patterns");
    println!("cargo:rerun-if-changed=build.rs");
}

fn grids() -> Vec<[u8; 16]> {
    fn dfs(index: usize, grid: &mut [u8; 16], out: &mut Vec<[u8; 16]>) {
        if index == 16 {
            out.push(*grid);
            return;
        }
        let row = index / 4;
        let col = index % 4;
        let box_row = (row / 2) * 2;
        let box_col = (col / 2) * 2;
        for num in 1u8..=4 {
            let mut valid = (0..4).all(|i| grid[row * 4 + i] != num && grid[i * 4 + col] != num);
            if valid {
                'boxes: for r in 0..2 {
                    for c in 0..2 {
                        if grid[(box_row + r) * 4 + box_col + c] == num {
                            valid = false;
                            break 'boxes;
                        }
                    }
                }
            }
            if !valid {
                continue;
            }
            grid[index] = num;
            dfs(index + 1, grid, out);
            grid[index] = 0;
        }
    }
    let mut out = Vec::with_capacity(GRID_COUNT);
    let mut grid = [0u8; 16];
    dfs(0, &mut grid, &mut out);
    out
}

fn base_patterns(grids: &[[u8; 16]], terms: &[[u32; 64]; 4]) -> Vec<Vec<[u8; 4]>> {
    let mut patterns = vec![Vec::new(); grids.len()];
    let mut slots = [u32::MAX; SLOTS];
    let mut counts = [0u16; SLOTS];
    let mut first = [0u16; SLOTS];
    let mut used = [0u16; SLOTS];
    let mut groups = [[0u8; 4]; GRID_COUNT];
    for a in 0..13u8 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    let position = [a, b, c, d];
                    let mut used_len = 0usize;
                    for (index, grid) in grids.iter().enumerate() {
                        let clue = sort4([
                            clue_group(grid, position[0]),
                            clue_group(grid, position[1]),
                            clue_group(grid, position[2]),
                            clue_group(grid, position[3]),
                        ]);
                        let key = rank4(terms, clue) as u32;
                        groups[index] = clue;
                        let mut slot = ((key as usize).wrapping_mul(0x9e37_79b1) >> 22) & MASK;
                        loop {
                            let held = slots[slot];
                            if held == u32::MAX {
                                slots[slot] = key;
                                counts[slot] = 1;
                                first[slot] = index as u16;
                                used[used_len] = slot as u16;
                                used_len += 1;
                                break;
                            }
                            if held == key {
                                counts[slot] += 1;
                                break;
                            }
                            slot = (slot + 1) & MASK;
                        }
                    }
                    for &slot in &used[..used_len] {
                        let slot = slot as usize;
                        if counts[slot] == 1 {
                            let index = first[slot] as usize;
                            patterns[index].push(groups[index]);
                        }
                        slots[slot] = u32::MAX;
                        counts[slot] = 0;
                    }
                }
            }
        }
    }
    patterns
}

fn rank_terms() -> [[u32; 64]; 4] {
    let mut terms = [[0u32; 64]; 4];
    for (value, slot) in terms[0].iter_mut().enumerate() {
        *slot = value as u32;
    }
    for (value, slot) in terms[1].iter_mut().enumerate() {
        *slot = ((value + 1) * value / 2) as u32;
    }
    for (value, slot) in terms[2].iter_mut().enumerate() {
        *slot = ((value + 2) * (value + 1) * value / 6) as u32;
    }
    for (value, slot) in terms[3].iter_mut().enumerate() {
        *slot = ((value + 3) * (value + 2) * (value + 1) * value / 24) as u32;
    }
    terms
}

fn rank4(terms: &[[u32; 64]; 4], v: [u8; 4]) -> usize {
    (terms[0][v[0] as usize]
        + terms[1][v[1] as usize]
        + terms[2][v[2] as usize]
        + terms[3][v[3] as usize]) as usize
}

fn sort4(v: [u8; 4]) -> [u8; 4] {
    let (a0, a1) = (v[0].min(v[1]), v[0].max(v[1]));
    let (a2, a3) = (v[2].min(v[3]), v[2].max(v[3]));
    let (b0, b2) = (a0.min(a2), a0.max(a2));
    let (b1, b3) = (a1.min(a3), a1.max(a3));
    let (c1, c2) = (b1.min(b2), b1.max(b2));
    [b0, c1, c2, b3]
}

fn clue_group(grid: &[u8; 16], pos: u8) -> u8 {
    ((grid[pos as usize] - 1) << 4) | (pos & 0x0f)
}

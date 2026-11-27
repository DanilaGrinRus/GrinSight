#![no_main]

use risc0_zkvm::guest::env;
mod state;

const H2_ID: [u8; 32] = [
    0xe4,0x5f,0xa3,0x73,0x2d,0x5e,0xd2,0xe0,0x8e,0xfb,0xa5,0xac,0xd0,0x31,0x71,0x51,
    0x64,0xc4,0x3b,0x0e,0x55,0xd7,0xcc,0x4d,0x20,0x70,0x1c,0x2d,0x0c,0xf4,0x0e,0x61,
];
fn words(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i*4..i*4+4].try_into().unwrap()))
}

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut self_id = [0; 32];
    env::read_slice(&mut self_id);
    let mut len = [0; 4];
    env::read_slice(&mut len);
    let len = u32::from_be_bytes(len) as usize;
    assert!((8..=4096).contains(&len));
    let mut parent = vec![0u8; len];
    env::read_slice(&mut parent);
    let mut current = match &parent[..8] {
        b"GSZ2MH02" => {
            env::verify(words(&H2_ID), &parent).unwrap();
            state::State::from_h2(&parent)
        }
        b"GSZBMH01" => {
            // The receiver additionally checks the final journal ID against the
            // program it actually verified. Every predecessor must carry that ID.
            env::verify(words(&self_id), &parent).unwrap();
            state::State::from_batch(&parent, &self_id)
        }
        _ => panic!("unrecognized antecedent"),
    };
    let mut count = [0u8; 1];
    env::read_slice(&mut count);
    assert!((1..=8).contains(&count[0]));
    for _ in 0..count[0] {
        let mut child = [0; 400];
        env::read_slice(&mut child);
        current.advance(child);
    }
    env::commit_slice(&current.encode(&self_id));
}


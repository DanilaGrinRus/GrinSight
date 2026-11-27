#![no_main]
use risc0_zkvm::guest::env;
mod relation;
risc0_zkvm::guest::entry!(main);

fn main() {
    let mut candidate = [0u8; 400];
    env::read_slice(&mut candidate);
    let point = relation::checkpoint(&candidate);
    env::commit_slice(&point);
}


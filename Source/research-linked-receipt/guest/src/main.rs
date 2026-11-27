#![no_main]

use risc0_zkvm::guest::env;

mod relation;

// Accepted first-stage program, compiled from research-genesis-receipt/guest.
// The witness cannot choose either this ID or the authenticated public statement.
const FIRST_IMAGE_ID: [u32; 8] = [
    1727208000, 2806425962, 3710334176, 4017533812,
    4261108587, 368033744, 2969332350, 438786009,
];

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut parent = [0u8; 520];
    let mut header = [0u8; 400];
    env::read_slice(&mut parent);
    env::read_slice(&mut header);
    env::verify(FIRST_IMAGE_ID, &parent).unwrap();
    env::commit_slice(&relation::successor(&parent, &header));
}


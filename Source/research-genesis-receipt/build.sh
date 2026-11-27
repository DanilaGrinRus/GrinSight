#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${GENESIS_RESEARCH_TARGET:-/var/tmp/grinsight-genesis-receipt}
mkdir -p "$target"
# Use the offline registry of the ZK toolchain, not the wallet's unrelated vendor set.
cd "$target"
export CARGO_TARGET_DIR="$target/guest"
export RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'
cargo +risc0 build --offline --release --locked --manifest-path "$src/guest/Cargo.toml" --target riscv32im-risc0-zkvm-elf
unset RUSTFLAGS
export GENESIS_GUEST_ELF="$target/guest/riscv32im-risc0-zkvm-elf/release/grin-genesis-guest"
export CARGO_TARGET_DIR="$target/host"
cargo build --offline --release --locked --manifest-path "$src/host/Cargo.toml"


#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${LINKED_RESEARCH_TARGET:-/var/tmp/grinsight-linked-receipt}
mkdir -p "$target"
cd "$target"
export CARGO_TARGET_DIR="$target/guest"
export RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'
cargo +risc0 build --offline --release --locked --manifest-path "$src/guest/Cargo.toml" --target riscv32im-risc0-zkvm-elf


#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${LINKED_RESEARCH_TARGET:-/var/tmp/grinsight-linked-receipt}
mkdir -p "$target"
cd "$target"
export PATH="$HOME/.cargo/bin:$PATH"
bash "$src/build-guest.sh"
export CARGO_TARGET_DIR="$target/host"
cargo build --locked --offline --release --features producer --manifest-path "$src/host/Cargo.toml"
tool="$target/host/release/research-grin-linked-receipt"
raw="$target/guest/riscv32im-risc0-zkvm-elf/release/grin-linked-guest"
id=$("$tool" pack-elf "$raw" "$target/guest.elf")
[[ "$id" == "$(tr -d '[:space:]' < "$src/image-id.hex")" ]] || { echo "unrecognized linked guest image: $id" >&2; exit 1; }
echo "LINKED_GUEST_ELF=$target/guest.elf"

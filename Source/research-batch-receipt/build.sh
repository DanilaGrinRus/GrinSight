#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${BATCH_RESEARCH_TARGET:-/var/tmp/grinsight-batch-receipt}
mkdir -p "$target"; cd "$target"
export PATH="$HOME/.cargo/bin:$PATH"
bash "$src/build-guest.sh"
export CARGO_TARGET_DIR="${BATCH_HOST_TARGET:-$target/host}"
cargo build --locked --offline --release --features producer --manifest-path "$src/host/Cargo.toml"
tool="$CARGO_TARGET_DIR/release/research-grin-batch-receipt"
id=$("$tool" pack-elf "$target/guest/riscv32im-risc0-zkvm-elf/release/grin-batch-guest" "$target/guest.elf")
[[ "$id" == "$(tr -d '[:space:]' < "$src/image-id.hex")" ]] || { echo "unrecognized batch guest image: $id" >&2; exit 1; }
echo "BATCH_GUEST_ELF=$target/guest.elf"

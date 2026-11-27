#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${LINKED_RESEARCH_TARGET:-/var/tmp/grinsight-linked-receipt}
out=${1:?provide a new output directory}
export PATH="$HOME/.cargo/bin:$PATH"
export LINKED_GUEST_ELF="$target/guest.elf"
export RISC0_SERVER_PATH="$(command -v r0vm)"
unset RISC0_DEV_MODE
prior="$src/../research-genesis-receipt/testdata"
"$target/host/release/research-grin-linked-receipt" prove \
  "$prior/checkpoint.bin" "$prior/history.receipt" "$src/testdata/h2-header.bin" "$out"

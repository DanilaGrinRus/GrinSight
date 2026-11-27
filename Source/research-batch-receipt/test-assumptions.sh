#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${BATCH_RESEARCH_TARGET:-/var/tmp/grinsight-batch-receipt}
tool="${BATCH_HOST_TARGET:-$target/host}/release/research-grin-batch-receipt"
h2="$src/../research-linked-receipt/testdata"
h6="$src/testdata/h6"
h8="$src/testdata/h8"
scratch=$(mktemp -d "$target/negative.XXXXXXXX")
trap 'rm -f -- "$scratch/input" "$scratch/h7" "$scratch/mutated" "$scratch/log"; rmdir -- "$scratch"' EXIT
export PATH="$HOME/.cargo/bin:$PATH"
export BATCH_GUEST_ELF="$target/guest.elf"
unset RISC0_DEV_MODE
python3 - "$src" "$scratch" <<'PY'
from pathlib import Path
import sys
src, dest = map(Path, sys.argv[1:])
p = (src / "testdata/h6/checkpoint.bin").read_bytes()
with (src.parent / "chain/headers/tests/mainnet/first-4100-headers.bin").open("rb") as chain:
    for _ in range(8):
        wire = chain.read(int.from_bytes(chain.read(2), "big"))
assert len(wire) == 400 and int.from_bytes(wire[2:10], "big") == 7
(dest / "h7").write_bytes(wire)
(dest / "input").write_bytes(bytes.fromhex((src / "image-id.hex").read_text().strip()) + len(p).to_bytes(4, "big") + p + b"\x01" + wire)
q = bytearray(p)
q[-1] ^= 1
(dest / "mutated").write_bytes(q)
PY
refuse() {
    local required=$1; shift
    if "$@" >"$scratch/log" 2>&1; then echo "unexpected success" >&2; exit 1; fi
    grep -F -- "$required" "$scratch/log"
    test ! -e "$scratch/published"
}
refuse "open $scratch/missing" "$tool" prove "$h6/checkpoint.bin" "$scratch/missing" "$scratch/h7" "$scratch/published"
refuse "cryptographic verification failed" "$tool" prove "$h6/checkpoint.bin" "$h2/history.receipt" "$scratch/h7" "$scratch/published"
refuse "proof does not bind" "$tool" prove "$scratch/mutated" "$h6/history.receipt" "$scratch/h7" "$scratch/published"
refuse "proof does not bind" "$tool" prove "$h6/checkpoint.bin" "$h8/history.receipt" "$scratch/h7" "$scratch/published"
refuse "no receipt found to resolve assumption" r0vm --elf "$BATCH_GUEST_ELF" --initial-input "$scratch/input"

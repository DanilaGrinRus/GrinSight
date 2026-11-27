#!/usr/bin/env bash
set -euo pipefail
src=$(cd "$(dirname "$0")" && pwd)
target=${LINKED_RESEARCH_TARGET:-/var/tmp/grinsight-linked-receipt}
tool="$target/host/release/research-grin-linked-receipt"
prior="$src/../research-genesis-receipt/testdata"
scratch=$(mktemp -d "$target/negative.XXXXXXXX")
trap 'rm -f -- "$scratch/bad-parent" "$scratch/input" "$scratch/negative.log" "$scratch/conditional.receipt"; rmdir -- "$scratch"' EXIT
export LINKED_GUEST_ELF="$target/guest.elf"
export PATH="$HOME/.cargo/bin:$PATH"
unset RISC0_DEV_MODE

refuse() {
    local required=$1; shift
    if "$@" >"$scratch/negative.log" 2>&1; then echo "unexpected success" >&2; exit 1; fi
    grep -F -- "$required" "$scratch/negative.log"
    test ! -e "$scratch/published"
}
header="$src/testdata/h2-header.bin"
refuse "open $scratch/missing" "$tool" prove "$prior/checkpoint.bin" "$scratch/missing" "$header" "$scratch/published"
python3 - "$prior/checkpoint.bin" "$scratch/bad-parent" <<'PY'
import pathlib, sys
point = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
point[519] ^= 1
pathlib.Path(sys.argv[2]).write_bytes(point)
PY
refuse "proof does not bind" "$tool" prove "$scratch/bad-parent" "$prior/history.receipt" "$header" "$scratch/published"
cat "$prior/checkpoint.bin" "$header" > "$scratch/input"
if r0vm --elf "$LINKED_GUEST_ELF" --initial-input "$scratch/input" --receipt-kind succinct --receipt "$scratch/conditional.receipt" >"$scratch/negative.log" 2>&1; then
    # A VM admitting an unresolved assumption must still fail full verification.
    refuse "cryptographic verification failed" "$tool" verify main "$src/testdata/checkpoint.bin" "$scratch/conditional.receipt"
else
    cat "$scratch/negative.log"
    grep -Eiq 'assumption|SYS_VERIFY|sys_verify' "$scratch/negative.log"
fi

#!/bin/sh
# Stage 2 check: the C side builds the state from saved segments, applies
# blocks and must get the same results as the Rust core.
set -e
cd "$(dirname "$0")/.."
cargo build --release --offline --features testkit
FX=$(mktemp -d)
./target/release/us-fixture "$FX" > /dev/null
${CC:-cc} -std=c99 -Wall -Wextra -Iinclude tests/test_abi.c target/release/libgrinsight_state_ffi.a -lpthread -ldl -lm -o "$FX/test_abi"
"$FX/test_abi" "$FX"

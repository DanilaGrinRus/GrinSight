#!/usr/bin/env bash
# NO LONGER USED: make_android.ps1 builds grinsight-tor for Android on Windows
# with the NDK and the `rustls` feature (no OpenSSL). Kept for reference.
# grinsight-tor for Android arm64, built in WSL (Ubuntu): OpenSSL for Android is
# built from source by the openssl-src crate, which needs perl and make
# (present in Linux, missing on Windows). Called by make_android.ps1 -WithTor,
# or by hand:   bash /mnt/c/DHW/GrinFlyClient/GrinSight/tor/build_android_wsl.sh
#
# Needs (once, see make_android.ps1): build-essential perl, rustup with the
# aarch64-linux-android target, Android NDK r27c in ~/android-ndk-r27c.
# Versions are pinned by tor/Cargo.lock (--locked); crates come from crates.io.
set -euo pipefail

GRINSIGHT="${GRINSIGHT:-/mnt/c/DHW/GrinFlyClient/GrinSight}"
NDK="${ANDROID_NDK_ROOT:-$HOME/android-ndk-r27c}"
API=24
OUT="$GRINSIGHT/dist/android/jniLibs/arm64-v8a"
source "$HOME/.cargo/env" 2>/dev/null || true

BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -x "$BIN/aarch64-linux-android$API-clang" ] || { echo "NDK not found in $NDK"; exit 1; }
command -v perl >/dev/null && command -v make >/dev/null || { echo "need perl and make (sudo apt install -y build-essential perl)"; exit 1; }

export ANDROID_NDK_ROOT="$NDK" ANDROID_NDK_HOME="$NDK"
export PATH="$BIN:$PATH"
export CC_aarch64_linux_android="$BIN/aarch64-linux-android$API-clang"
export CXX_aarch64_linux_android="$BIN/aarch64-linux-android$API-clang++"
export AR_aarch64_linux_android="$BIN/llvm-ar"
export RANLIB_aarch64_linux_android="$BIN/llvm-ranlib"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$BIN/aarch64-linux-android$API-clang"
# Build on the Linux file system (much faster than /mnt/c); only the result is copied.
export CARGO_TARGET_DIR="$HOME/grinsight-android-target"

cargo build --release --locked --target aarch64-linux-android \
    --manifest-path "$GRINSIGHT/tor/Cargo.toml" -p grinsight-tor

mkdir -p "$OUT"
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/grinsight-tor" "$OUT/libgrinsight_tor.so"
echo "ready: $OUT/libgrinsight_tor.so"
file "$OUT/libgrinsight_tor.so" 2>/dev/null || true

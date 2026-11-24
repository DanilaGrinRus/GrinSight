#!/bin/bash
# GrinSight for macOS: builds the four programs for Apple silicon and Intel,
# joins them into universal binaries, makes GrinSight.app and a .dmg in
# dist-macos/, and runs the interface scenario against the built programs.
# Runs on any Mac with Rust (rustup) and Xcode's command line tools, and on
# GitHub's macOS machines (.github/workflows/macos.yml). Nothing is signed with
# a developer identity: macOS asks once before the first start (right click →
# Open). The binaries carry the ad-hoc signature macOS needs to run them at all.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
TOOLCHAIN=${TOOLCHAIN:-1.99.1}
TARGETS=${TARGETS:-"aarch64-apple-darwin x86_64-apple-darwin"}
OUT="$ROOT/dist-macos"
STAMP=$(date +%Y%m%d-%H%M)
# the version is the window's own: one line of ui/app/src/lib.rs
VER=$(sed -n 's/^pub const APP_VERSION: &str = "\([0-9]*\.[0-9]*\.[0-9]*\)";.*/\1/p' "$ROOT/ui/app/src/lib.rs")
[ -n "$VER" ] || { echo "no APP_VERSION in ui/app/src/lib.rs"; exit 2; }
say() { echo "$(date +%H:%M:%S) $*"; }

rustup toolchain install "$TOOLCHAIN" --profile minimal >/dev/null
for t in $TARGETS; do rustup target add --toolchain "$TOOLCHAIN" "$t" >/dev/null; done
export RUSTUP_TOOLCHAIN=$TOOLCHAIN

# The offline sets are used where they are in the tree; a configuration whose
# set is missing (a checkout without the vendored crates) is moved aside for
# this build only, and the crates come from crates.io at the versions of the
# lock files.
for cfg in .cargo/config.toml ui/.cargo/config.toml transport/*/.cargo/config.toml; do
  [ -f "$cfg" ] || continue
  dir=$(sed -n 's/^directory *= *"\(.*\)"/\1/p' "$cfg" | head -1)
  base=$(dirname "$(dirname "$cfg")")
  if [ -n "$dir" ] && [ ! -d "$base/$dir" ]; then
    say "no $base/$dir: $cfg set aside for this build"
    mv "$cfg" "$cfg.offline-set-missing"
  fi
done

export CARGO_TARGET_DIR="$ROOT/target-macos"
build() { local what=$1 dir=$2 t=$3; shift 3; local s=$SECONDS; (cd "$dir" && cargo build --release -q --target "$t" "$@"); say "$what $t built in $((SECONDS - s)) s"; }
for t in $TARGETS; do
  build host paycore/host "$t" --bin fly-paycore-host
  build chain chain/fly-chain "$t"
  build mailbox transport/mailbox-nostr "$t" --bin fly-mailbox
  build onion onion "$t" --bin fly-onion
  build ui ui/app "$t" --bin fly-ui
done

rm -rf "$OUT" && mkdir -p "$OUT"
APP="$OUT/GrinSight.app"
mkdir -p "$APP/Contents/MacOS/bin" "$APP/Contents/Resources"
universal() { # name, destination
  local parts=()
  for t in $TARGETS; do parts+=("$CARGO_TARGET_DIR/$t/release/$1"); done
  lipo -create "${parts[@]}" -output "$2"
  chmod 755 "$2"
}
universal fly-ui "$APP/Contents/MacOS/GrinSight"
for p in fly-paycore-host fly-chain fly-mailbox fly-onion; do universal "$p" "$APP/Contents/MacOS/bin/$p"; done

# the icon, from the app's own picture
ICONSET="$OUT/icon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 64 128 256 512; do
  sips -z $s $s "$ROOT/ui/app/images/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); sips -z $d $d "$ROOT/ui/app/images/icon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/GrinSight.icns"
rm -rf "$ICONSET"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>GrinSight</string>
  <key>CFBundleDisplayName</key><string>GrinSight</string>
  <key>CFBundleIdentifier</key><string>org.grinsight.fly</string>
  <key>CFBundleVersion</key><string>${VER}.${STAMP//-/.}</string>
  <key>CFBundleShortVersionString</key><string>${VER}</string>
  <key>CFBundleExecutable</key><string>GrinSight</string>
  <key>CFBundleIconFile</key><string>GrinSight</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
cp "$ROOT/dist-files/LICENSE-GPL-3.0.txt" "$APP/Contents/Resources/" 2>/dev/null || true

# ad-hoc signatures (no identity): macOS on Apple silicon runs nothing without one
for b in "$APP/Contents/MacOS/bin/"* "$APP/Contents/MacOS/GrinSight"; do codesign --force -s - "$b"; done
codesign --force -s - "$APP"
lipo -info "$APP/Contents/MacOS/GrinSight"

say "scenario against the packed programs"
T=$(mktemp -d)
if "$APP/Contents/MacOS/GrinSight" --scenario "$T/out" --host "$APP/Contents/MacOS/bin/fly-paycore-host" --profile "$T/p" --guard-dir "$T/g"; then
  say "scenario: passed"
else
  say "scenario: FAILED"; tail -5 "$T/out/scenario.log" 2>/dev/null || true; exit 1
fi
cp "$T/out/scenario.log" "$OUT/scenario.log"
rm -rf "$T"

DMG="$OUT/GrinSight-$STAMP-macos.dmg"
hdiutil create -quiet -volname GrinSight -srcfolder "$APP" -ov -format UDZO "$DMG"
(cd "$OUT" && shasum -a 256 "$(basename "$DMG")" > SHA256SUMS.txt && cat SHA256SUMS.txt)
say "done: $DMG"

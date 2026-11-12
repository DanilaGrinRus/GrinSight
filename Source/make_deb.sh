#!/usr/bin/env bash
# Собирает GrinSight .deb (amd64). Запускать в WSL2/Linux.
#
#   bash make_deb.sh [--version 0.1.0] [--repo /mnt/c/DHW/GrinFlyClient/GrinSight] [--win-vendor /mnt/c/DHW/vendor]
#
# Нужно в WSL: rustup+cargo с target x86_64-unknown-linux-gnu; flutter с включённым
# Linux-desktop (см. tasks/TASK_LINUX_DEB_RU.md); GTK3 dev-библиотеки; dpkg-deb; clang/cc.
# Ядро собирается ОФЛАЙН из вендоров репозитория (как make_service.ps1): header-sync
# из local-vendor (относительный путь), grinsight-tor из Arti-вендора (на Windows это
# C:/DHW/vendor → в WSL /mnt/c/DHW/vendor), на rustls (без OpenSSL).
#
# Результат: dist/linux/grinsight_<version>_amd64.deb
set -euo pipefail

VERSION=0.1.0
REPO="/mnt/c/DHW/GrinFlyClient/GrinSight"
WINVENDOR="/mnt/c/DHW/vendor"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --win-vendor) WINVENDOR="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
cd "$REPO"

command -v dpkg-deb >/dev/null || { echo "нужен dpkg-deb:  sudo apt install -y dpkg-dev"; exit 1; }
command -v cargo    >/dev/null || { echo "нужен cargo (rustup)";                           exit 1; }
rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-gnu \
  || rustup target add x86_64-unknown-linux-gnu

OUT="$REPO/dist/linux"
CORE="$OUT/grinsight-core"
rm -rf "$OUT"; mkdir -p "$CORE"
export CARGO_TARGET_DIR="$REPO/.build/target-linux"
REL="$CARGO_TARGET_DIR/release"

echo ">> ядро: grinsight-service + reverse-wtema-header-sync (offline, locked)"
cargo build --offline --locked --release \
  --manifest-path header-sync/Cargo.toml \
  --bin grinsight-service --bin reverse-wtema-header-sync

echo ">> grinsight-tor (rustls, без OpenSSL)"
# Перекрываем путь к Arti-вендору на Linux-путь (в файле tor/vendor.toml он Windows-ный).
cargo --config "source.vendored-sources.directory=\"$WINVENDOR\"" \
  build --offline --locked --release \
  --manifest-path tor/Cargo.toml -p grinsight-tor \
  --no-default-features --features rustls

for b in grinsight-service reverse-wtema-header-sync grinsight-tor; do
  cp "$REL/$b" "$CORE/$b"
done
chmod +x "$CORE"/*

echo ">> контрольные точки"
if [ ! -d dist/grinsight-core/checkpoints ]; then
  echo "НЕТ dist/grinsight-core/checkpoints — запусти один раз make_service.ps1 на Windows (создаёт подписанную точку)"; exit 1
fi
if [ ! -f dist/grinsight-core/checkpoints/mainnet/release.sig ] || ! cmp -s dist/grinsight-core/checkpoints/mainnet/release.txt release/release.txt; then
  echo "в dist/grinsight-core нет подписанной точки из release/ — сначала make_service.ps1 (или make_app.ps1) на Windows"; exit 1
fi
cp -r dist/grinsight-core/checkpoints "$CORE/"

echo ">> Flutter Linux bundle"
BUNDLE="UI/flutter_app/build/linux/x64/release/bundle"
# Всегда свежая релизная сборка (старый бандл мог быть dev-сборкой с пометкой «прототип»).
echo "собираю flutter build linux (GS_RELEASE)..."
( cd UI/flutter_app && flutter build linux --release --dart-define=GS_RELEASE=true )
if [ ! -d "$BUNDLE" ]; then
  echo "нет Flutter Linux bundle: включи Linux-desktop и собери (см. tasks/TASK_LINUX_DEB_RU.md)"; exit 1
fi
if [ ! -x "$BUNDLE/grinsight" ]; then
  echo "в бандле нет исполняемого 'grinsight' — задай BINARY_NAME=grinsight в UI/flutter_app/linux/CMakeLists.txt"; exit 1
fi

echo ">> сборка дерева .deb"
PKG="$OUT/pkgroot"
APPDIR="$PKG/opt/grinsight"
mkdir -p "$APPDIR" "$PKG/usr/bin" \
         "$PKG/usr/share/applications" \
         "$PKG/usr/share/icons/hicolor/512x512/apps" \
         "$PKG/DEBIAN"
cp -r "$BUNDLE"/. "$APPDIR/"
# ядро кладётся рядом с приложением: сервис сам находит соседей lib*/checkpoints
cp -r "$CORE" "$APPDIR/grinsight-core"

# запускатор в /usr/bin
cat > "$PKG/usr/bin/grinsight" <<'W'
#!/bin/sh
exec /opt/grinsight/grinsight "$@"
W
chmod +x "$PKG/usr/bin/grinsight"

cp UI/flutter_app/assets/icon/app_icon.png \
   "$PKG/usr/share/icons/hicolor/512x512/apps/grinsight.png"

cat > "$PKG/usr/share/applications/grinsight.desktop" <<'D'
[Desktop Entry]
Type=Application
Name=GrinSight
Comment=Revelio for your coins — Grin light wallet
Exec=grinsight
Icon=grinsight
Categories=Finance;Network;
Terminal=false
D

SIZE=$(du -sk "$PKG" | cut -f1)
cat > "$PKG/DEBIAN/control" <<C
Package: grinsight
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: DanilaGrinRus <DanilaGrinRus@users.noreply.github.com>
Installed-Size: $SIZE
Depends: libgtk-3-0, libglib2.0-0, libstdc++6, libc6
Description: GrinSight — Grin light wallet that proves its balance
 Light wallet for Grin: verifies headers and PoW, PIBD state against the
 output root, and each new block against the output and kernel roots.
 Ships a signed mainnet checkpoint; Tor/GlauxNet included.
C

DEB="$OUT/grinsight_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$PKG" "$DEB"
echo ""
echo "готово: $DEB"
dpkg-deb -I "$DEB" | sed 's/^/  /'
echo ""
echo "установка:   sudo apt install $DEB"
echo "или:         sudo dpkg -i $DEB ; sudo apt -f install"

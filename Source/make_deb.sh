#!/usr/bin/env bash
# Собирает GrinSight .deb (amd64). Запускать в WSL2/Linux.
#
#   bash make_deb.sh [--version 0.2.0] [--repo /mnt/c/DHW/GrinSight/Source] [--win-vendor /mnt/c/DHW/GrinSight/Source/tor-vendor]
#
# Нужно в WSL: rustup+cargo с target x86_64-unknown-linux-gnu; flutter с включённым
# Linux-desktop (см. tasks/TASK_LINUX_DEB_RU.md); GTK3 dev-библиотеки; dpkg-deb; clang/cc.
# Ядро собирается ОФЛАЙН из вендоров репозитория (как make_service.ps1): header-sync
# из local-vendor (относительный путь), grinsight-tor из Arti-вендора (на Windows это
# C:/DHW/vendor → в WSL /mnt/c/DHW/vendor), на rustls (без OpenSSL).
#
# Результат: dist/linux/grinsight_<version>_amd64.deb
set -euo pipefail

VERSION=0.2.0
REPO="/mnt/c/DHW/GrinSight/Source"
WINVENDOR="/mnt/c/DHW/GrinSight/Source/tor-vendor"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --win-vendor) WINVENDOR="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
cd "$REPO"

# Инструменты, установленные не в PATH (wsl bash без профиля их не видит).
for d in "$HOME/.cargo/bin" /opt/flutter/bin "$HOME/flutter/bin"; do
  [ -d "$d" ] && PATH="$d:$PATH"
done
export PATH
command -v dpkg-deb >/dev/null || { echo "нужен dpkg-deb:  sudo apt install -y dpkg-dev"; exit 1; }
command -v cargo    >/dev/null || { echo "нужен cargo (rustup)";                           exit 1; }
rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-gnu \
  || rustup target add x86_64-unknown-linux-gnu

OUT="$REPO/dist/linux"
CORE="$OUT/grinsight-core"
rm -rf "$OUT"; mkdir -p "$CORE"
# Промежуточные файлы сборки — на диске самой WSL, а не на /mnt/c: доступ к диску Windows
# из WSL идёт через медленную прослойку, а Rust при сборке трогает тысячи файлов
# (в 3–10 раз быстрее). Исходники остаются на месте. Переопределяется переменной.
export CARGO_TARGET_DIR="${GS_LINUX_TARGET:-$HOME/.cache/grinsight/target-linux}"
mkdir -p "$CARGO_TARGET_DIR"
# Строка прогресса cargo видна и при выводе в файл / Tee-Object (без терминала её нет).
export CARGO_TERM_PROGRESS_WHEN=always CARGO_TERM_PROGRESS_WIDTH=80
REL="$CARGO_TARGET_DIR/release"

echo ">> ядро: grinsight-service + reverse-wtema-header-sync (offline, locked)"
# Офлайн из local-vendor, если он есть; в пакете исходников его нет — тогда те же
# версии (--locked) берутся с crates.io.
NET=""; [ -d local-vendor ] && NET="--offline"
cargo build $NET --locked --release \
  --manifest-path header-sync/Cargo.toml \
  --bin grinsight-service --bin reverse-wtema-header-sync

echo ">> grinsight-tor (rustls, без OpenSSL)"
# Перекрываем путь к Arti-вендору на Linux-путь (в файле tor/vendor.toml он Windows-ный).
if [ -d "$WINVENDOR" ]; then TORCFG=(--config "source.vendored-sources.directory=\"$WINVENDOR\"" build --offline); else TORCFG=(build); fi
cargo "${TORCFG[@]}" --locked --release \
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
# Дерево пакета — на диске WSL: на /mnt/c у всех папок права 777, а dpkg-deb требует
# 0755 для DEBIAN ("control directory has bad permissions 777").
PKGTMP="$(mktemp -d "${TMPDIR:-/tmp}/grinsight-deb.XXXXXX")"
trap 'rm -rf "$PKGTMP"' EXIT
PKG="$PKGTMP/pkgroot"
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

# Права как у обычного пакета: каталоги 0755, файлы 0644, исполняемые 0755.
find "$PKG" -type d -exec chmod 0755 {} +
find "$PKG" -type f -exec chmod u+rw,go+r,go-w {} +
chmod 0755 "$PKG/usr/bin/grinsight" "$APPDIR/grinsight" "$APPDIR/grinsight-core"/grinsight-service \
  "$APPDIR/grinsight-core"/reverse-wtema-header-sync "$APPDIR/grinsight-core"/grinsight-tor
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

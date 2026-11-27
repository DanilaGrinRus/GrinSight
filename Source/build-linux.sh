#!/bin/bash
# Inside GrinSightBuild (Debian 13), as root. Builds the four programs in a
# Debian 10 root (glibc 2.28), so they run on Debian 10+, Ubuntu 20.04+ and
# Mint 20+, RHEL/CentOS Stream/Rocky/Alma 8+, Fedora and Arch; packs a .deb,
# an .rpm and a .tar.gz with a PKGBUILD for Arch; runs the interface scenario
# on the oldest system (Debian 10) and on the newest (Debian 13, from the
# extracted .deb); copies the packages to C:\DHW\dist\.
set -euo pipefail
say() { echo "$(date +%H:%M:%S) $*"; }
OLD=/srv/buster
SOURCE=$(cd -- "$(dirname -- "$0")" && pwd -P)
PHASE=${1:-all}
case "$PHASE" in all|core) ;; *) echo 'expected all or core' >&2; exit 2;; esac
STAMP=$(date +%Y%m%d-%H%M)
# the version is the window's own: one line of ui/app/src/lib.rs
VER=$(sed -nE 's/^pub const APP_VERSION: \&str = "([0-9]+\.[0-9]+\.[0-9]+A?)";.*/\1/p' "$SOURCE/ui/app/src/lib.rs")
[ -n "$VER" ] || { echo "no APP_VERSION in ui/app/src/lib.rs"; exit 2; }
REL="0.${STAMP//-/.}"
export DEBIAN_FRONTEND=noninteractive

# ---- the old root, once
if [ ! -x "$OLD/usr/bin/apt-get" ]; then
  say "making the Debian 10 root"
  apt-get install -y -q --no-install-recommends debootstrap debian-archive-keyring rpm >/dev/null
  KEYS=/usr/share/keyrings/debian-archive-removed-keys.gpg
  debootstrap --variant=minbase --keyring="$KEYS" buster "$OLD" http://archive.debian.org/debian >/dev/null
fi
command -v rpmbuild >/dev/null || apt-get install -y -q --no-install-recommends rpm >/dev/null
mountpoint -q "$OLD/proc" || mount -t proc proc "$OLD/proc"
mountpoint -q "$OLD/dev" || mount --bind /dev "$OLD/dev"
cp /etc/resolv.conf "$OLD/etc/resolv.conf"
mkdir -p "$OLD/root/src/GrinSight/FlyClient/.tools"
mountpoint -q "$OLD/root/src/GrinSight/FlyClient/.tools" || { mount --bind /mnt/c/DHW/GrinSight/FlyClient/.tools "$OLD/root/src/GrinSight/FlyClient/.tools"; mount -o remount,bind,ro "$OLD/root/src/GrinSight/FlyClient/.tools"; }
cleanup() { umount "$OLD/root/src/GrinSight/FlyClient/.tools" 2>/dev/null || true; umount "$OLD/dev" 2>/dev/null || true; umount "$OLD/proc" 2>/dev/null || true; }
trap cleanup EXIT

if [ ! -x "$OLD/root/.cargo/bin/cargo" ]; then
  say "tools in the Debian 10 root"
  chroot "$OLD" bash -c 'set -e; export DEBIAN_FRONTEND=noninteractive
    echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends build-essential pkg-config curl ca-certificates dpkg-dev file \
      libfontconfig1-dev libfreetype6-dev libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libgl1-mesa-dev libegl1-mesa-dev clang >/dev/null
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.99.1 >/dev/null'
fi
chroot "$OLD" bash -c 'ldd --version | head -1; /root/.cargo/bin/rustc --version'

say "copying the candidate sources from $SOURCE"
SRC="$OLD/root/src/grinsight-release"
mkdir -p "$SRC"
rsync -a --delete --exclude '/target*' --exclude '/vendor-crates' --exclude '/ui/vendor-crates' \
  --exclude '/transport/vendor-sets' --exclude '/*.log' --exclude '/logs/' --exclude '/points-out/' "$SOURCE/" "$SRC/"
# Use the offline registries already prepared in this build root. On a new
# builder copy the registries provided with the source distribution instead.
for dir in vendor-crates ui/vendor-crates transport/vendor-sets; do
  if [[ ! -e "$SRC/$dir" && ! -L "$SRC/$dir" ]]; then
    if [[ -d "$OLD/root/src/core-v0.2/$dir" ]]; then
      ln -s "/root/src/core-v0.2/$dir" "$SRC/$dir"
    else
      mkdir -p "$SRC/$dir"
      rsync -aL "$SOURCE/$dir/" "$SRC/$dir/"
    fi
  fi
done

say "building (glibc 2.28)"
chroot "$OLD" bash -c 'set -e; export PATH=/root/.cargo/bin:$PATH CARGO_TARGET_DIR=/root/target
  b() { t=$SECONDS; (cd "/root/src/grinsight-release/$1" && shift && cargo build --release --locked --offline -q "$@"); echo "  built in $((SECONDS - t)) s"; }
  b paycore/host --bin fly-paycore-host
  b chain/fly-chain --bin fly-chain
  b transport/mailbox-nostr --bin fly-mailbox
  b onion --bin fly-onion
  if [[ $1 == core ]]; then exit 0; fi
  CARGO_TARGET_DIR=/root/target-ui b ui/app --bin fly-ui' bash "$PHASE"
if [[ $PHASE == core ]]; then say "core phase complete"; exit 0; fi

say "scenario on Debian 10 (the oldest system)"
chroot "$OLD" bash -c 'set -euo pipefail; T=$(mktemp -d); trap '\''rm -rf "$T"'\'' EXIT; /root/target-ui/release/fly-ui --scenario "$T/out" --host /root/target/release/fly-paycore-host --profile "$T/p" --guard-dir "$T/g" | tail -1'

# ---- one fresh tree for every package
PACK_WORK=$(mktemp -d /tmp/grinsight-linux-package.XXXXXXXX)
trap 'cleanup; rm -rf -- "$PACK_WORK"' EXIT
TREE="$PACK_WORK/tree"
mkdir "$TREE"
LIB=/usr/lib/grinsight-light
install -D -m755 "$OLD/root/target-ui/release/fly-ui" "$TREE$LIB/fly-ui"
for p in fly-paycore-host fly-chain fly-mailbox fly-onion; do install -D -m755 "$OLD/root/target/release/$p" "$TREE$LIB/bin/$p"; done
strip "$TREE$LIB/fly-ui" "$TREE$LIB/bin/"*
# The program for Tor bridges is not built here: the lyrebird of the official Tor Expert
# Bundle. Its SHA-256 is the one of the list of checksums signed by the Tor Browser
# developers (checked when the Windows package is made: get-tor-bridge-programs.ps1).
PT_VER=16.0.1
PT=tor-expert-bundle-linux-x86_64-$PT_VER.tar.gz
PT_SUM=7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725
[ -f "/root/$PT" ] || curl -fsSL -o "/root/$PT" "https://dist.torproject.org/torbrowser/$PT_VER/$PT"
echo "$PT_SUM  /root/$PT" | sha256sum -c - || { say "the Tor Expert Bundle was not accepted"; exit 1; }
mkdir -p "$PACK_WORK/pt" && tar -xzf "/root/$PT" -C "$PACK_WORK/pt"
install -D -m755 "$PACK_WORK/pt/tor/pluggable_transports/lyrebird" "$TREE$LIB/bin/lyrebird"
install -D -m644 "$PACK_WORK/pt/docs/lyrebird.txt" "$TREE/usr/share/doc/grinsight-light/LICENSE-lyrebird.txt"
say "lyrebird: $(sha256sum "$TREE$LIB/bin/lyrebird" | cut -c1-16) $(stat -c %s "$TREE$LIB/bin/lyrebird") bytes"
mkdir -p "$TREE/usr/bin"
cat > "$TREE/usr/bin/grinsight-light" <<'SH'
#!/bin/sh
# GrinSight: the window and the wallet's programs. The wallet lives in
# ~/.local/share/grinsight-light/profile; the guard against rollback in
# ~/.local/state/grinsight-light/guard (the wallet process's default).
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/grinsight-light"
LIB=/usr/lib/grinsight-light
exec "$LIB/fly-ui" --host "$LIB/bin/fly-paycore-host" --profile "$DATA/profile" \
  --chain "$LIB/bin/fly-chain" --onion "$LIB/bin/fly-onion" --transport "$LIB/bin/fly-mailbox" --relay wss://relay.floonet.dev "$@"
SH
chmod 755 "$TREE/usr/bin/grinsight-light"
install -D -m644 "$SRC/ui/app/images/icon.png" "$TREE/usr/share/pixmaps/grinsight-light.png"
mkdir -p "$TREE/usr/share/applications" "$TREE/usr/share/doc/grinsight-light" "$TREE/usr/share/licenses/grinsight-light"
cat > "$TREE/usr/share/applications/grinsight-light.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=GrinSight
Comment=Grin wallet
Comment[ru]=Кошелёк Grin
Exec=grinsight-light
Icon=grinsight-light
Terminal=false
Categories=Office;Finance;
DESK
cp "$SRC/dist-files/LICENSE-GPL-3.0.txt" "$TREE/usr/share/licenses/grinsight-light/LICENSE-GPL-3.0.txt"
for font in Inter DejaVu WalletCJK; do
  install -m644 "$SRC/ui/app/fonts/LICENSE-$font.txt" "$TREE/usr/share/licenses/grinsight-light/"
done
printf 'GrinSight\nThe interface (fly-ui) is distributed under the GNU General Public License,\nversion 3 only; the text is in /usr/share/licenses/grinsight-light/.\n' > "$TREE/usr/share/doc/grinsight-light/copyright"
OUT="$PACK_WORK/out" && mkdir "$OUT"

# ---- .deb (dependencies as Debian 10 names them: the lowest versions)
DEB="$OUT/grinsight-light_${VER}~${STAMP}_amd64.deb"
D="$PACK_WORK/debroot" && cp -a "$TREE" "$D" && mkdir -p "$D/DEBIAN"
DEPS=$(chroot "$OLD" bash -c 'set -e; w=$(mktemp -d); trap '\''rm -rf "$w"'\'' EXIT; cd "$w"; mkdir debian; touch debian/control; dpkg-shlibdeps -O -e /root/target-ui/release/fly-ui -e /root/target/release/fly-paycore-host -e /root/target/release/fly-chain -e /root/target/release/fly-mailbox -e /root/target/release/fly-onion 2>/dev/null' | sed -n 's/^shlibs:Depends=//p')
[ -n "$DEPS" ] || { say 'No ELF dependency metadata'; exit 1; }
cat > "$D/DEBIAN/control" <<CTRL
Package: grinsight-light
Version: ${VER}~${STAMP}
Architecture: amd64
Maintainer: GrinSight <grinsight@localhost>
Installed-Size: $(du -sk "$D/usr" | cut -f1)
Depends: $DEPS
Recommends: libxkbcommon-x11-0, libwayland-client0, libgl1 | libgl1-mesa-glx, libegl1 | libegl1-mesa
Section: utils
Priority: optional
Description: GrinSight — Grin wallet
 A Grin wallet that checks the chain itself (public nodes of several
 operators, its own Tor) and keeps keys in a separate process from the window.
CTRL
dpkg-deb --build --root-owner-group "$D" "$DEB" >/dev/null
say "deb: $(basename "$DEB") — Depends: $DEPS"

# ---- .rpm (requirements found by rpm itself from the programs)
R="$PACK_WORK/rpmbuild" && mkdir -p "$R"/{SPECS,BUILD,RPMS,SOURCES,SRPMS,BUILDROOT}
cat > "$R/SPECS/grinsight-light.spec" <<SPEC
Name: grinsight-light
Version: $VER
Release: $REL
Summary: GrinSight — Grin wallet
License: GPL-3.0-only
BuildArch: x86_64
AutoReqProv: yes
Recommends: libxkbcommon-x11, libwayland-client, mesa-libGL, mesa-libEGL
%description
A Grin wallet that checks the chain itself (public nodes of several
operators, its own Tor) and keeps keys in a separate process from the window.
%install
mkdir -p %{buildroot}
cp -a $TREE/. %{buildroot}/
%files
/usr/bin/grinsight-light
/usr/lib/grinsight-light
/usr/share/applications/grinsight-light.desktop
/usr/share/pixmaps/grinsight-light.png
/usr/share/doc/grinsight-light
/usr/share/licenses/grinsight-light
SPEC
rpmbuild --define "_topdir $R" --define "_build_id_links none" --define "debug_package %{nil}" --define "__strip /bin/true" -bb "$R/SPECS/grinsight-light.spec" >/dev/null 2>&1 || { rpmbuild --define "_topdir $R" --define "_build_id_links none" --define "debug_package %{nil}" -bb "$R/SPECS/grinsight-light.spec" 2>&1 | tail -20; exit 1; }
RPM=$(ls "$R"/RPMS/x86_64/*.rpm)
cp "$RPM" "$OUT/"
say "rpm: $(basename "$RPM")"
rpm -qpR "$RPM" 2>/dev/null | grep -v '^rpmlib' | sed 's/^/  requires: /'

# ---- .tar.gz and PKGBUILD (Arch; the archive also works by hand anywhere)
TGZ="grinsight-light-${VER}.${STAMP//-/.}-x86_64.tar.gz"
tar -C "$TREE" --owner=0 --group=0 -czf "$OUT/$TGZ" usr
SUM=$(sha256sum "$OUT/$TGZ" | cut -d' ' -f1)
cat > "$OUT/PKGBUILD" <<PKG
# Maintainer: GrinSight
# Installs the prebuilt GrinSight (built against glibc 2.28) from the archive next to this file.
pkgname=grinsight-light-bin
pkgver=${VER}.${STAMP//-/.}
pkgrel=1
pkgdesc="GrinSight — Grin wallet"
arch=('x86_64')
license=('GPL-3.0-only')
depends=('glibc' 'gcc-libs' 'fontconfig')
optdepends=('libxkbcommon-x11: X11 keyboard' 'wayland: Wayland' 'libglvnd: OpenGL')
provides=('grinsight-light')
conflicts=('grinsight-light')
source=("$TGZ")
sha256sums=('$SUM')
package() {
  cp -a "\$srcdir/usr" "\$pkgdir/"
}
PKG
say "arch: $TGZ + PKGBUILD"

# Exercise the packaged ELF files, without replacing an installed copy.
dpkg-deb --extract "$DEB" "$PACK_WORK/deb-check"
mkdir -p "$PACK_WORK/rpm-check" "$PACK_WORK/tar-check"
(cd "$PACK_WORK/rpm-check" && rpm2cpio "$RPM" | cpio --quiet -id)
tar -xzf "$OUT/$TGZ" -C "$PACK_WORK/tar-check"
for dir in deb-check rpm-check tar-check; do
  diff -qr "$TREE/usr" "$PACK_WORK/$dir/usr"
done
T="$PACK_WORK/scenario" && mkdir "$T"
app="$PACK_WORK/deb-check$LIB"
"$app/fly-ui" --scenario "$T/out" --host "$app/bin/fly-paycore-host" --profile "$T/p" --guard-dir "$T/g" | tail -1

DEST=/mnt/c/DHW/dist/linux-$VER-$STAMP
mkdir -p "$DEST"
cp "$OUT"/* "$DEST/"
(cd "$DEST" && sha256sum * > SHA256SUMS.txt && cat SHA256SUMS.txt)
say "done: $DEST"

#!/usr/bin/env bash
# Build an Arch Linux package without makepkg.
#
# Expects VERSION, PKG_ARCH and BINARY in the environment and runs from the
# repository root. Run it under fakeroot so the files are recorded as owned by
# root, matching what makepkg produces.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${PKG_ARCH:?PKG_ARCH is required}"
: "${BINARY:?BINARY is required}"

ROOT="pkg-arch"
rm -rf "$ROOT"
mkdir -p "$ROOT/usr/bin" "$ROOT/usr/share/licenses/subdive"
install -m 0755 "$BINARY" "$ROOT/usr/bin/subdive"
install -m 0644 LICENSE "$ROOT/usr/share/licenses/subdive/LICENSE"

# fakeroot records this as root:root without needing real privileges.
chown -R 0:0 "$ROOT"

SIZE="$(du -sb "$ROOT/usr" | cut -f1)"
{
  echo "pkgname = subdive"
  echo "pkgbase = subdive"
  echo "pkgver = ${VERSION}-1"
  echo "pkgdesc = Deep subdomain enumeration with DNS-over-HTTPS fallback"
  echo "url = https://github.com/konanguyen/subdive"
  echo "builddate = $(date +%s)"
  echo "packager = konanguyen <ng.hao2711@gmail.com>"
  echo "size = ${SIZE}"
  echo "arch = ${PKG_ARCH}"
  echo "license = MIT"
  echo "depend = ca-certificates"
  echo "xdata = pkgtype=pkg"
} > "$ROOT/.PKGINFO"

bsdtar -czf "$ROOT/.MTREE" --format=mtree \
  --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
  -C "$ROOT" .PKGINFO usr

bsdtar -cf - -C "$ROOT" .PKGINFO .MTREE usr \
  | zstd -c -T0 -19 > "subdive-${VERSION}-1-${PKG_ARCH}.pkg.tar.zst"

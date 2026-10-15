#!/usr/bin/env bash
# Build a Debian/Ubuntu source package (for a Launchpad PPA) from a release tag.
#
#   packaging/debian/build-source.sh 0.1.0 noble [ppa-revision]
#
# Produces ../build-deb/eyalsec-cli_<ver>-<rev>.dsc, .orig.tar.gz, .debian.tar.xz
# and _source.changes. Sign and upload with:
#   debsign -k <your key id> ../build-deb/*_source.changes
#   dput ppa:<launchpad-user>/eyalsec ../build-deb/*_source.changes
# Needs: devscripts, debhelper, dpkg-dev, git (and golang-go to also build binaries).
set -euo pipefail

version=${1:?usage: $0 VERSION SERIES [REVISION]}
series=${2:?usage: $0 VERSION SERIES [REVISION]}
rev=${3:-1}
here=$(cd "$(dirname "$0")/../.." && pwd)
out="$here/../build-deb"
rm -rf "$out"
mkdir -p "$out"

# The upstream tarball is exactly the tagged tree.
git -C "$here" archive --format=tar.gz --prefix="eyalsec-cli-$version/" -o "$out/eyalsec-cli_$version.orig.tar.gz" "v$version" 2>/dev/null \
  || git -C "$here" archive --format=tar.gz --prefix="eyalsec-cli-$version/" -o "$out/eyalsec-cli_$version.orig.tar.gz" HEAD
tar -C "$out" -xzf "$out/eyalsec-cli_$version.orig.tar.gz"
cp -r "$here/packaging/debian" "$out/eyalsec-cli-$version/debian"
rm -f "$out/eyalsec-cli-$version/debian/build-source.sh"

pkgver="$version-${rev}"
if [ "$series" != "unstable" ]; then
  pkgver="$version-${rev}~${series}1"
fi
cd "$out/eyalsec-cli-$version"
sed -i "1s/^eyalsec-cli ([^)]*) [a-z-]*;/eyalsec-cli ($pkgver) $series;/" debian/changelog
dpkg-buildpackage -S -sa -us -uc -d
echo
echo "Source package ready in $out:"
ls -1 "$out"

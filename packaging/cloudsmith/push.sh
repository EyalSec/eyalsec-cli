#!/usr/bin/env bash
# Upload one release's .deb and .rpm packages to a Cloudsmith repository.
#
#   CLOUDSMITH_API_KEY=... packaging/cloudsmith/push.sh 0.1.0 [owner/repo]
#
# Needs the Cloudsmith CLI (pip install cloudsmith-cli) and the GitHub CLI (gh).
# "any-distro/any-version" publishes one package for every Debian/Ubuntu and
# every RPM distribution: the binary is static, so one build fits them all.
set -euo pipefail

version=${1:?usage: $0 VERSION [OWNER/REPO]}
repo=${2:-eyalsec/eyalsec-cli}
: "${CLOUDSMITH_API_KEY:?set CLOUDSMITH_API_KEY (Cloudsmith > User settings > API key)}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "v$version" --repo EyalSec/eyalsec-cli --dir "$work" \
  --pattern '*.deb' --pattern '*.rpm' --pattern checksums.txt
(cd "$work" && sha256sum --ignore-missing -c checksums.txt)

for f in "$work"/*.deb; do
  cloudsmith push deb "$repo/any-distro/any-version" "$f"
done
for f in "$work"/*.rpm; do
  cloudsmith push rpm "$repo/any-distro/any-version" "$f"
done

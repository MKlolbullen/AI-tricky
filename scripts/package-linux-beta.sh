#!/usr/bin/env bash
# Package the standalone app and source installer for the pinned Linux scanners.
set -Eeuo pipefail
cd -- "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
  echo 'Build the Linux beta on x86-64 Linux.' >&2
  exit 2
fi
if [[ ! -x dist-bin/ai-tricky ]]; then
  echo 'Build the standalone binary first using scripts/build-binary.sh.' >&2
  exit 2
fi
name=ai-tricky-linux-amd64-beta
stage="$(mktemp -d dist-bin/.beta.XXXXXXXX)"
trap 'rm -rf -- "$stage"' EXIT
root="$stage/$name"
mkdir -p "$root/scripts" "$root/backend" "$root/integrations/cli-scope" "$root/docs"
cp dist-bin/ai-tricky LICENSE THIRD_PARTY_NOTICES.md "$root/"
cp scripts/install-tools.sh scripts/check-recon-tools.py "$root/scripts/"
cp backend/__init__.py backend/recon_tools.py "$root/backend/"
cp -R toolchains "$root/"
cp integrations/cli-scope/relay.go "$root/integrations/cli-scope/"
cp docs/SCANNER-PROFILES.md "$root/docs/"
tar -C "$stage" -czf "$stage/$name.tar.gz" "$name"
mv -- "$stage/$name.tar.gz" dist-bin/
(cd dist-bin && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")

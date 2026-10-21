#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Installs PantherClaw's binaries from a GitHub release (G0 M13 D36,
# PN-012.6) on Linux or macOS, after checking them:
#   1. the archive's SHA-256 must match its line in the release's
#      checksums.txt, or nothing is installed;
#   2. with the GitHub CLI (gh) installed, the archive's build provenance
#      attestation must verify (`gh attestation verify --repo
#      katocxl/pantherclaw`), or nothing is installed; without gh the script
#      prints the command to run by hand.
#
#   curl -fsSLO https://raw.githubusercontent.com/katocxl/pantherclaw/main/install.sh
#   sh install.sh [--version vX.Y.Z] [--dir DIR] [--all]
#
# --version   the release tag (default: the latest release)
# --dir       where the binaries go (default: $HOME/.local/bin)
# --all       install every binary in the archive, not only pclaw
#
# Windows: download the .zip and checksums.txt from the release page and
# check them the same way (Get-FileHash, gh attestation verify).
set -eu

REPO=katocxl/pantherclaw
BASE_URL=${PANTHERCLAW_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}
LATEST_URL=${PANTHERCLAW_LATEST_URL:-https://api.github.com/repos/$REPO/releases/latest}
GH=${PANTHERCLAW_GH:-gh}
version=${PANTHERCLAW_VERSION:-}
dir=${PANTHERCLAW_INSTALL_DIR:-$HOME/.local/bin}
all=0

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case $1 in
    --version) [ $# -ge 2 ] || die "--version needs a tag"; version=$2; shift 2 ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a directory"; dir=$2; shift 2 ;;
    --all) all=1; shift ;;
    -h|--help) sed -n '5,23p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

fetch() { # url file
  if command -v curl > /dev/null 2>&1; then
    curl -fsSL --proto '=https,http' -o "$2" "$1"
  elif command -v wget > /dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "needs curl or wget"
  fi
}

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "needs sha256sum or shasum"
  fi
}

# PANTHERCLAW_OS and PANTHERCLAW_ARCH override the detection (tests).
case ${PANTHERCLAW_OS:-$(uname -s)} in
  Linux|linux) os=linux ;;
  Darwin|darwin) os=darwin ;;
  *) die "unsupported system $(uname -s); on Windows download the .zip from https://github.com/$REPO/releases" ;;
esac
case ${PANTHERCLAW_ARCH:-$(uname -m)} in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -z "$version" ]; then
  fetch "$LATEST_URL" "$tmp/latest.json"
  version=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -1)
  [ -n "$version" ] || die "could not read the latest release's tag"
fi
case $version in
  v[0-9]*) ;;
  *) die "--version must be a tag like v1.0.0" ;;
esac

archive="pantherclaw_${version#v}_${os}_${arch}.tar.gz"
echo "Downloading $archive ($version)"
fetch "$BASE_URL/$version/checksums.txt" "$tmp/checksums.txt"
fetch "$BASE_URL/$version/$archive" "$tmp/$archive"

# 1. SHA-256 against exactly one line of checksums.txt.
lines=$(awk -v f="$archive" '$2 == f || $2 == "*" f' "$tmp/checksums.txt" | wc -l | tr -d ' ')
[ "$lines" = 1 ] || die "checksums.txt has $lines entries for $archive (want 1); nothing installed"
want=$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1}' "$tmp/checksums.txt")
got=$(sha256 "$tmp/$archive")
[ "$got" = "$want" ] || die "SHA-256 mismatch for $archive (got $got, checksums.txt says $want); nothing installed"
echo "SHA-256 matches checksums.txt"

# 2. Build provenance attestation.
if command -v "$GH" > /dev/null 2>&1; then
  "$GH" attestation verify "$tmp/$archive" --repo "$REPO" > "$tmp/attestation.log" 2>&1 ||
    { cat "$tmp/attestation.log" >&2; die "the attestation of $archive does not verify; nothing installed"; }
  echo "Attestation verified (built by $REPO's release workflow)"
else
  echo "The GitHub CLI (gh) is not installed, so the attestation was not checked. To check it, download the archive and run:"
  echo "  gh attestation verify $archive --repo $REPO"
fi

mkdir -p "$tmp/x"
tar -xzf "$tmp/$archive" -C "$tmp/x"
mkdir -p "$dir"
if [ "$all" = 1 ]; then
  bins="pclaw pantherclaw-server pantherclaw-gateway pantherclaw-sim pclaw-admin pantherclaw-edge pantherclaw-probe"
else
  bins=pclaw
fi
installed=""
for b in $bins; do
  [ -f "$tmp/x/$b" ] || continue
  cp "$tmp/x/$b" "$dir/$b.new"
  chmod 0755 "$dir/$b.new"
  mv "$dir/$b.new" "$dir/$b"
  installed="$installed $b"
done
[ -n "$installed" ] || die "no binaries found in $archive"
echo "Installed$installed to $dir"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH." ;;
esac
echo "Next: pclaw up (docs/quickstart.md)"

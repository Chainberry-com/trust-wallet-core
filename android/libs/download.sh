#!/usr/bin/env bash
# Re-vendors com.trustwallet:wallet-core (+ its wallet-core-proto dependency)
# from GitHub Packages into this directory, laid out as a plain local Maven
# repo (com/<group>/<artifact>/<version>/...). build.gradle points at this
# directory first, so a normal build needs no GitHub credentials — only
# re-running this script (to bump the pinned version, or the first time
# someone sets this up) needs a token.
#
# Usage:
#   GITHUB_ACTOR=you GITHUB_TOKEN=ghp_xxx ./download.sh 4.1.19
# or rely on gpr.user / gpr.key in ~/.gradle/gradle.properties (same
# credentials used by build.gradle's GitHub Packages fallback).
set -euo pipefail

VERSION="${1:?Usage: download.sh <wallet-core version, e.g. 4.1.19>}"
LIBS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GITHUB_USER="${GITHUB_ACTOR:-}"
GITHUB_PASS="${GITHUB_TOKEN:-}"
if [ -z "$GITHUB_USER" ] || [ -z "$GITHUB_PASS" ]; then
  GRADLE_PROPS="$HOME/.gradle/gradle.properties"
  if [ -f "$GRADLE_PROPS" ]; then
    GITHUB_USER="${GITHUB_USER:-$(grep '^gpr.user=' "$GRADLE_PROPS" | cut -d= -f2-)}"
    GITHUB_PASS="${GITHUB_PASS:-$(grep '^gpr.key='  "$GRADLE_PROPS" | cut -d= -f2-)}"
  fi
fi
if [ -z "$GITHUB_USER" ] || [ -z "$GITHUB_PASS" ]; then
  echo "error: no GitHub credentials found (env vars or ~/.gradle/gradle.properties gpr.user/gpr.key)" >&2
  exit 1
fi

REGISTRY="https://maven.pkg.github.com/trustwallet/wallet-core"

# module:packaging pairs — wallet-core is an .aar, wallet-core-proto is a plain .jar
MODULES=("wallet-core:aar" "wallet-core-proto:jar")

for entry in "${MODULES[@]}"; do
  artifact="${entry%%:*}"
  ext="${entry##*:}"
  dest="$LIBS_DIR/com/trustwallet/$artifact/$VERSION"
  mkdir -p "$dest"
  base="$REGISTRY/com/trustwallet/$artifact/$VERSION"
  for file in "$artifact-$VERSION.pom" "$artifact-$VERSION.$ext" "$artifact-$VERSION.pom.sha1" "$artifact-$VERSION.$ext.sha1"; do
    echo "fetching $file"
    curl -sS -L -f -u "$GITHUB_USER:$GITHUB_PASS" -o "$dest/$file" "$base/$file"
  done
  # verify what we just wrote against GitHub's own sha1
  ( cd "$dest" && sha1sum -c "$artifact-$VERSION.pom.sha1" "$artifact-$VERSION.$ext.sha1" )
done

echo "done — vendored wallet-core $VERSION into $LIBS_DIR"
echo "remember to bump the version in ../build.gradle (dependencies block) and the podspec, and delete the old version's directories above if this is a version bump rather than a first-time vendor."

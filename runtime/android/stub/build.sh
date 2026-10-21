#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here}"
android_jar="${ANDROID_JAR:?set ANDROID_JAR to a platform android.jar (API 31 or newer)}"
d8="${D8:-d8}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

javac -source 8 -target 8 -bootclasspath "$android_jar" -Xlint:-options -d "$work/classes" \
  "$here/co/ostorlab/rasp/RaspStub.java"

"$d8" --release --min-api 31 --lib "$android_jar" --output "$work" \
  "$work"/classes/co/ostorlab/rasp/*.class

mkdir -p "$out"
mv "$work/classes.dex" "$out/stub.dex"
echo "wrote $out/stub.dex"

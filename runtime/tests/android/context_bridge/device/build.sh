#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?output directory}"
bridge="${2:?runtime-bridge-compile-only.jar from stub build}"
jar="${ANDROID_JAR:?set ANDROID_JAR}"
tools="${ANDROID_BUILD_TOOLS:?set ANDROID_BUILD_TOOLS}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mapfile -t sources < <(find "$here/src" -name '*.java' | sort)
javac -source 8 -target 8 -Xlint:-options -bootclasspath "$jar" -classpath "$bridge" \
  -d "$work/classes" "${sources[@]}"
mapfile -t classes < <(find "$work/classes" -name '*.class' | sort)
"$tools/d8" --release --min-api 31 --lib "$jar" --classpath "$bridge" --output "$work" "${classes[@]}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
"$tools/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/host-unsigned.apk"
(cd "$work" && zip -q "$out/host-unsigned.apk" classes.dex)

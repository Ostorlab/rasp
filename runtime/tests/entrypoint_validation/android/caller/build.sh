#!/usr/bin/env bash
# Actual SDK unsigned caller; no keys, signatures, installs or domain verification.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?task output}; jar=${ANDROID_JAR:?SDK jar}; tools=${ANDROID_BUILD_TOOLS:?build tools}
mkdir -p "$out/classes";out=$(cd "$out" && pwd)
mapfile -t sources < <(rg --files "$here/src" -g '*.java' | sort)
javac -source 8 -target 8 -Xlint:-options -bootclasspath "$jar" -d "$out/classes" "${sources[@]}"
mapfile -t classes < <(rg --files "$out/classes" -g '*.class' | sort)
"$tools/d8" --release --min-api 31 --lib "$jar" --output "$out" "${classes[@]}"
"$tools/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/caller-unsigned.apk"
(cd "$out" && zip -q caller-unsigned.apk classes.dex)

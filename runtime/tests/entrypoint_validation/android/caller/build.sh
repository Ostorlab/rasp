#!/usr/bin/env bash
# Actual SDK unsigned caller; no keys, signatures, installs or domain verification.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?task output}; jar=${ANDROID_JAR:?SDK jar}; tools=${ANDROID_BUILD_TOOLS:?build tools}
mkdir -p "$out/classes";out=$(cd "$out" && pwd)
find "$here/src" -type f -name '*.java' | LC_ALL=C sort > "$out/sources.list"
mapfile -t sources < "$out/sources.list"
[[ ${#sources[@]} -gt 0 ]] || { printf '%s\n' 'No Java sources found' >&2; exit 1; }
javac -source 8 -target 8 -Xlint:-options -bootclasspath "$jar" -d "$out/classes" "${sources[@]}"
find "$out/classes" -type f -name '*.class' | LC_ALL=C sort > "$out/classes.list"
mapfile -t classes < "$out/classes.list"
[[ ${#classes[@]} -gt 0 ]] || { printf '%s\n' 'No compiled Java classes found' >&2; exit 1; }
rm -f "$out/classes.dex"
"$tools/d8" --release --min-api 31 --lib "$jar" --output "$out" "${classes[@]}"
[[ -s "$out/classes.dex" ]] || { printf '%s\n' 'No nonempty classes.dex produced' >&2; exit 1; }
"$tools/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/caller-unsigned.apk"
(cd "$out" && zip -q caller-unsigned.apk classes.dex)

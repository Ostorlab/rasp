#!/usr/bin/env bash
# Build real SDK source APK and proto-manifest AAB; unsigned, no installation or caller proof.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
runtime=$(cd "$here/../../../.." && pwd)
out=${1:?task output}; bridge=${2:?compile-only bridge}
jar=${ANDROID_JAR:?actual SDK jar}; tools=${ANDROID_BUILD_TOOLS:?actual build tools}
mkdir -p "$out/classes" "$out/aab/base/manifest" "$out/aab/base/dex"
out=$(cd "$out" && pwd)
find "$here/src" -type f -name '*.java' | LC_ALL=C sort > "$out/sources.list"
mapfile -t sources < "$out/sources.list"
[[ ${#sources[@]} -gt 0 ]] || { printf '%s\n' 'No Java sources found' >&2; exit 1; }
javac -source 8 -target 8 -Xlint:-options -bootclasspath "$jar" -classpath "$bridge" -d "$out/classes" \
  "${sources[@]}" "$runtime/entrypoint_validation/android/co/ostorlab/rasp/entry/EntryPointValidation.java" \
  "$runtime/host_context/android/co/ostorlab/rasp/host/HostOperationContext.java"
find "$out/classes" -type f -name '*.class' | LC_ALL=C sort > "$out/classes.list"
mapfile -t classes < "$out/classes.list"
[[ ${#classes[@]} -gt 0 ]] || { printf '%s\n' 'No compiled Java classes found' >&2; exit 1; }
rm -f "$out/classes.dex"
if [[ -n "${R8_JAR:-}" ]]; then
  java -cp "$R8_JAR" com.android.tools.r8.R8 --release --min-api 31 --lib "$jar" --classpath "$bridge" \
    --pg-conf "$here/fixture-rules.pro" --pg-map-output "$out/r8-map.txt" --output "$out" "${classes[@]}"
else
  "$tools/d8" --release --min-api 31 --lib "$jar" --classpath "$bridge" --output "$out" "${classes[@]}"
fi
[[ -s "$out/classes.dex" ]] || { printf '%s\n' 'No nonempty classes.dex produced' >&2; exit 1; }
"$tools/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/host-unsigned.apk"
(cd "$out" && zip -q host-unsigned.apk classes.dex)
"$tools/aapt2" link --proto-format -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/proto.apk"
unzip -p "$out/proto.apk" AndroidManifest.xml > "$out/aab/base/manifest/AndroidManifest.xml"
cp "$out/classes.dex" "$out/aab/base/dex/classes.dex"
# Empty default protobuf message: structural AAB fixture, not bundletool/store certification.
: > "$out/aab/BundleConfig.pb"
(cd "$out/aab" && zip -q -r "$out/host-unsigned.aab" BundleConfig.pb base)

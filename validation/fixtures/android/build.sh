#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?new output directory}"
bridge="${2:?matching production compile-only bridge jar}"
policy="${3:?actual production Android example policy}"
python="${PACKER_PYTHON:?pinned installed packer interpreter}"
jar="${ANDROID_JAR:?API35-or-newer public SDK jar}"
tools="${ANDROID_BUILD_TOOLS:?pinned SDK build-tools directory}"
test ! -e "$out"
mkdir -m 700 "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d "$out/work.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/res/values" "$work/generated" "$work/classes"
printf '%s\n' '<resources><item type="id" name="status"/></resources>' > "$work/res/values/ids.xml"
"$tools/aapt2" compile --dir "$work/res" -o "$work/resources.zip"
"$tools/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" --java "$work/generated" \
  -o "$out/host-unsigned.apk" "$work/resources.zip"
"$python" -I -B - "$policy" "$work/generated/fixture/validation/ExpectedPolicy.java" "$out/policy-sha256.txt" <<'PY'
import importlib.metadata
import pathlib
import sys
from rasp_packer import local_policy
importlib.metadata.distribution("rasp-packer")
policy = local_policy.load(pathlib.Path(sys.argv[1]))
pathlib.Path(sys.argv[2]).write_text('package fixture.validation; final class ExpectedPolicy { static final String SHA256 = "' + policy.sha256 + '"; }\n')
pathlib.Path(sys.argv[3]).write_text(policy.sha256 + '\n')
PY
cp "$work/generated/fixture/validation/ExpectedPolicy.java" "$out/ExpectedPolicy.java"
javac -source 8 -target 8 -Xlint:-options -bootclasspath "$jar" -classpath "$bridge" -d "$work/classes" \
  "$work/generated/fixture/validation/R.java" "$work/generated/fixture/validation/ExpectedPolicy.java" "$here/MainActivity.java"
mapfile -t classes < <(find "$work/classes" -name '*.class' | sort)
"$tools/d8" --release --min-api 31 --lib "$jar" --classpath "$bridge" --output "$work" "${classes[@]}"
(cd "$work" && zip -q "$out/host-unsigned.apk" classes.dex)
chmod 600 "$out/host-unsigned.apk" "$out/ExpectedPolicy.java" "$out/policy-sha256.txt"

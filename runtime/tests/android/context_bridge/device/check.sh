#!/usr/bin/env bash
set -euo pipefail
apk="${1:?signed protected APK with development runtime}"
adb="${ADB:-adb}"
"$adb" install -r "$apk"
"$adb" logcat -c
"$adb" shell am force-stop fixture.contextbridge
"$adb" shell am start -W -n fixture.contextbridge/.MainActivity
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
# Capture at least the second 60-second monitor pass; timeout is expected on a running app.
result=0
timeout 80 "$adb" logcat -v monotonic -s RaspRuntime:I ContextBridgeFixture:I AndroidRuntime:E > "$log" || result=$?
if [[ "$result" != 0 && "$result" != 124 ]]; then cat "$log"; exit "$result"; fi
cat "$log"
python3 - "$log" <<'PY'
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
marker = next(index for index, line in enumerate(lines) if "initialized after attachment" in line)
assert any("sig.cert_sha256/package_manager ok" in line for line in lines[marker + 1:]), "no supported signer measurement after initialization"
assert all("FATAL EXCEPTION" not in line for line in lines), "fixture crashed"
PY

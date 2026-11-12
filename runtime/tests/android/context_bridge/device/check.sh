#!/usr/bin/env bash
set -euo pipefail
apk="${1:?signed protected APK with development runtime}"
mode="${2:-context}"
adb="${ADB:-adb}"
"$adb" install -r "$apk"
"$adb" logcat -c
"$adb" shell am force-stop fixture.contextbridge
"$adb" shell am start -W -n fixture.contextbridge/.MainActivity
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
# Capture at least the second 60-second monitor pass; timeout is expected on a running app.
result=0
timeout 80 "$adb" logcat -v monotonic -s RaspRuntime:I ContextBridgeFixture:I WindowBridgeFixture:I AndroidRuntime:E > "$log" || result=$?
if [[ "$result" != 0 && "$result" != 124 ]]; then cat "$log"; exit "$result"; fi
cat "$log"
python3 - "$log" "$mode" <<'PY'
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
marker = next(index for index, line in enumerate(lines) if "initialized after attachment" in line)
assert any("sig.cert_sha256/package_manager ok" in line for line in lines[marker + 1:]), "no supported signer measurement after initialization"
if sys.argv[2] == "--windows":
    assert any("active window attached" in line for line in lines), "no attached window"
    assert any("overlay.observer_state/window_callback ok active" in line for line in lines[marker + 1:]), "no active observer"
    assert any("overlay.coverage/window_callback ok best_effort" in line for line in lines[marker + 1:]), "no best-effort window coverage"
    for signal in ("touch_events", "obscured_touch_events", "partially_obscured_touch_events", "dropped_events", "lost_windows", "invalid_events", "interval_ms", "active_windows"):
        assert any("overlay." + signal + "/window_callback ok " in line for line in lines[marker + 1:]), "missing " + signal
assert all("FATAL EXCEPTION" not in line for line in lines), "fixture crashed"
PY

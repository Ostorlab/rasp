#!/usr/bin/env bash
set -euo pipefail
apk="${1:?signed protected APK with development runtime}"
adb="${ADB:-adb}"
services="${2:-}"
if [[ -n "$services" && "$services" != --services && "$services" != --root-context ]]; then
  echo 'second argument must be --services or --root-context when checking opt-in metadata' >&2
  exit 2
fi
api="$("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
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
python3 - "$log" "$services" "$api" <<'PY'
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
marker = next(index for index, line in enumerate(lines) if "initialized after attachment" in line)
assert any("sig.cert_sha256/package_manager ok" in line for line in lines[marker + 1:]), "no supported signer measurement after initialization"
assert all("FATAL EXCEPTION" not in line for line in lines), "fixture crashed"
if sys.argv[2] == "--services":
    api = int(sys.argv[3])
    after_init = lines[marker + 1:]
    for identity in (
        "a11y.enabled_services/accessibility_manager",
        "ime.enabled_components/input_method_manager",
        "ime.current_component/input_method_manager",
        "notification.enabled_listeners/settings_secure",
    ):
        results = [line for line in after_init if identity + " " in line]
        assert len(results) > 0, "missing selected output: " + identity
        if identity.startswith("ime.current_component") and api < 34:
            assert all(identity + " unsupported" in line for line in results), "unguarded selected IME"
        print("Service metadata (inspect expected device state; error means unknown):", results[-1])
PY

if [[ "$services" == --root-context ]]; then
  python3 - "$log" <<'PY_CONTEXT'
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
marker = next(index for index, line in enumerate(lines) if "initialized after attachment" in line)
for identity in (
    "root.manager_packages_v1/package_manager",
    "root.mountinfo_context_v1/proc_self_mountinfo",
    "root.mount_namespace_v1/proc_self_ns_mnt",
    "net.default_proxy_v1/connectivity_manager",
    "debug.adb_enabled_v1/settings_global",
    "debug.developer_options_enabled_v1/settings_global",
):
    results = [line for line in lines[marker + 1:] if identity + " " in line]
    assert len(results) > 0, "missing selected output: " + identity
    if identity.startswith("debug."):
        assert all(identity + " unsupported" in line for line in results), "settings truth must remain unsupported"
    print("Root/environment context (compare device state; no verdict):", results[-1])
PY_CONTEXT
fi

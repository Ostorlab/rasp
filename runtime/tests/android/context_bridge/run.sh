#!/usr/bin/env bash
set -euo pipefail
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) echo "Context bridge runner requires a Linux or macOS host" >&2; exit 2 ;;
esac
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cmake --preset host -S "$runtime" -B "$work" "$@"
cmake --build "$work" --parallel 2 --target \
  rasp_android_context_bridge_jni rasp_android_service_jni rasp_android_context_bridge_java \
  rasp_android_application_context_test rasp_android_window_events_test \
  rasp_android_storage_jni rasp_android_private_storage_test
ctest --test-dir "$work" --parallel 2 --output-on-failure --no-tests=error \
  -R '^(AndroidWindowBridge[.]|WindowEvents[.]|AndroidContextBridge[.]|AndroidIdentity[.]|AndroidServiceExposure[.]|ApplicationContext[.]|AndroidPrivateStorage[.]|AndroidPrivateStorageVm[.])'

if [[ "$(uname -s)" == Darwin ]]; then
  cmake --build "$work" --parallel 2 --target rasp_ios_private_storage_test
  ctest --test-dir "$work" --parallel 2 --output-on-failure --no-tests=error -R '^ApplePrivateStorage[.]'
fi

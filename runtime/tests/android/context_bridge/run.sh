#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
jdk="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
"${CXX:-clang++}" -std=c++23 -shared -fPIC -pthread -fno-exceptions -fno-rtti \
  -Wall -Wextra -Werror -Wpedantic -I"$jdk/include" -I"$jdk/include/linux" -I"$runtime/android/src" \
  "$here/driver.cpp" "$runtime/android/src/util/application_context.cpp" \
  "$runtime/android/src/util/package_manager.cpp" "$runtime/android/src/util/jni.cpp" \
  -o "$work/libbridge_test.so"
mapfile -t sources < <(find "$here/java" -name '*.java' | sort)
javac -d "$work/classes" "$runtime/android/stub/co/ostorlab/rasp/RuntimeBridge.java" "${sources[@]}"
for mode in late early concurrent lifetime unavailable; do
  java -Xcheck:jni -cp "$work/classes" co.ostorlab.rasp.BridgeTest "$work/libbridge_test.so" "$mode"
done

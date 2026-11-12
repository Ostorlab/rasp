#!/bin/bash
# Actual Apple toolchain/export/header/link gate; runs only on macOS with Xcode.
set -euo pipefail
framework=${1:?framework path required}
work=${2:?isolated output path required}
root=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$work"
binary="$framework/RaspRuntime"
# Inspect the actual adapter object as well as the shipped framework: Objective-C
# containment must not introduce C++ exception or terminate paths, even if linked.
adapter="$(dirname "$framework")/CMakeFiles/RaspRuntime.dir/src/capture/capture_bridge.mm.o"
nm -j "$adapter" > "$work/adapter-symbols.txt"
if grep -E '(___cxa_|___gxx_personality|___clang_call_terminate|__ZSt9terminatev)' "$work/adapter-symbols.txt"; then
  echo "FAIL: the capture adapter references C++ exception or terminate machinery"
  exit 1
fi
nm -gUj "$binary" | LC_ALL=C sort > "$work/exports.txt"
diff -u "$root/ios/capture_exports.txt" "$work/exports.txt"
# PUBLIC_HEADER is part of the framework that is also staged into the packer wheel.
cmp "$root/ios/include/rasp/ios_capture.h" "$framework/Headers/ios_capture.h"
xcrun vtool -show-build "$binary" | grep -qxE ' *minos 12\.0'
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version
for language in c objective-c c++ objective-c++; do
  flags=(-Wall -Wextra -Werror -Wunguarded-availability)
  if [[ "$language" == c++ || "$language" == objective-c++ ]]; then flags+=(-std=c++23 -nostdinc++); fi
  if [[ "$language" == objective-c || "$language" == objective-c++ ]]; then flags+=(-fobjc-arc); fi
  xcrun --sdk iphoneos clang -x "$language" -target arm64-apple-ios12.0 \
    -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
    "${flags[@]}" -F "$(dirname "$framework")" "$root/tests/ios/capture/host_link.c" \
    -framework RaspRuntime -o "$work/host-${language//+/p}"
done

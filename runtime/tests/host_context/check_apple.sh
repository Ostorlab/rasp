#!/bin/bash
# Real Apple SDK host-source consumers and unsigned UIKit/Swift app. No signing/device claim.
set -euo pipefail
framework=${1:?actual RaspRuntime.framework}
out=${2:?task-owned output directory}
root=$(cd "$(dirname "$0")/../.." && pwd)
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$out/ContextHost.app/Frameworks"
includes=(-I "$root/host_context/include" -I "$framework/Headers")
flags=(-target arm64-apple-ios12.0 -isysroot "$sdk" -Wall -Wextra -Werror -Wunguarded-availability)
xcrun --sdk iphoneos clang -std=c11 "${flags[@]}" "${includes[@]}" -fvisibility=hidden \
  -c "$root/host_context/src/host_context.c" -o "$out/context.o"
xcrun --sdk iphoneos clang -std=c11 "${flags[@]}" "${includes[@]}" -fvisibility=hidden \
  -c "$root/host_context/src/clock_math.c" -o "$out/math.o"
xcrun --sdk iphoneos clang -std=c11 "${flags[@]}" "${includes[@]}" -fvisibility=hidden \
  -c "$root/host_context/ios/host_clock.c" -o "$out/clock.o"
for language in c objective-c c++ objective-c++; do
  language_flags=(-Wall -Wextra -Werror)
  if [[ "$language" == c++ || "$language" == objective-c++ ]]; then language_flags+=(-std=c++23 -nostdinc++); fi
  if [[ "$language" == objective-c || "$language" == objective-c++ ]]; then language_flags+=(-fobjc-arc); fi
  xcrun --sdk iphoneos clang -x "$language" "${flags[@]}" "${language_flags[@]}" "${includes[@]}" \
    -F "$(dirname "$framework")" "$root/tests/host_context/c_host.c" -x none "$out/context.o" "$out/clock.o" "$out/math.o" \
    -framework RaspRuntime -o "$out/host-${language//+/p}"
done
xcrun --sdk iphoneos swiftc -warnings-as-errors -target arm64-apple-ios12.0 -sdk "$sdk" \
  -I "$root/host_context/include" -I "$framework/Headers" -F "$(dirname "$framework")" \
  -import-objc-header "$root/tests/host_context/ios/bridge.h" \
  "$root/host_context/ios/HostOperationContext.swift" "$root/tests/host_context/ios/main.swift" \
  "$out/context.o" "$out/clock.o" "$out/math.o" -framework RaspRuntime -framework UIKit -framework Foundation \
  -Xlinker -rpath -Xlinker @executable_path/Frameworks -o "$out/ContextHost.app/ContextHost"
cp -R "$framework" "$out/ContextHost.app/Frameworks/"
cp "$root/tests/host_context/ios/Info.plist" "$out/ContextHost.app/Info.plist"
xcrun vtool -show-build "$out/ContextHost.app/ContextHost" | grep -qxE ' *minos 12\.0'
cmp "$framework/RaspRuntime" "$out/ContextHost.app/Frameworks/RaspRuntime.framework/RaspRuntime"
nm -gUj "$framework/RaspRuntime" | LC_ALL=C sort > "$out/framework-exports.txt"
diff -u "$root/ios/capture_exports.txt" "$out/framework-exports.txt"
# Capture the actual host-source compile database for the platform's strict tidy step.
cmake -S "$root/tests/host_context/platform" -B "$out/analysis" -G "Unix Makefiles" \
  -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DRASP_LIBRARY="$framework/RaspRuntime" \
  -DRASP_POLICY_INCLUDE="$framework/Headers"
cmake --build "$out/analysis" --parallel 2

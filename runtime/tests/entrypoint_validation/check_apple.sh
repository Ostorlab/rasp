#!/usr/bin/env bash
# Actual Apple SDK consumers and unsigned Swift UIKit legacy/scene host. No signing/device claim.
set -euo pipefail
framework=${1:?actual framework}; out=${2:?task-owned output}
runtime=$(cd "$(dirname "$0")/../.." && pwd)
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$out/EntryHost.app/Frameworks"
includes=(-I "$runtime/entrypoint_validation/include" -I "$runtime/entrypoint_validation/ios" \
  -I "$runtime/host_context/include" -I "$framework/Headers" -I "$runtime/tests/entrypoint_validation")
macsdk=$(xcrun --sdk macosx --show-sdk-path)
for source in entrypoint_validation/src/link_validation.c entrypoint_validation/ios/url_bytes.c; do
  xcrun --sdk macosx clang -std=c11 -isysroot "$macsdk" "${includes[@]}" -Wall -Wextra -Werror -fvisibility=hidden \
    -c "$runtime/$source" -o "$out/mac-$(basename "$source" .c).o"
done
xcrun --sdk macosx swiftc -warnings-as-errors -sdk "$macsdk" "${includes[@]}" \
  -import-objc-header "$runtime/tests/entrypoint_validation/ios/url_test_bridge.h" \
  "$runtime/entrypoint_validation/ios/EntryPointValidation.swift" "$runtime/tests/entrypoint_validation/ios/url_test.swift" \
  "$out/mac-link_validation.o" "$out/mac-url_bytes.o" -framework Foundation -o "$out/url-tests"
"$out/url-tests"
flags=(-target arm64-apple-ios12.0 -isysroot "$sdk" -Wall -Wextra -Werror -Wunguarded-availability -fvisibility=hidden)
for source in entrypoint_validation/src/link_validation.c entrypoint_validation/ios/url_bytes.c \
    host_context/src/host_context.c host_context/src/clock_math.c host_context/ios/host_clock.c \
    tests/entrypoint_validation/c_host.c; do
  xcrun --sdk iphoneos clang -std=c11 "${flags[@]}" "${includes[@]}" -Wframe-larger-than=4096 \
    -c "$runtime/$source" -o "$out/$(basename "$source" .c).o"
done
for language in c objective-c c++ objective-c++; do
  extra=(); if [[ "$language" == c++ || "$language" == objective-c++ ]]; then extra+=(-std=c++23 -nostdinc++); fi
  if [[ "$language" == objective-c || "$language" == objective-c++ ]]; then extra+=(-fobjc-arc); fi
  xcrun --sdk iphoneos clang -x "$language" "${flags[@]}" "${extra[@]}" "${includes[@]}" \
    -F "$(dirname "$framework")" "$runtime/tests/entrypoint_validation/consumer.c" -x none \
    "$out/link_validation.o" "$out/c_host.o" -framework RaspRuntime -o "$out/consumer-${language//+/p}"
done
xcrun --sdk iphoneos swiftc -warnings-as-errors -module-name EntryHost -target arm64-apple-ios12.0 -sdk "$sdk" \
  "${includes[@]}" -F "$(dirname "$framework")" -import-objc-header "$runtime/tests/entrypoint_validation/ios/bridge.h" \
  "$runtime/entrypoint_validation/ios/EntryPointValidation.swift" "$runtime/host_context/ios/HostOperationContext.swift" \
  "$runtime/tests/entrypoint_validation/ios/main.swift" "$out/link_validation.o" "$out/url_bytes.o" \
  "$out/host_context.o" "$out/clock_math.o" "$out/host_clock.o" -framework RaspRuntime -framework Foundation -framework UIKit \
  -Xlinker -rpath -Xlinker @executable_path/Frameworks -o "$out/EntryHost.app/EntryHost"
cp -R "$framework" "$out/EntryHost.app/Frameworks/"
cp "$runtime/tests/entrypoint_validation/ios/Info.plist" "$out/EntryHost.app/Info.plist"
cmp "$framework/RaspRuntime" "$out/EntryHost.app/Frameworks/RaspRuntime.framework/RaspRuntime"
xcrun vtool -show-build "$out/EntryHost.app/EntryHost" | grep -qxE ' *minos 12\.0'
nm -gUj "$framework/RaspRuntime" | LC_ALL=C sort > "$out/framework-exports.txt"
diff -u "$runtime/ios/capture_exports.txt" "$out/framework-exports.txt"
cmake -S "$runtime/tests/entrypoint_validation/platform" -B "$out/analysis" -G "Unix Makefiles" \
  -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DRASP_LIBRARY="$framework/RaspRuntime" -DRASP_POLICY_INCLUDE="$framework/Headers"
cmake --build "$out/analysis" --parallel 2

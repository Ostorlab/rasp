#!/usr/bin/env bash
# Actual SDK minimum-iOS12 compile/link gates; compilation is not device evidence.
set -euo pipefail
stage=${1:?stage path required}
framework=${2:?framework path required}
out=${3:?isolated output path required}
source_dir=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
for mode in c11 objc cpp17 cpp23 objcpp; do
  case "$mode" in
    c11) flags=(-x c -std=c11) ;;
    objc) flags=(-x objective-c -std=c11 -fobjc-arc) ;;
    cpp17) flags=(-x c++ -std=c++17 -nostdinc++) ;;
    cpp23) flags=(-x c++ -std=c++23 -nostdinc++) ;;
    objcpp) flags=(-x objective-c++ -std=c++23 -nostdinc++ -fobjc-arc) ;;
  esac
  xcrun --sdk iphoneos clang -target arm64-apple-ios12.0 -isysroot "$sdk" \
    -Wall -Wextra -Werror -Wunguarded-availability -Wframe-larger-than=4096 \
    "${flags[@]}" -I "$stage/include" -c "$source_dir/host.c" -o "$out/$mode.o"
  xcrun --sdk iphoneos clang -target arm64-apple-ios12.0 -isysroot "$sdk" \
    "$out/$mode.o" "$stage/lib/librasp_scoped_keys.a" "$stage/lib/libtfpsacrypto.a" \
    "$stage/lib/libc++.a" -F "$(dirname "$framework")" -framework RaspRuntime -framework Foundation \
    -o "$out/$mode"
  size -m "$out/$mode" > "$out/size-$mode.txt"
  python3 - "$out/size-$mode.txt" <<'PYCODE'
import re, sys
text = open(sys.argv[1]).read()
rows = re.findall(r'Section (__data|__bss|__common|__thread_data|__thread_bss): (\d+)', text)
assert rows, "missing mutable section accounting"
size = sum(int(value) for _, value in rows)
print("complete consumer mutable sections including linked dependencies:", size)
assert size <= 131072, size
PYCODE
  nm "$out/$mode" > "$out/symbols-$mode.txt"
  if grep -q __libcpp_contention_table "$out/symbols-$mode.txt"; then exit 1; fi
  xcrun vtool -show-build "$out/$mode" | grep -qxE ' *minos 12\.0'
done
xcrun --sdk iphoneos swiftc -warnings-as-errors -target arm64-apple-ios12.0 -sdk "$sdk" \
  -I "$stage/include" -F "$(dirname "$framework")" "$source_dir/host.swift" \
  "$stage/lib/librasp_scoped_keys.a" "$stage/lib/libtfpsacrypto.a" "$stage/lib/libc++.a" \
  -framework RaspRuntime -o "$out/swift"
xcrun vtool -show-build "$out/swift" | grep -qxE ' *minos 12\.0'

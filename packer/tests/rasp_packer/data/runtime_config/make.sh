#!/usr/bin/env bash
#
# Makes the stand-ins for the runtime's binary that the packer's tests write the config into, from runtime.c: an
# Android librasp.so for arm64, an iOS framework binary for arm64, and a universal (fat) iOS framework binary with an
# arm64 slice and an x86_64 simulator slice. The files this writes are the ones committed next to this script.
#
# Run it with LLVM's clang, ld.lld, ld64.lld and llvm-lipo on the PATH, all from one LLVM release:
#
#   PATH=/usr/lib/llvm-19/bin:$PATH packer/tests/rasp_packer/data/runtime_config/make.sh
#
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

clang --target=aarch64-linux-android31 -shared -fPIC -nostdlib -fuse-ld=lld -O1 -Wl,--build-id=none \
  "$here/runtime.c" -o "$here/librasp.so"
for target in arm64-apple-ios12.0 x86_64-apple-ios12.0-simulator; do
  clang --target="$target" -dynamiclib -nostdlib -fuse-ld=lld -O1 \
    -Wl,-install_name,@rpath/RaspRuntime.framework/RaspRuntime "$here/runtime.c" -o "$work/RaspRuntime-$target"
done
cp "$work/RaspRuntime-arm64-apple-ios12.0" "$here/RaspRuntime"
llvm-lipo -create "$work/RaspRuntime-arm64-apple-ios12.0" "$work/RaspRuntime-x86_64-apple-ios12.0-simulator" \
  -output "$here/RaspRuntime-universal"

#!/usr/bin/env bash
# Compile/link actual optional host source on the selected ABI; never executes a device.
set -euo pipefail
stage=${1:?installed runtime prefix}
abi=${2:?Android ABI}
out=${3:?task-owned output directory}
mode=${4:?Release or Debug}
root=$(cd "$(dirname "$0")/../.." && pwd)
lib="$stage/rasp_packer/android/resources/lib/$abi/librasp.so"
test -s "$lib"
cmake -S "$root/tests/host_context/platform" -B "$out" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-31 -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE="$mode" -DRASP_LIBRARY="$lib" -DRASP_POLICY_INCLUDE="$root/core/include/rasp"
cmake --build "$out" --parallel 2
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
for caller in host_c host_cpp; do
  "$bin/llvm-readelf" -h "$out/$caller" > "$out/$caller-elf.txt"
  "$bin/llvm-nm" -D --defined-only "$out/$caller" > "$out/$caller-exports.txt"
  if grep -q rasp_host_ "$out/$caller-exports.txt"; then
    echo 'host helper unexpectedly exported' >&2
    exit 1
  fi
done

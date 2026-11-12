#!/usr/bin/env bash
# New host-only C/C++ consumer compilation/linkage, never a device execution claim.
set -euo pipefail
stage=${1:?installed prefix}; abi=${2:?ABI}; out=${3:?task output}; mode=${4:?Release or Debug}
runtime=$(cd "$(dirname "$0")/../.." && pwd)
lib="$stage/rasp_packer/android/resources/lib/$abi/librasp.so"
policy_include="$stage/rasp_packer/android/resources/include/rasp"
cmp "$policy_include/local_policy_host.h" "$runtime/core/include/rasp/local_policy_host.h"
cmake -S "$runtime/tests/entrypoint_validation/platform" -B "$out" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-31 -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE="$mode" -DRASP_LIBRARY="$lib" -DRASP_POLICY_INCLUDE="$policy_include"
cmake --build "$out" --parallel 2
nm="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"
for consumer in entry_c entry_cpp; do
  "$nm" -D --defined-only "$out/$consumer" > "$out/$consumer-exports.txt"
  if rg 'rasp_entry_|entry_demo_' "$out/$consumer-exports.txt"; then exit 1; fi
done

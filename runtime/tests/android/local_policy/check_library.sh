#!/usr/bin/env bash
# Link actual C/C++ consumers against one installed Android artifact; no device execution.
set -euo pipefail
stage="$1"
abi="$2"
out="$3"
case "$abi" in
  arm64-v8a) target=aarch64-linux-android31 ;;
  armeabi-v7a) target=armv7a-linux-androideabi31 ;;
  x86_64) target=x86_64-linux-android31 ;;
  x86) target=i686-linux-android31 ;;
  *) echo 'unsupported ABI' >&2; exit 1 ;;
esac
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
resources="$stage/rasp_packer/android/resources"
lib="$resources/lib/$abi/librasp.so"
mkdir -p "$out"
"$bin/llvm-nm" -D --defined-only "$lib" | awk '{print $3}' | LC_ALL=C sort > "$out/exports.txt"
printf '%s\n' JNI_OnLoad rasp_local_policy_gate_v1 rasp_local_policy_info_v1 > "$out/expected-exports.txt"
diff -u "$out/expected-exports.txt" "$out/exports.txt"
for language in c c++; do
  flags=()
  if [[ "$language" == c++ ]]; then flags+=(-nostdinc++); fi
  "$bin/clang" --target="$target" -x "$language" -Wall -Wextra -Werror "${flags[@]}" \
    -I "$resources/include" tests/host/local_policy_host.c "$lib" \
    -Wl,--allow-shlib-undefined -o "$out/host-$language"
done

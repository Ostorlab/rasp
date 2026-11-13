#!/usr/bin/env bash
# Actual installed C/C++ link checks for the companion and unchanged injected runtime.
set -euo pipefail
stage=${1:?stage path required}
abi=${2:?ABI required}
out=${3:?isolated output path required}
case "$abi" in
  arm64-v8a) target=aarch64-linux-android31 ;;
  armeabi-v7a) target=armv7a-linux-androideabi31 ;;
  x86_64) target=x86_64-linux-android31 ;;
  x86) target=i686-linux-android31 ;;
  *) exit 1 ;;
esac
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
source_dir=$(cd "$(dirname "$0")" && pwd)
lib="$stage/rasp_packer/android/resources/lib/$abi/librasp.so"
mkdir -p "$out"
for language in c c++; do
  flags=(-std=c11)
  if [[ "$language" == c++ ]]; then flags=(-std=c++17); fi
  "$bin/clang" --target="$target" -x "$language" -Wall -Wextra -Werror -Wframe-larger-than=4096 \
    "${flags[@]}" -I "$stage/include" -c "$source_dir/host.c" -o "$out/host-$language.o"
  "$bin/clang++" --target="$target" -static-libstdc++ "$out/host-$language.o" \
    "$stage/lib/librasp_scoped_keys.a" "$stage/lib/libtfpsacrypto.a" "$lib" \
    -Wl,--allow-shlib-undefined -o "$out/host-$language"
  "$bin/llvm-readelf" -S --wide "$out/host-$language" > "$out/sections-$language.txt"
  python3 - "$out/sections-$language.txt" <<'PYCODE'
import re, sys
text = open(sys.argv[1]).read()
rows = re.findall(r'\] (\.(?:data|bss|tdata|tbss)) +\S+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +([0-9a-fA-F]+)', text)
assert rows, "missing mutable section accounting"
size = sum(int(value, 16) for _, value in rows)
print("complete consumer mutable sections including linked dependencies:", size)
assert size <= 131072, size
arena = 71936
assert size >= arena, size
print("typed arena payload:", arena, "complete other mutable state:", size - arena)
assert size - arena <= 32768, size - arena
PYCODE
  "$bin/llvm-nm" -C "$out/host-$language" > "$out/symbols-$language.txt"
  if grep -q __libcpp_contention_table "$out/symbols-$language.txt"; then exit 1; fi
done
"$bin/llvm-nm" -D --defined-only "$lib" | awk '{print $3}' | LC_ALL=C sort > "$out/exports.txt"
printf '%s\n' JNI_OnLoad rasp_local_policy_gate_v1 rasp_local_policy_info_v1 > "$out/expected-exports.txt"
diff -u "$out/expected-exports.txt" "$out/exports.txt"

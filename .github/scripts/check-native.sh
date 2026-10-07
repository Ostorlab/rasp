#!/usr/bin/env bash
set -euo pipefail

cpp=poc/flutter_rasp/android/src/main/cpp
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
mapfile -t sources < <(find "$cpp" -maxdepth 1 -name '*.c' ! -name 'rasp_jni.c' | sort)

gcc -Wall -Wextra -Werror -I "$cpp" \
  poc/flutter_rasp/android/src/test/cpp/native_test.c "${sources[@]}" -ldl -o "$out/native-test"
"$out/native-test"
gcc -shared -fPIC -O2 -fvisibility=hidden -Wall -Wextra -Werror -I "$cpp" \
  "${sources[@]}" -ldl -o "$out/librasp_core.so"
strip --strip-all "$out/librasp_core.so"
PYTHONPATH=poc/verifier python -m rasp_verifier.budgets size "$out/librasp_core.so" --max-bytes 1048576

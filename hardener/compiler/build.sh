#!/bin/sh
set -eu
: "${LLVM_HOME:?Set LLVM_HOME to an LLVM 18 installation prefix}"
case "$($LLVM_HOME/bin/llvm-config --version)" in 18.*) ;; *) echo 'LLVM 18 is required' >&2; exit 2;; esac
output=${1:?Usage: build.sh output.so}
# llvm-config emits compiler flags as shell words (toolchain paths must not contain spaces).
"$LLVM_HOME/bin/clang++" -shared -fPIC $($LLVM_HOME/bin/llvm-config --cxxflags) \
    "$(dirname "$0")/RaspPass.cpp" -o "$output" \
    $($LLVM_HOME/bin/llvm-config --ldflags --system-libs --libs core passes transformutils)

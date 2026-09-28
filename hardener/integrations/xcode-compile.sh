#!/bin/sh
# Custom Xcode build rule for explicitly selected C sources. LLVM/plugin versions must match.
set -eu
: "${LLVM_HOME:?LLVM 18 prefix required}"
: "${RASP_PASS_PLUGIN:?Built RaspPass library required}"
: "${RASP_FUNCTIONS:?Comma-separated function allowlist required}"
: "${RASP_SEED:?Nonzero uint32 build seed required}"
: "${RASP_APPLE_TARGET:?For example arm64-apple-ios15.0}"
: "${SDKROOT:?Xcode SDK root required}"
: "${INPUT_FILE_PATH:?Xcode input file required}"
: "${SCRIPT_OUTPUT_FILE_0:?Xcode output object required}"
exec python3 "$(dirname "$0")/../compiler/compile.py" \
    --llvm-prefix "$LLVM_HOME" --plugin "$RASP_PASS_PLUGIN" --functions "$RASP_FUNCTIONS" \
    --seed "$RASP_SEED" --probe-symbol "${RASP_PROBE_SYMBOL:-rasp_guard_probe}" \
    --input "$INPUT_FILE_PATH" --output "$SCRIPT_OUTPUT_FILE_0" \
    -- -target "$RASP_APPLE_TARGET" -isysroot "$SDKROOT"

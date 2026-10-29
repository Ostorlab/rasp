#!/usr/bin/env bash
#
# Makes the stand-in for the runtime's binary that the packer's tests write the config into, from runtime.c: an Android
# librasp.so for arm64. The file this writes is the one committed next to this script.
#
# Run it with LLVM's clang and ld.lld on the PATH:
#
#   PATH=/usr/lib/llvm-19/bin:$PATH packer/tests/rasp_packer/data/runtime_config/make.sh
#
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
clang --target=aarch64-linux-android31 -shared -fPIC -nostdlib -fuse-ld=lld -O1 -Wl,--build-id=none \
  "$here/runtime.c" -o "$here/librasp.so"

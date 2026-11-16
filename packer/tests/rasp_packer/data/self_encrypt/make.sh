#!/usr/bin/env bash
#
# Makes the stand-in runtime library the self-encryption tests encrypt, from librasp.c, for arm64 Android. The file
# this writes is the one committed next to this script.
#
# Run it with LLVM's clang and ld.lld on the PATH, from one LLVM release:
#
#   PATH=/usr/lib/llvm-19/bin:$PATH packer/tests/rasp_packer/data/self_encrypt/make.sh
#
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

clang --target=aarch64-linux-android31 -shared -fPIC -nostdlib -fuse-ld=lld -O1 -funwind-tables \
  -Wl,--build-id=none -Wl,--eh-frame-hdr -Wl,-z,pack-relative-relocs -Wl,-soname,librasp.so \
  "$here/librasp.c" -o "$here/librasp.so"

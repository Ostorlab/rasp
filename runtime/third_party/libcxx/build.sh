#!/usr/bin/env bash
#
# Builds the static libc++ and libc++abi that the iOS runtime links, and packs
# them with their headers into a .tar.xz. The archive this produces is the one
# committed next to this script. The CI job in .github/workflows/libcxx.yml runs
# this script and checks that its output still matches the committed archive.
#
# The build is deterministic: with the same LLVM source, the same patch and the
# same Xcode toolchain, it produces the same libc++.a, libc++abi.a and headers,
# byte for byte. Rebuild and recommit the archive when any of those changes.
#
# Run it on macOS with Xcode and CMake 4.4 on the PATH:
#
#   runtime/third_party/libcxx/build.sh [output-dir]
#
set -euo pipefail

llvm_version=23.1.3
llvm_sha256=c44186a7762ed28954be72e5ff6df9808e0779d4f1bf014ecc4e7e211d31ee34
deployment_target=12.0
architecture=arm64
sysroot=iphoneos

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
patch_file=$here/libcxx-apple-posix-memalign.patch
archive_name=libcxx-ios-$architecture-$sysroot$deployment_target-llvm$llvm_version.tar.xz

out_dir=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

root=llvm-project-$llvm_version.src
archive=$work/$root.tar.xz
curl -fsSL -o "$archive" \
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-$llvm_version/$root.tar.xz"
echo "$llvm_sha256  $archive" | shasum -a 256 -c -

src=$work/src
mkdir -p "$src"
tar -xf "$archive" -C "$src" --strip-components 1 \
  "$root/runtimes" "$root/libcxx" "$root/libcxxabi" "$root/libc" \
  "$root/cmake" "$root/llvm/cmake" "$root/llvm/utils" "$root/third-party"

patch -p1 -d "$src" -i "$patch_file"

build=$work/build
install=$work/install
# -ffile-prefix-map rewrites the build and source paths that would otherwise be
# baked into the objects, so the output does not depend on where it was built.
flags="-Werror=unguarded-availability -ffile-prefix-map=$src=/llvm -ffile-prefix-map=$build=/build"
# ZERO_AR_DATE stops the archiver from writing timestamps into libc++.a.
export ZERO_AR_DATE=1

cmake -S "$src/runtimes" -B "$build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=$sysroot \
  -DCMAKE_OSX_ARCHITECTURES=$architecture \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=$deployment_target \
  -DCMAKE_C_FLAGS="$flags" \
  -DCMAKE_CXX_FLAGS="$flags" \
  -DCMAKE_INSTALL_PREFIX="$install" \
  -DLIBCXX_ENABLE_SHARED=OFF \
  -DLIBCXXABI_ENABLE_SHARED=OFF \
  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLIBCXX_ENABLE_EXCEPTIONS=OFF \
  -DLIBCXXABI_ENABLE_EXCEPTIONS=OFF \
  -DLIBCXX_ENABLE_RTTI=OFF \
  -DLIBCXX_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXXABI_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXX_ENABLE_VENDOR_AVAILABILITY_ANNOTATIONS=OFF \
  -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
  -DLIBCXX_INCLUDE_TESTS=OFF \
  -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
  -DLIBCXXABI_INCLUDE_TESTS=OFF

cmake --build "$build" --parallel
cmake --install "$build" > /dev/null

stage=$work/stage
mkdir -p "$stage"
cp "$install/lib/libc++.a" "$install/lib/libc++abi.a" "$stage/"
cp -R "$install/include" "$stage/include"

mkdir -p "$out_dir"
tar -cf "$work/out.tar" -C "$stage" libc++.a libc++abi.a include
xz -9 -e -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

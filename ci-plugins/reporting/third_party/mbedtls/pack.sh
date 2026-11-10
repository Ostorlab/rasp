#!/usr/bin/env bash
#
# Makes the Mbed TLS source archive that the reporting plugin builds. It
# downloads the official Mbed TLS release, which holds its TF-PSA-Crypto, checks
# its SHA-256, and keeps only what the build needs: the CMake files, the headers,
# the library sources and the licences, of Mbed TLS and of its TF-PSA-Crypto. The
# archive this produces is the one committed next to this script. The CI job in
# .github/workflows/vendored.yml runs this script and checks that its output still
# matches the committed archive.
#
# The output is deterministic: the files are sorted and get fixed owners, modes
# and timestamps, so the same release always gives the same archive.
#
# Run it on Linux, with curl, GNU tar, bzip2 and xz on the PATH:
#
#   plugins/reporting/third_party/mbedtls/pack.sh [output-dir]
#
set -euo pipefail

mbedtls_version=4.2.0
mbedtls_sha256=2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=mbedtls-$mbedtls_version
archive_name=$root-source.tar.xz

out_dir=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

release=$work/$root.tar.bz2
curl -fsSL -o "$release" \
  "https://github.com/Mbed-TLS/mbedtls/releases/download/$root/$root.tar.bz2"
echo "$mbedtls_sha256  $release" | sha256sum -c -

crypto=$root/tf-psa-crypto
src=$work/src
mkdir -p "$src"
tar -xjf "$release" -C "$src" \
  "$root/CMakeLists.txt" "$root/LICENSE" "$root/cmake" "$root/doxygen" "$root/framework/CMakeLists.txt" \
  "$root/include" "$root/library" "$root/pkgconfig" \
  "$crypto/CMakeLists.txt" "$crypto/LICENSE" "$crypto/objlib.cmake" "$crypto/cmake" "$crypto/doxygen" \
  "$crypto/framework/CMakeLists.txt" "$crypto/include" "$crypto/core" "$crypto/dispatch" "$crypto/drivers" \
  "$crypto/extras" "$crypto/platform" "$crypto/utilities" "$crypto/pkgconfig"

tar -cf "$work/out.tar" -C "$src" \
  --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u=rwX,go=rX' "$root"

mkdir -p "$out_dir"
xz -9 -e -T1 -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

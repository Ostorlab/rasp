#!/usr/bin/env bash
#
# Makes the TF-PSA-Crypto source archive that the runtime builds. It downloads
# the official TF-PSA-Crypto release, checks its SHA-256 against the value the
# project publishes, and keeps only what the build needs: the library sources,
# the headers, the CMake files they use and the licence. The archive this
# produces is the one committed next to this script. The CI job in
# .github/workflows/tf-psa-crypto.yml runs this script and checks that its output
# still matches the committed archive.
#
# The output is deterministic: the files are sorted and get fixed owners, modes
# and timestamps, so the same release always gives the same archive.
#
# Run it on Linux, with curl, GNU tar, bzip2 and xz on the PATH:
#
#   runtime/third_party/tf-psa-crypto/pack.sh [output-dir]
#
set -euo pipefail

tf_psa_crypto_version=1.1.1
tf_psa_crypto_sha256=3236f70e827fa693ae9e97499957a80c6dba25395d4617b7d21ecb60c82a480e

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=tf-psa-crypto-$tf_psa_crypto_version
archive_name=$root-source.tar.xz

out_dir=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

release=$work/$root.tar.bz2
curl -fsSL -o "$release" \
  "https://github.com/Mbed-TLS/TF-PSA-Crypto/releases/download/$root/$root.tar.bz2"
echo "$tf_psa_crypto_sha256  $release" | sha256sum -c -

src=$work/src
mkdir -p "$src"
tar -xjf "$release" -C "$src" \
  "$root/CMakeLists.txt" "$root/LICENSE" "$root/objlib.cmake" "$root/cmake" "$root/doxygen" \
  "$root/include" "$root/core" "$root/dispatch" "$root/drivers" "$root/extras" "$root/platform" \
  "$root/utilities" "$root/pkgconfig" "$root/framework/CMakeLists.txt"

tar -cf "$work/out.tar" -C "$src" \
  --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u=rwX,go=rX' "$root"

mkdir -p "$out_dir"
xz -9 -e -T1 -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

#!/usr/bin/env bash
#
# Makes the Mbed TLS source archive that the Android runtime builds. It downloads
# the official Mbed TLS release, checks its SHA-256 against the value Mbed TLS
# publishes, and keeps only what the build needs: the library sources, the
# headers and the licence. The archive this produces is the one committed next
# to this script. The CI job in .github/workflows/mbedtls.yml runs this script
# and checks that its output still matches the committed archive.
#
# The output is deterministic: the files are sorted and get fixed owners, modes
# and timestamps, so the same release always gives the same archive.
#
# Run it on Linux, with curl, GNU tar, bzip2 and xz on the PATH:
#
#   runtime/third_party/mbedtls/pack.sh [output-dir]
#
set -euo pipefail

mbedtls_version=3.6.7
mbedtls_sha256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6

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

src=$work/src
mkdir -p "$src"
tar -xjf "$release" -C "$src" "$root/LICENSE" "$root/include" "$root/library"

tar -cf "$work/out.tar" -C "$src" \
  --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u=rwX,go=rX' "$root"

mkdir -p "$out_dir"
xz -9 -e -T1 -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

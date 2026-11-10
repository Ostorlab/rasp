#!/usr/bin/env bash
#
# Makes the libcurl source archive that the reporting plugin builds. It downloads
# the official libcurl release, checks its SHA-256, and keeps only what the build
# needs: the CMake files, the headers, the library sources and the licence. The
# archive this produces is the one committed next to this script. The CI job in
# .github/workflows/vendored.yml runs this script and checks that its output still
# matches the committed archive.
#
# The output is deterministic: the files are sorted and get fixed owners, modes
# and timestamps, so the same release always gives the same archive.
#
# Run it on Linux, with curl, GNU tar and xz on the PATH:
#
#   plugins/reporting/third_party/curl/pack.sh [output-dir]
#
set -euo pipefail

curl_version=8.23.0
curl_sha256=8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=curl-$curl_version
archive_name=$root-source.tar.xz

out_dir=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

release=$work/$root.tar.xz
curl -fsSL -o "$release" "https://curl.se/download/$root.tar.xz"
echo "$curl_sha256  $release" | sha256sum -c -

src=$work/src
mkdir -p "$src"
tar -xJf "$release" -C "$src" \
  "$root/CMakeLists.txt" "$root/COPYING" "$root/CMake" "$root/include" "$root/lib" "$root/docs/CMakeLists.txt" \
  "$root/scripts/CMakeLists.txt" "$root/curl-config.in" "$root/libcurl.pc.in"

tar -cf "$work/out.tar" -C "$src" \
  --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u=rwX,go=rX' "$root"

mkdir -p "$out_dir"
xz -9 -e -T1 -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

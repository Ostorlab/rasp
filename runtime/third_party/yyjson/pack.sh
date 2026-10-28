#!/usr/bin/env bash
#
# Makes the yyjson source archive that the runtime builds. It downloads the
# source of the official yyjson release tag, checks its SHA-256, and keeps only
# what the build needs: yyjson.c, yyjson.h and the licence. The archive this
# produces is the one committed next to this script. The CI job in
# .github/workflows/yyjson.yml runs this script and checks that its output still
# matches the committed archive.
#
# The output is deterministic: the files are sorted and get fixed owners, modes
# and timestamps, so the same release always gives the same archive.
#
# Run it on Linux, with curl, GNU tar, gzip and xz on the PATH:
#
#   runtime/third_party/yyjson/pack.sh [output-dir]
#
set -euo pipefail

yyjson_version=0.13.0
yyjson_sha256=34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=yyjson-$yyjson_version
archive_name=$root-source.tar.xz

out_dir=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

release=$work/$root.tar.gz
curl -fsSL -o "$release" "https://github.com/ibireme/yyjson/archive/refs/tags/$yyjson_version.tar.gz"
echo "$yyjson_sha256  $release" | sha256sum -c -

src=$work/src
mkdir -p "$src"
tar -xzf "$release" -C "$src" "$root/LICENSE" "$root/src/yyjson.c" "$root/src/yyjson.h"

tar -cf "$work/out.tar" -C "$src" \
  --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u=rwX,go=rX' "$root"

mkdir -p "$out_dir"
xz -9 -e -T1 -c "$work/out.tar" > "$out_dir/$archive_name"
echo "wrote $out_dir/$archive_name"

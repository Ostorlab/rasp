#!/usr/bin/env bash
#
# Makes RaspTestApp.ipa, the iOS test app that the release packs, from main.c and Info.plist. The IPA this writes is the
# one committed in the folder above this script.
#
# The build needs no iOS SDK: the app links against two text stubs (.tbd) that this script writes, one for libSystem
# and one for UIKit, which name only the symbols the app uses. The executable is arm64 only, for iOS 12.0, the
# runtime's minimum, and has no code signature. It gets 1 KiB of free header space, so the packer can add its load
# commands.
#
# The output is deterministic: the zip entries are listed in a fixed order and get fixed modes and timestamps, and no
# extra attributes, so the same tools always give the same IPA.
#
# Run it with LLVM's clang and ld64.lld, both from one LLVM release, and Info-ZIP's zip on the PATH:
#
#   PATH=/usr/lib/llvm-19/bin:$PATH packer/tests/apps/ios/RaspTestApp/make.sh
#
set -euo pipefail

name=RaspTestApp
min_ios=12.0

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/libSystem.tbd" <<'TBD'
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-ios ]
install-name: '/usr/lib/libSystem.B.dylib'
exports:
  - targets: [ arm64-ios ]
    symbols: [ dyld_stub_binder ]
...
TBD
cat > "$work/UIKit.tbd" <<'TBD'
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-ios ]
install-name: '/System/Library/Frameworks/UIKit.framework/UIKit'
exports:
  - targets: [ arm64-ios ]
    symbols: [ _UIApplicationMain ]
...
TBD

app=Payload/$name.app
mkdir -p "$work/$app"
clang --target="arm64-apple-ios$min_ios" -nostdlib -fuse-ld=lld -O2 -Wl,-headerpad,0x400 -Wl,-no_adhoc_codesign \
  "$here/main.c" "$work/libSystem.tbd" "$work/UIKit.tbd" -o "$work/$app/$name"
cp "$here/Info.plist" "$work/$app/Info.plist"

chmod 755 "$work/Payload" "$work/$app" "$work/$app/$name"
chmod 644 "$work/$app/Info.plist"
entries=(Payload/ "$app/" "$app/Info.plist" "$app/$name")
(cd "$work" && TZ=UTC touch -d '1980-01-01 00:00:00' "${entries[@]}" && TZ=UTC zip -X -9 -q "$work/$name.ipa" "${entries[@]}")

cp "$work/$name.ipa" "$here/../$name.ipa"
echo "wrote $(cd "$here/.." && pwd)/$name.ipa"

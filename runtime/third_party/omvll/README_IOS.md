# Vendored O-MVLL plugin for the iOS runtime

**O-MVLL** (https://obfuscator.re/o-mvll/) is a clang pass plugin: clang loads it
with `-fpass-plugin` and it transforms the code while it compiles. A Release build
of `RaspRuntime.framework` obfuscates itself with this plugin; see
`runtime/cmake/omvll_ios.cmake` and the scheme in `runtime/cmake/omvll_config.py`
(shared with Android).

This is Phase 1: compile-time obfuscation only (Layer A). There is no at-rest
encryption or self-decrypt bootstrap yet (Layer B / Phase 2), so the whole
framework is obfuscated in place. The string literals the `DATA_READ_LITERALS`
pass protects remain recoverable with `strings` in the shipped framework until
Phase 2 adds an at-rest layer.

## What is in the vendored archive?

- `omvll-1.11.0-xcode27-macos-arm64.tar.xz` — the plugin, built, as a committed
  archive, so the build does not depend on anything outside the repository. It
  holds the plugin (`omvll-xcode.dylib`) and the Python standard library
  (`Lib/`) the plugin's embedded interpreter needs to read the scheme. The iOS
  build checks its SHA-256, extracts it into the build tree and loads the plugin
  from there.

## Why is the plugin pinned to Xcode 27's clang?

O-MVLL is ABI-locked to one clang. The plugin and the clang that loads it must
come from the same LLVM, or clang refuses the plugin or crashes while it runs.
This archive is pinned to one toolchain:

- O-MVLL 1.11.0.
- Xcode 27.0 (the version `.github/workflows/runtime.yml` builds the iOS
  framework with).
- A macOS arm64 build host.

`runtime/cmake/omvll_ios.cmake` checks these at configure time and fails with a
clear message on a mismatch, rather than letting it surface later as an opaque
plugin-load error. A Debug or host build does not obfuscate, so it needs none of
this.

## Which build hosts can run the obfuscator?

The plugin is a macOS arm64 shared object (`omvll-xcode.dylib`), so it loads only
on macOS arm64 build hosts; `omvll_ios.cmake` rejects an obfuscated build anywhere
else. This mirrors the Android host limit, which is Linux x86_64 only.

## Where does this archive come from?

Repacked from O-MVLL's official 1.11.0 macOS release asset
(`omvll_v1-11-0_macos_*.tar.gz` at
https://github.com/open-obfuscator/o-mvll/releases/tag/1.11.0), keeping only
`omvll-xcode.dylib` and the Python `Lib/`, recompressed as `.tar.xz` — the same
shape as the vendored Android archive.

- SHA-256: `16fe9a48a4840aebd4969a8a255c66ad7283344799b5ff079cc9a6c266f5a445`. The
  build verifies it; check it by hand with
  `shasum -a 256 omvll-1.11.0-xcode27-macos-arm64.tar.xz` (expected: `16fe9a48...f5a445`).

## What is validated, and what is still to do

Validated: a Release build with the full pass set installs and runs on a physical
iPhone (xcode-27 runner), and a `strings` scan shows the signal names are absent.
`runtime.yml`'s ios job runs an obfuscation canary asserting configure reports
O-MVLL engaged and the skip-listed literals stay readable.

Still to do (not in this change):

- Phase 2: at-rest encryption + a Mach-O self-decrypt bootstrap.
- On-device verification that the obfuscated runtime's checks still detect (repack,
  debugger, emulator signals) once installed.
- Randomize the canary with a per-build `RASP_OMVLL_SEED`, as the Android job does.

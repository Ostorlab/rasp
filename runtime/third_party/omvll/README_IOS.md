# Vendored O-MVLL plugin for the iOS runtime

O-MVLL (https://obfuscator.re/o-mvll/) is the obfuscator the runtime uses. It is
a clang pass plugin: clang loads it with `-fpass-plugin` and it transforms the
code while it compiles. A Release build of `RaspRuntime.framework` obfuscates
itself with this plugin; see `runtime/cmake/omvll_ios.cmake` and the scheme in
`runtime/cmake/omvll_config.py` (shared with Android).

This is Phase 1: compile-time obfuscation only (Layer A). There is no at-rest
encryption or self-decrypt bootstrap yet (Layer B / Phase 2), so the whole
framework is obfuscated in place, but the string literals the `DATA_READ_LITERALS`
pass protects remain recoverable with `strings` in the shipped framework until
Phase 2 adds an at-rest layer.

## What is here

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

The plugin is a macOS arm64 shared object (`omvll-xcode.dylib`). It runs only on
a macOS arm64 build host, so obfuscation is available only there. A build on any
other host cannot load it, so `omvll_ios.cmake` rejects an obfuscated build on
one. This is the mirror of the Android host limit, which is Linux x86_64 only.

## Where this archive came from

Repacked from O-MVLL's official 1.11.0 macOS release asset
(`omvll_v1-11-0_macos_*.tar.gz` at
https://github.com/open-obfuscator/o-mvll/releases/tag/1.11.0), keeping only
`omvll-xcode.dylib` and the Python `Lib/`, recompressed as `.tar.xz` — the same
shape as the vendored Android archive.

- SHA-256: `16fe9a48a4840aebd4969a8a255c66ad7283344799b5ff079cc9a6c266f5a445`

## Still to do (not in this change)

- Phase 2: at-rest encryption + a Mach-O self-decrypt bootstrap.
- An iOS CI canary mirroring the Android one: build Release with a random
  `RASP_OMVLL_SEED` and assert the protected literals remain `strings`-visible.
- A device build on a real iPhone to confirm the obfuscated framework runs (the
  Android effort only caught its worst bug on device).

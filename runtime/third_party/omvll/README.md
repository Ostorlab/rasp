# Vendored O-MVLL plugin for the Android runtime

O-MVLL (https://obfuscator.re/o-mvll/) is the obfuscator the Android runtime
uses. It is a clang pass plugin: clang loads it with `-fpass-plugin` and it
transforms the code while it compiles. A Release build of `librasp.so`
obfuscates itself with this plugin; see `runtime/cmake/omvll.cmake` and the
scheme in `runtime/cmake/omvll_config.py`.

This directory holds that plugin, already built, as a committed archive, so the
build does not depend on anything outside the repository.

## What is here

- `omvll-1.11.0-ndk-r29-clang21-linux-x86_64.tar.xz` — the archive. It holds the
  plugin (`omvll-ndk.so`) and the Python standard library (`Lib/`) the plugin's
  embedded interpreter needs to read the scheme. The Android build checks its
  SHA-256, extracts it into the build tree and loads the plugin from there.

## The version, and why it is pinned

O-MVLL is ABI-locked to one clang. The plugin and the clang that loads it must
come from the same LLVM, or clang refuses the plugin or crashes while it runs.
This archive is pinned to one toolchain:

- O-MVLL 1.11.0.
- Android NDK r29 (`29.0.14206865`), which is clang 21 (revision `r563880c`).
- A Linux x86_64 build host.

`runtime/cmake/omvll.cmake` checks all three at configure time and fails with a
clear message on a mismatch, rather than letting it surface later as an opaque
plugin-load error. An obfuscated build therefore needs NDK r29 on a Linux x86_64
machine. A Debug or host build does not obfuscate, so it needs none of this.

## The host limit

The plugin is a Linux x86_64 shared object. It runs only on a Linux x86_64 build
host, so obfuscation is available only there. A build on any other host (macOS,
Windows, an arm64 Linux) cannot load the plugin, so `omvll.cmake` rejects an
obfuscated build on one. This is why iOS obfuscation is a separate piece of work:
the iOS framework builds with a different LLVM, for which there is no matching
O-MVLL yet.

## Licence

O-MVLL is Apache-2.0. Vendoring the plugin as a build dependency is within that
licence. Record it in the repository's third-party notices.

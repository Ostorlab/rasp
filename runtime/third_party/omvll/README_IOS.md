# Vendored O-MVLL plugin for the iOS runtime

**O-MVLL** (https://obfuscator.re/o-mvll/) is a clang pass plugin: clang loads it
with `-fpass-plugin` and it transforms the code while it compiles. A Release build
of `RaspRuntime.framework` obfuscates itself with this plugin; see
`runtime/cmake/omvll_ios.cmake` and the scheme in `runtime/cmake/omvll_config.py`.

This is Phase 1: compile-time obfuscation only (Layer A). There is no at-rest
encryption or self-decrypt bootstrap yet (Layer B / Phase 2). Only the `RaspRuntime`
target's own C++/Objective-C++ translation units and its directly compiled core
host bridge receive the plugin. Linked core, individual plugins, registry and
third-party libraries compile without it. Android has no plugin integration in
this parent. The string literals skipped by `DATA_READ_LITERALS` remain
recoverable with `strings` in the shipped framework.

## What is in the vendored archive?

- `omvll-1.11.0-xcode27-macos-arm64.tar.xz` — the built plugin, committed as an
  archive so the build does not depend on anything outside the repository. It
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

`runtime/cmake/omvll_ios.cmake` checks the Apple target, macOS arm64 host and Clang
compiler family; it does not identify the exact Xcode compiler build. The plugin
embeds LLVM 21.1.6, source `903b9faaae5c43ecc9b7e33f8db9c94c7429374a`; separate
LLVM 23 tidy/libc++ tools are not its compiler ABI. Actual Apple CI must validate
the pairing. A Debug or host build does not obfuscate.

## Which build hosts can run the obfuscator?

The plugin is a macOS arm64 shared object (`omvll-xcode.dylib`), so it loads only
on macOS arm64 build hosts; `omvll_ios.cmake` rejects an obfuscated build anywhere
else. No Android plugin archive is selected in this parent.

## Where does this archive come from?

Repacked from O-MVLL's official 1.11.0 macOS release asset
(`omvll_v1-11-0_macos_*.tar.gz` at
https://github.com/open-obfuscator/o-mvll/releases/tag/1.11.0), keeping only
`omvll-xcode.dylib` and the Python `Lib/`, recompressed as `.tar.xz`.

- SHA-256: `16fe9a48a4840aebd4969a8a255c66ad7283344799b5ff079cc9a6c266f5a445`. The
  build verifies it; check it by hand with
  `shasum -a 256 omvll-1.11.0-xcode27-macos-arm64.tar.xz` (expected: `16fe9a48...f5a445`).

## What is validated, and what is still to do

`runtime.yml` builds and links with the actual Apple SDK and checks that configure
reports O-MVLL engaged and the skip-listed literals stay readable. That gate does
not establish transformed execution, physical-device startup or absence of all
signal names. Those require separately associated artifact/device evidence.

The [seed policy](../../../docs/native-seed-policy.md) captures one canonical seed
and mode at configure time. The compiler launcher verifies the captured plugin,
config and actual nearest `omvll.yml` before each invocation; a default extracted
plugin is also compared to the selected archive member during configuration.
Explicit legacy plugin/config/Python-path overrides are captured rather than
silently forbidden. Their byte identities do not constitute root approval of a
new protected profile or validate arbitrary custom config behavior.

Still to do (not in this change):

- Phase 2: at-rest encryption + a Mach-O self-decrypt bootstrap.
- On-device verification that the obfuscated runtime's checks still detect (repack,
  debugger, emulator signals) once installed.
- An externally frozen per-release seed/publisher pipeline and artifact sidecar;
  the launcher never generates release-attempt seeds itself.

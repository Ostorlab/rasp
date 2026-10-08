# Vendored libc++ for iOS

The iOS runtime supports **iOS 12.0**, so it can go into any app the App Store
accepts today. The libc++ that ships inside iOS only supports iOS 15 and later,
so the runtime cannot use it. Instead it carries its own copy of libc++, built
from the LLVM source and linked into the framework as a static library.

This directory holds that copy, already built, together with everything needed
to rebuild it and check it.

## What is here

- `libcxx-ios-arm64-iphoneos12.0-llvm23.1.3.tar.xz` — the built library. It holds
  `libc++.a`, `libc++abi.a` and the libc++ headers (`include/c++/v1`). The iOS
  build extracts it and links it; see `runtime/cmake/libcxx.cmake`.
- `libcxx-apple-posix-memalign.patch` — the one change made to the LLVM source
  before building (explained below).
- `build.sh` — rebuilds the archive from the LLVM source.

## How it is built

`build.sh` downloads the LLVM 23.1.3 source, checks its SHA-256, applies the
patch and builds libc++ and libc++abi for iOS arm64 with a minimum of iOS 12.0.
The build is:

- **static** — `libc++.a` and `libc++abi.a`, no shared libraries.
- **hermetic** — every libc++ symbol is hidden, so nothing leaks out of the
  framework and nothing clashes with the app's own copy of libc++.
- **without exceptions and without RTTI** — the same as the runtime itself.
- **without vendor availability annotations** — those annotations are what make
  Apple's libc++ refuse features below iOS 15. Our own copy has every feature,
  because it is inside our binary, so they are turned off.

The build is reproducible. With the same LLVM source, the same patch and the
same Xcode toolchain it produces the same bytes. `build.sh` passes
`-ffile-prefix-map` and sets `ZERO_AR_DATE` so the output does not depend on the
build path or on timestamps.

## The patch

libc++ allocates aligned memory with the C11 function `aligned_alloc`. On iOS
that function only exists from iOS 13. The runtime's minimum is iOS 12, and the
build uses `-Werror=unguarded-availability`, so this stops the build with
`'aligned_alloc' is only available on iOS 13.0 or newer`.

The patch changes one line so that on Apple platforms libc++ uses
`posix_memalign` instead. That function does the same job and has existed on iOS
since the first version. The patch only affects Apple; Android and the Linux host
are untouched.

## Rebuilding

Run on macOS, with Xcode and CMake 4.4 on the PATH:

```
runtime/third_party/libcxx/build.sh
```

It rewrites the `.tar.xz` next to it. Commit the new archive.

Rebuild when any of these changes: the LLVM version, the patch, the minimum iOS
version, the architecture, or the Xcode toolchain used to build it.

## How CI checks it

`.github/workflows/libcxx.yml` runs `build.sh` on the same Xcode image and
compares its `libc++.a`, `libc++abi.a` and headers against the committed archive.
If they differ, the committed archive is stale or was not built from this source,
and the job fails. This way the binary in git is always provably the result of
the pinned LLVM source plus the patch in this directory.

# RASP

[![Packer](https://github.com/Ostorlab/rasp/actions/workflows/packer.yml/badge.svg)](https://github.com/Ostorlab/rasp/actions/workflows/packer.yml)
[![Runtime](https://github.com/Ostorlab/rasp/actions/workflows/runtime.yml/badge.svg)](https://github.com/Ostorlab/rasp/actions/workflows/runtime.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Runtime application self-protection (RASP) for Android and iOS apps.**

rasp protects an app you have already built. It adds a small runtime to the APK, AAB or IPA, and the protected app
checks the device it runs on and itself while it is in use. No change to the app's source code is needed.

## Features

- **Android and iOS:** APK, AAB and IPA.
- **No source code changes:** protect the build you already ship.
- **Choose the checks:** turn on only the check groups that fit your users.
- **Detects:** root and jailbreak, debuggers, Frida and other hooking, emulators, app virtualizers, network
  interception (VPN tunnels and proxies), tampering with the runtime's code, and repackaged copies.
- **Runs all the time:** the checks run when the app starts, then every 60 seconds.
- **Events on the Ostorlab platform:** protect apps and see their events in
  [Mobile ADR](#use-rasp-on-the-ostorlab-platform).

## How it works

```
your app (APK / AAB / IPA)
        │
        ▼
  rasp pack --checks …        adds the runtime and writes the chosen checks into its config
        │
        ▼
protected app (unsigned)  ──▶  you sign it and ship it
        │
        ▼
on the device                  the runtime runs the chosen checks and hands the observations
                               to its plugins; a development build also logs them
```

A plugin is code compiled into the runtime ([API](runtime/core/include/rasp/plugin.h), [example](runtime/plugins/example/)). It can add its own checks, and it receives the observations of each run, for example to send them somewhere. A runtime built without plugins keeps the observations to itself, and a release build doesn't log them.

- **The packer** (`packer/`, Python) adds the runtime to the app and returns it unsigned.
- **The runtime** (`runtime/`, C++) runs inside the protected app and runs the checks.

## Quick start

1. **Build the runtime** for your platform ([details](runtime/README.md#build)):

   ```
   cd runtime
   cmake --preset android
   cmake --build --preset android
   ```

   Put the built files where the packer looks for them: see the READMEs in
   [`packer/src/rasp_packer/android/resources/`](packer/src/rasp_packer/android/resources/README.md) and
   [`packer/src/rasp_packer/ios/resources/`](packer/src/rasp_packer/ios/resources/README.md).

2. **Install the packer:**

   ```
   cd packer
   uv sync --locked
   ```

3. **Protect an app:**

   ```
   uv run rasp pack app.apk --platform android --build-id my-build-1 --checks root,debugger,hooks --output app-protected.apk
   ```

4. **Sign** `app-protected.apk` with your release key, then ship it.

The packer is also a Python library:

```python
import pathlib

from rasp_packer import packer
from rasp_packer import platforms

result = packer.pack(
    app=pathlib.Path("app.ipa"),
    platform=platforms.Platform.IOS,
    output=pathlib.Path("app-protected.ipa"),
    build_id="my-build-1",
    checks=["jailbreak", "debugger", "hooks"],
)
```

## Checks

| Group | Android | iOS | Detects |
|---|:---:|:---:|---|
| `root` | ✓ | | Root files, writable system partitions, SELinux and build properties |
| `jailbreak` | | ✓ | Jailbreak files, sandbox escape and process spawning |
| `debugger` | ✓ | ✓ | A debugger attached to the app |
| `hooks` | ✓ | ✓ | Frida and other libraries injected into the app |
| `integrity` | ✓ | | The runtime's code changed in memory |
| `mitm` | ✓ | ✓ | VPN tunnels, and proxies on iOS |
| `identity` | ✓ | ✓ | A repackaged copy of the app (always on) |
| `emulator` | ✓ | ✓ | An emulator or the iOS Simulator |
| `virtualizer` | | ✓ | The app running inside another app's container |

- Pass the groups with `--checks` (or `checks=` in Python). `identity` is always added.
- An unknown group is skipped with a warning, so a list written for an older version still packs.
- Without `--checks`, only `identity` runs.

Each check and the signals it reports are described in [`runtime/README.md`](runtime/README.md).

## Requirements

| | |
|---|---|
| Protected Android app | Android 12 (API 31) or later. The packer raises a lower minimum SDK to 31. |
| Protected iOS app | iOS 12.0 or later |
| Packer | Python 3.14, [uv](https://docs.astral.sh/uv/) |
| Runtime build | CMake 4.4, Clang from LLVM 23; the Android NDK, SDK and a JDK for Android; Xcode on a Mac for iOS |

## Documentation

- [`packer/README.md`](packer/README.md): the packer, its options, build ids and checks.
- [`runtime/README.md`](runtime/README.md): the runtime, each check, building and logs.
- [`TODO.md`](TODO.md): known work that isn't done yet.

## Use rasp on the Ostorlab platform

Don't want to build the runtime yourself, or want to see what your protected apps find on real devices? Mobile ADR
on the [Ostorlab platform](https://report.ostorlab.co) protects your apps with rasp and shows their events:

1. Create an account on the [Ostorlab platform](https://report.ostorlab.co) and open **Mobile ADR**.
2. Upload your APK, AAB or IPA, choose the checks, and download the protected app
   ([Protect an app](https://docs.ostorlab.co/mobile_adr/protect_an_app.html)).
3. Sign it and ship it as usual.
4. See the events in the **Events** tab: each check run on a device, what it found (root files, Frida, a VPN
   tunnel…), and whether the check could run ([Events](https://docs.ostorlab.co/mobile_adr/events.html)).
5. Find every protected version of your app, with its checks and RASP release
   ([Applications and builds](https://docs.ostorlab.co/mobile_adr/applications_and_builds.html)).

## Contributing

Contributions are welcome: open an issue or a pull request. Every change goes through a pull request.

- Packer: run the checks listed in [`packer/README.md`](packer/README.md#development) (format, lint, types, tests).
- Runtime: read [`runtime/CONTRIBUTING.md`](runtime/CONTRIBUTING.md) first. It lists the rules the build enforces and
  the ones reviewers check.

## Security

Please don't report a vulnerability in a public issue. See [`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE)

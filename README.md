# rasp

Runtime application self-protection (RASP) for Android and iOS apps, by [Ostorlab](https://www.ostorlab.co).

`rasp` adds a runtime to an app you have already built. The protected app checks the device it runs on, for root or
jailbreak, a debugger, hooking frameworks such as Frida, an emulator, network interception and tampering, and reports
what it observes. You choose which checks it runs. No change to the app's source code is needed.

- **The packer** (Python) takes an APK, an AAB or an IPA and adds the runtime to it. It returns the protected app
  unsigned: you sign it with your own key before you ship it.
- **The runtime** (C++) runs inside the protected app. It runs the chosen checks when the app starts, then every 60
  seconds.

## Requirements

- **Android:** the protected app needs Android 12 (API 31) or later. The packer raises the app's minimum SDK to 31
  when it is lower.
- **iOS:** iOS 12.0 or later.
- **To build:** Python 3.14 and [uv](https://docs.astral.sh/uv/) for the packer; CMake 4.4 and Clang from LLVM 23 for
  the runtime, plus the Android NDK, the Android SDK and a JDK for Android, or Xcode on a Mac for iOS. See
  [`runtime/README.md`](runtime/README.md#build).

## Getting started

1. Build the runtime for your platform:

   ```
   cd runtime
   cmake --preset android        # or: cmake --preset ios, on a Mac
   cmake --build --preset android
   ```

2. Put the built runtime where the packer looks for it, as described in
   [`packer/src/rasp_packer/android/resources/README.md`](packer/src/rasp_packer/android/resources/README.md) and
   [`packer/src/rasp_packer/ios/resources/README.md`](packer/src/rasp_packer/ios/resources/README.md).

3. Install the packer and protect an app with the checks it should run:

   ```
   cd packer
   uv sync --locked
   uv run rasp pack app.apk --platform android --build-id my-build-1 --checks root,debugger,hooks --output app-protected.apk
   ```

4. Sign `app-protected.apk` with your release key, as you sign the app today, then ship it.

The packer is also a Python library, `rasp_packer.packer.pack`. See [`packer/README.md`](packer/README.md).

## Checks

The runtime runs its checks in groups. You choose the groups a protected app runs with `--checks`; the packer writes
them into the runtime's config, and the runtime runs only those.

| Group | Android | iOS | What it looks for |
|---|---|---|---|
| `root` | ✓ | | Root files, writable system partitions, SELinux and build properties. |
| `jailbreak` | | ✓ | Jailbreak files, sandbox escape and process spawning. |
| `debugger` | ✓ | ✓ | A debugger attached to the app. |
| `hooks` | ✓ | ✓ | Frida and other libraries injected into the app. |
| `integrity` | ✓ | | The runtime's code changed in memory. |
| `mitm` | ✓ | ✓ | VPN tunnels, and on iOS proxies. User-installed certificates are not detected yet. |
| `identity` | ✓ | ✓ | Whether the app still has the identity it shipped with, which a repackaged copy changes. Always runs. |
| `emulator` | ✓ | ✓ | An emulator or the iOS Simulator. |
| `virtualizer` | | ✓ | The app running inside another app's container. |

- `identity` always runs: the packer adds it to every choice.
- An id that is not a group of the app's platform is skipped with a warning, so a list written for an older version
  still packs.
- Without `--checks`, the packer warns and runs only `identity`.

The groups are listed in [`packer/src/rasp_packer/checks.py`](packer/src/rasp_packer/checks.py), and a test checks
that they match the runtime. Each check and the signals it reports are described in
[`runtime/README.md`](runtime/README.md).

## Layout

```
packer/                 Python packer: a library, with the `rasp` command line as its client
  src/rasp_packer/
    android/            APK and AAB: add the runtime library
    ios/                IPA: add the runtime framework
  tests/
runtime/                C++ runtime libraries, built with CMake, and the Android stub, in Java
  core/                 code shared by both platforms: config, observations, helpers
  android/              Android entry point (JNI), the Android checks, the payload decryption, the stub loader, and the .so build
  ios/                  iOS entry point, the iOS checks, and the RaspRuntime.framework build
  tests/                tests that run on a development machine, without a device
```

## Contributing

Contributions are welcome. Every change goes through a pull request.

- The packer's checks (format, lint, types, tests) are in [`packer/README.md`](packer/README.md#development).
- Before changing the runtime, read [`runtime/CONTRIBUTING.md`](runtime/CONTRIBUTING.md): it lists the rules the build
  enforces and the ones reviewers check.
- Known work that isn't done yet is listed in [`TODO.md`](TODO.md).

## Security

Please don't open a public issue for a vulnerability. See [`SECURITY.md`](SECURITY.md) for how to report one.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

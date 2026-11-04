# rasp

Ostorlab Mobile RASP: the **packer**, and the **runtime libraries** it puts inside an app.

- **The packer** (Python) takes a built app, an APK, an AAB or an IPA, and adds the runtime to it. It returns the protected app unsigned: you sign it before you ship it.
- **The runtime libraries** (C++) run inside the protected app, on Android and on iOS. They run the checks (debugger, hooking, jailbreak and root, tampering, and others).

## Layout

```
packer/                 Python packer: a library, with the `rasp` command line as its client
  src/rasp_packer/
    android/            APK and AAB: add the runtime library
    ios/                IPA: add the runtime framework
  tests/
runtime/                C++ runtime libraries, built with CMake, and the Android stub, in Java
  core/                 code shared by both platforms: observations, helpers
  android/              Android entry point (JNI), the Android checks, the payload decryption, the stub loader, and the .so build
  ios/                  iOS entry point, the iOS checks, and the RaspRuntime.framework build
  tests/                tests that run on a development machine, without a device
```

## Usage

Pack an app with the check groups it should run, then sign the protected app:

```
rasp pack app.apk --platform android --build-id <build id> --checks root,debugger,hooks --output app-protected.apk
```

The packer can also be called as a Python library. See [`packer/README.md`](packer/README.md).

## Check groups

The runtime runs its checks in groups. The caller of the packer chooses the groups a protected app runs (`--checks`), the packer writes them into the runtime's config, and the runtime runs only those, when the app starts and then every 60 seconds. `identity` always runs: the packer adds it to every choice.

| Group | Android | iOS | What it looks for |
|---|---|---|---|
| `root` | ✓ | | Root files, writable system partitions, SELinux and build properties. |
| `jailbreak` | | ✓ | Jailbreak files, sandbox escape and process spawning. |
| `debugger` | ✓ | ✓ | A debugger attached to the app. |
| `hooks` | ✓ | ✓ | Frida and other libraries injected into the app. |
| `integrity` | ✓ | | The runtime's code changed in memory. |
| `mitm` | ✓ | ✓ | VPN tunnels, proxies and user-installed certificates. |
| `identity` | ✓ | ✓ | Whether the app still has the identity it shipped with, which a repackaged copy changes. Always runs. |
| `emulator` | ✓ | ✓ | An emulator or the iOS Simulator. |
| `virtualizer` | | ✓ | The app running inside another app's container. |

An id that is not a group of the app's platform is skipped with a warning, so a list made for an older version still packs. The groups are listed in [`packer/src/rasp_packer/checks.py`](packer/src/rasp_packer/checks.py), and a test checks they match the runtime. See [Checks](packer/README.md#checks) in the packer's README.

## Contributing

Every change goes through a pull request.

Known work that isn't done yet is listed in [`TODO.md`](TODO.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).

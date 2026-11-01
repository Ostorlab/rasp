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

## Contributing

Every change goes through a pull request.

Known work that isn't done yet is listed in [`TODO.md`](TODO.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).

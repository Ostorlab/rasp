# Android runtime artifacts

The packer injects two prebuilt artifacts into every app. They come from the
runtime build, not from the packer, and are placed here:

- `stub.dex` — the stub loader. The packer uses it as the app's `classes.dex`,
  and points `<application android:name>` at the class
  `co.ostorlab.rasp.RaspStub` (see `resources.STUB_APPLICATION_CLASS`). The
  stub loads the native runtime, receives the decrypted dex files and hands
  control to the app's original application class.
- `lib/<abi>/librasp.so` — the native runtime, one file per ABI (for example
  `lib/arm64-v8a/librasp.so`). The stub loads it with `System.loadLibrary("rasp")`.

Until the runtime build writes these files, `resources.load()` raises
`MissingRuntimeArtifactError`.

## What the stub and the runtime read

The packer writes, as assets:

- `assets/rasp/config.json` — the runtime config (see `config.RuntimeConfig`):
  the payload key, the ids, the original application class and the dex names.
- `assets/rasp/payload.bin` — the app's original dex files, encrypted (see
  `cipher` for the frame format and `payload` for the container format).

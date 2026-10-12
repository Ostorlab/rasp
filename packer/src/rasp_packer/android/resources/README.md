# Android runtime artifacts

The packer injects prebuilt files from the Android runtime build into every app: one stub dex, and one native runtime library per ABI. They are not built by the packer. The release workflow (`.github/workflows/release.yml`) builds them and copies them into this folder, `packer/src/rasp_packer/android/resources/`, on the release tag:

- `stub.dex`: the stub, an `AppComponentFactory`. The packer uses it as the app's `classes.dex`, and sets `<application android:appComponentFactory>` to its class, `co.ostorlab.rasp.RaspStub` (`resources.STUB_FACTORY_CLASS`). When the app starts, Android loads the factory, which loads the native runtime. The runtime decrypts `payload.bin`, and the factory serves the decrypted dex files from memory with `InMemoryDexClassLoader`, so Android runs the app's own code.
- `lib/<abi>/librasp.so`: the native runtime for one ABI, for example `lib/arm64-v8a/librasp.so`. The stub loads it with `System.loadLibrary("rasp")`. There is no fixed list of ABIs: each folder under `lib/` is one ABI, and the packer adds every one it finds.

A checkout of `main` has neither, so `resources.load()` raises `MissingRuntimeArtifactError`.

## What the packer writes for each app

The packer also writes two assets into the APK. They are made for each app when it is packed, so they are not files of this folder:

- `assets/rasp/config.json`: the runtime config (`config.RuntimeConfig`): the payload key (`key_hex`), the build id (`build_id`) and the names of the original dex files (`dex_names`). The stub reads the key and passes it to the native runtime.
- `assets/rasp/payload.bin`: the app's original dex files, encrypted. `cipher` describes the frame format, and `payload` the container inside it.

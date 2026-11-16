# Android runtime artifacts

The packer looks for these files in this folder, `packer/src/rasp_packer/android/resources/`:

- `stub.dex`: the stub, an `AppComponentFactory`. The packer ships it as the app's last base dex (`classesN.dex`) and sets `<application android:appComponentFactory>` to its class, `co.ostorlab.rasp.RaspStub` (`resources.STUB_FACTORY_CLASS`). When the app starts, Android loads the factory, which loads the native runtime and installs the on-demand loader as the parent of the app's base loader.
- `lib/<abi>/librasp.so`: the native runtime for one ABI, for example `lib/arm64-v8a/librasp.so`. The stub loads it with `System.loadLibrary("rasp")`. There is no fixed list of ABIs: each folder under `lib/` is one ABI. The loader's own dex is embedded in the `.so` at the runtime's build.

`stub.dex` and `librasp.so` are not in the repository: they come from the runtime build (see `runtime/README.md`). Without them, `resources.load()` raises `MissingRuntimeArtifactError`.

The packer splits DEX files in process with the `dexsplit` Python package and its native extension (see `split.py`).

## What the packer writes for each app

The packer writes these into the APK, made for each app when it is packed, so they are not files of this folder:

- `assets/rasp/key.bin`: the raw 32-byte key, stored uncompressed. It decrypts the class map and every business dex.
- `assets/rasp/map.bin`: the class map, encrypted under the key and stored. It names, per class, the business dex that defines it. `loader_map` builds it and `cipher` describes the frame format.
- `assets/business/<i>.dex`: one encrypted business dex per file, stored. Each is one `cipher` frame under the key.
- the framework dexes and the stub, in the clear, as `classes.dex` … `classesN.dex`.
- the runtime config, which holds the build id, in the `.rasp_config` section of each `lib/<abi>/librasp.so`.

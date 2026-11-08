# Android runtime artifacts

The packer looks for these files in this folder, `packer/src/rasp_packer/android/resources/`:

- `stub.dex`: the stub, an `AppComponentFactory`. The packer ships it as the app's last base dex (`classesN.dex`) and sets `<application android:appComponentFactory>` to its class, `co.ostorlab.rasp.RaspStub` (`resources.STUB_FACTORY_CLASS`). When the app starts, Android loads the factory, which loads the native runtime and installs the on-demand loader as the parent of the app's base loader.
- `lib/<abi>/librasp.so`: the native runtime for one ABI, for example `lib/arm64-v8a/librasp.so`. The stub loads it with `System.loadLibrary("rasp")`. There is no fixed list of ABIs: each folder under `lib/` is one ABI. The loader's own dex is embedded in the `.so` at the runtime's build.
- `split-dex`: the prebuilt dex splitter the packer runs (see `split.py`), bundled here so the packer needs nothing installed.

`split-dex` is in the repository. `stub.dex` and `librasp.so` are not: they come from the runtime build (see `runtime/README.md`). Without them, `resources.load()` raises `MissingRuntimeArtifactError`.

## What the packer writes for each app

The packer writes these into the APK, made for each app when it is packed, so they are not files of this folder:

- `assets/rasp/s.bin`: one input of the key schedule, stored uncompressed. It is one share of the fold that rebuilds the payload's root key, not a key by itself (`key_schedule`).
- `assets/rasp/map.bin`: the class map, encrypted and stored. It names, per class, the business dex that defines it. `loader_map` builds it and `cipher` describes the frame format; its key is derived from the schedule's root.
- `assets/business/<i>.dex`: one encrypted business dex per file, stored. Each is one `cipher` frame under its own schedule-derived key, so no two frames share a key.
- the framework dexes and the stub, in the clear, as `classes.dex` … `classesN.dex`.
- the runtime config, which holds the build id, and a per-ABI keystore share, both in the `.rasp_config` section of each `lib/<abi>/librasp.so`. The share is one input of the key schedule's fold, chosen per ABI so every ABI recovers the same root key.

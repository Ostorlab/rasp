# Packer

Adds the RASP runtime to a built app: an APK or an AAB for Android, an IPA for iOS. The packer returns the protected app unsigned: you sign it before you ship it.

The packer is a library. `rasp_packer.packer.pack` is its entry point, and the `rasp` command line is a thin client of it, so a job can pack an app without starting a process.

```python
import pathlib

from rasp_packer import packer
from rasp_packer import platforms

result = packer.pack(
    app=pathlib.Path("app.ipa"),
    platform=platforms.Platform.IOS,
    output=pathlib.Path("app-protected.ipa"),
    build_id="e6a8373149e83d008a5212b34bdd23bf637ad9561483c7a3c43b0a157c3f2a18",
    checks=["debugger", "hooks", "jailbreak"],
)
```

```
rasp pack app.ipa --platform ios --build-id e6a8373149e83d008a5212b34bdd23bf637ad9561483c7a3c43b0a157c3f2a18 --checks debugger,hooks,jailbreak --output app-protected.ipa
```

`checks` (`--checks` on the command line) is how the caller chooses the check groups the protected app runs. `pack` requires `checks`, and only the command line defaults it. Without `--checks`, the command line warns and packs the app with only the required check group, `identity`. An id that is not one of the platform's groups is skipped: the command line warns about it, and `pack` reports it in `skipped_checks`. See [Checks](#checks).

`pack` returns the path of the protected app, the app's package name and version, the build id, and the skipped check ids, `skipped_checks`. On iOS, the package name and version are `CFBundleIdentifier` and `CFBundleShortVersionString` from its `Info.plist`; on Android, they are the `package` and `android:versionName` of its manifest.

The packer adds a prebuilt runtime, which comes from the runtime build and is not in the repository. The packer looks for it in its package resources: see the README in `src/rasp_packer/android/resources/` and the one in `src/rasp_packer/ios/resources/`.

## Android

For Android the packer protects the app's code:

- it sorts the app's classes with the bundled `split-dex` tool. The classes under the app's package are the app's own code. The other classes, such as libraries, stay in the clear, as `classes.dex`, `classes2.dex`, ...;
- it encrypts the app's own classes, in dex files of their own, and stores each of these files as the asset `assets/business/<i>.dex`. It also stores the class map as `assets/rasp/map.bin`, encrypted too: the map names the dex file that defines each of these classes. It stores the key as `assets/rasp/key.bin`;
- it adds a small stub as the last dex file (`classesN.dex`), and sets `<application android:appComponentFactory>` to the stub's class, `co.ostorlab.rasp.RaspStub`, while leaving the app's own `<application android:name>` alone;
- it adds the native runtime as `lib/<abi>/librasp.so`, for each ABI the app has native libraries for, or for every ABI the runtime is built for when the app has none. Android installs the native libraries of one ABI only, so each of the app's ABIs needs the runtime. An app with native libraries for an ABI the runtime isn't built for is refused with `UnsupportedAbiError`. The packer writes the runtime config, which holds the build id and the checks, into the `.rasp_config` section of each `librasp.so`;
- it raises the app's `android:minSdkVersion` to 31 when it is lower, because the runtime supports Android 12 (API 31) and later. The protected app then doesn't install on older devices;
- it removes the app's v1 signature files from `META-INF/`, since the protected APK must be signed again.

For an AAB, the packer writes the same entries under `base/`, with the dex files under `base/dex/`, and edits its manifest the same way.

It reads the app's package and version from the `<manifest>` element. An APK whose manifest has no package, or no literal `android:versionName` (for example an `android:versionName` set to a `@string` resource), is refused with `InvalidApkError`, and so is one without a literal `android:minSdkVersion` on `<uses-sdk>`. An AAB is refused in the same cases, with `InvalidAabError`. An app that already holds the class map, or whose manifest already names the stub as its component factory, is refused with `AlreadyProtectedError`.

At run time Android loads the stub as the app's component factory, and the stub loads the runtime. The runtime starts the thread that runs the checks, and installs the on-demand class loader. The first time the app needs one of its own classes, this loader decrypts the dex file that defines it and loads it from memory.

The stub and the native runtime come from the runtime build. The packer looks for them under `src/rasp_packer/android/resources/` (see the README there), and raises `MissingRuntimeArtifactError` when they are missing.

The binary `AndroidManifest.xml` is edited in place by `android/apk/axml.py`, so the packer needs no Android build tool. The protected APK is returned aligned, with native libraries on 16 KB page boundaries and other stored entries on 4-byte boundaries, so it can be signed directly, with no separate `zipalign` step.

The key is stored in the clear, in `assets/rasp/key.bin`. The encryption raises the effort needed to read the app's code, but on its own does not defeat a determined analyst who reads the key from the app. `TODO.md` at the repository root tracks this limit.

## Layout

- `src/rasp_packer/packer.py`: `pack`, the entry point.
- `src/rasp_packer/platforms.py`: the platforms, Android and iOS.
- `src/rasp_packer/identity.py`: `AppIdentity`, the package name and version read from the app.
- `src/rasp_packer/protection_versions.py`: the protection version of each platform. It is public, so the caller can read it, for example to compute the build id.
- `src/rasp_packer/checks.py`: the check groups of each platform, in the order the runtime runs them, and the ones every protected app runs. The packer skips an id that isn't one of them and reports it, so that a caller still packs when it passes a check group that was renamed or removed, and adds the ones every protected app runs.
- `src/rasp_packer/cli.py`: the `rasp` command line.
- `src/rasp_packer/ios/`: packing of IPAs.
  - `ipa.py`: unpacks and repacks the IPA, keeping file permissions, and reads the app's identity (`CFBundleIdentifier` and `CFBundleShortVersionString`) from its `Info.plist`.
  - `macho.py`: makes the main executable load the runtime (`LC_LOAD_DYLIB` and `LC_RPATH`) and removes its code signature.
  - `packer.py`: embeds `RaspRuntime.framework`, writes the runtime config into its binary, and removes the app's `_CodeSignature`.
  - `runtime_binary.py`: writes the runtime config into the `__DATA,__rasp_config` section of the framework's `RaspRuntime` binary.
  - `resources.py`: locates the prebuilt `RaspRuntime.framework`, under `resources/` (see the README there). The framework is prebuilt by the runtime build; without it the packer raises `InvalidRuntimeError`.
- `src/rasp_packer/android/`: packing of APKs and AABs.
  - `packer.py`: the Android `pack`. It sorts the app's classes, encrypts the app's own dex files and the class map, adds the stub as the last dex file, adds `librasp.so` for the app's ABIs with the runtime config written into it, sets the manifest's `appComponentFactory` to the stub, raises its `minSdkVersion`, and removes the v1 signature files of an APK.
  - `apk/`: reading and editing the APK.
    - `archive.py`: reading and repacking the APK (a ZIP).
    - `axml.py`: reading and editing the binary `AndroidManifest.xml`.
    - `manifest.py`: the layer over `axml.py` for the component factory, the app's package and version, and its minimum API level.
  - `aab/`: reading and editing the AAB, and its manifest, which is in protobuf format.
  - `cipher.py`: the authenticated cipher for the class map and the app's own dex files.
  - `split.py`: runs the bundled `split-dex` tool, which sorts the app's classes into the app's own and the others.
  - `loader_map.py`: the class map, which names the dex file that defines each of the app's own classes.
  - `runtime_library.py`: writes the runtime config into the `.rasp_config` section of `librasp.so`.
  - `resources.py`: locating the prebuilt stub and native libraries, and the bundled `split-dex` tool.
- `tests/`: one test file per source file, at the same path, named `<module>_test.py`.

## Development

Python 3.14 and [uv](https://docs.astral.sh/uv/).

```
cd packer
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

CI runs the same commands (`.github/workflows/packer.yml`).

## Build id and protection version

Every protected build has a build id, which the packer writes into the app. The caller chooses it and passes it to `pack` (or to `rasp pack --build-id`). The packer accepts any id: it writes it as it is and does not check its format. It only refuses an id it cannot write: an empty one, one with control characters, or one too long for the space the runtime keeps for its config.

Each platform's protection version is a whole number in `src/rasp_packer/protection_versions.py`. The caller can read it from `rasp_packer.protection_versions.PROTECTION_VERSIONS`, for example to make it part of the build id. Bump it when a change alters what protected apps do on that platform: the runtime's behaviour, or how the packer transforms the app. Changes that leave protected apps the same, such as comments, refactors, tests or docs, do not bump it.

## Checks

The runtime runs its checks in groups, such as `debugger` or `hooks`. `src/rasp_packer/checks.py` lists the groups of each platform in `CHECKS`, and those every protected app runs in `REQUIRED_CHECKS` (`identity`). The caller chooses the groups a protected app runs and passes their ids to `pack` (or to `rasp pack --checks`, comma-separated). The packer:

- skips an id that is not one of the platform's groups and reports it in `PackResult.skipped_checks`, so that a caller, such as a CI job, still packs when it passes a group that was renamed or removed. The command line warns about each skipped id on stderr, such as `rasp pack: warning: 'oldcheck' is not a check of android, skipped`, and packs the app;
- adds the required groups, so `checks=["debugger", "hooks", "jailbreak"]` on iOS also runs `identity`;
- writes the ids sorted into the runtime config.

An empty choice, such as `checks=[]`, runs only the required groups. Without `--checks`, the command line warns and packs the app with only the required groups.

# Packer

Adds the RASP runtime to a built app: an APK for Android, an IPA for iOS. The packer returns the protected app unsigned: the customer signs it before shipping it.

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
)
```

```
rasp pack app.ipa --platform ios --build-id e6a8373149e83d008a5212b34bdd23bf637ad9561483c7a3c43b0a157c3f2a18 --output app-protected.ipa
```

`pack` returns the path of the protected app, the app's package name and version (on iOS, `CFBundleIdentifier` and `CFBundleShortVersionString` from its `Info.plist`; on Android, the `package` and `android:versionName` of its manifest), and the build id.

## Plugins

`pack(..., plugins=[...])`, or `rasp pack ... --plugin <dir>` repeated, adds plugins to the protected app, in the order given, which is the order the runtime loads them. A plugin adds checks to the runtime and sees each pass's observations; `runtime/core/include/rasp/plugin.h` is its API. A plugin bundle is a directory with:

- `plugin.json`: `{"name": ..., "version": ..., "api_version": ...}`. The name matches `[a-z][a-z0-9_]{0,31}`, and the API version must be one the runtime supports (`plugins.PLUGIN_API_VERSION`).
- `android/<abi>/librasp_plugin_<name>.so`: the Android library for each ABI. Every ABI the app gets `librasp.so` for needs one.
- `ios/rasp_plugin_<name>.framework`: the iOS framework, with its binary `rasp_plugin_<name>`. Packing an IPA needs it.
- `config`, optional: bytes the runtime gives the plugin when it starts it, at most 64 KiB.

On Android, the packer adds each library next to `librasp.so`, stored and aligned the same way, and writes the stored assets `assets/rasp/plugins.list` (one name per line) and `assets/rasp/plugin-config/<name>`. On iOS, it copies each framework into the app's `Frameworks/` and writes `plugins.list` and `plugin-config/<name>` into `RaspRuntime.framework`. The protected app is unsigned: the customer signs it, the plugin frameworks included. A bundle that is malformed or lacks a build the app needs raises `InvalidPluginError`.

The runtime is bundled in the packer.

## Android

For Android the packer protects the app's code:

- it encrypts the app's dex files (`classes.dex`, `classes2.dex`, ...) and stores them as the asset `assets/rasp/payload.bin`;
- it replaces `classes.dex` with a small stub, and sets `<application android:appComponentFactory>` to the stub's class, `co.ostorlab.rasp.RaspStub`, while leaving the app's own `<application android:name>` alone;
- it adds the native runtime as `lib/<abi>/librasp.so`, for each ABI the app has native libraries for, or for every ABI the runtime is built for when the app has none. Android installs the native libraries of one ABI only, so each of the app's ABIs needs the runtime. An app with native libraries for an ABI the runtime isn't built for is refused with `UnsupportedAbiError`;
- it raises the app's `android:minSdkVersion` to 31 when it is lower. The stub loads the dex files from memory as an `AppComponentFactory`, through a class loader with a native-library path, which needs Android 12 (API 31). The protected app then doesn't install on older devices;
- it writes the asset `assets/rasp/config.json`, which the stub reads: the payload key, which the stub passes to the native runtime, the build id and the names of the dex files;
- it removes the app's v1 signature files from `META-INF/`, since the customer signs the protected APK again.

It reads the app's package and version from the `<manifest>` element. An APK whose manifest has no package, or no literal `android:versionName` (for example an `android:versionName` set to a `@string` resource), is refused with `InvalidApkError`, and so is one without a literal `android:minSdkVersion` on `<uses-sdk>`. An APK that already holds a payload, or whose manifest already names the stub as its component factory, is refused with `AlreadyProtectedError`.

At run time Android loads the stub as the app's component factory; the stub loads the runtime, which starts the thread that runs the checks, and asks it for the on-demand loader, which decrypts each of the app's own dex files in memory the first time one of its classes is needed.

The stub and the native runtime are prebuilt by the runtime build and live under `src/rasp_packer/android/resources/` (see the README there). Without them the packer raises `MissingRuntimeArtifactError`.

The binary `AndroidManifest.xml` is edited in place by `android/apk/axml.py`, so the packer needs no Android build tool. The protected APK is returned aligned, with native libraries on 16 KB page boundaries and other stored entries on 4-byte boundaries, so the customer signs it directly with no separate `zipalign` step.

First version: the payload key is written in cleartext in `config.json`. The dex encryption raises the effort needed to read the app's code, but on its own does not defeat a determined analyst who reads the key in `config.json`. `TODO.md` at the repository root tracks this limit.

## Install

Each release publishes the packer to the private Python repository `rasp-packer` in Google Artifact Registry. Installing it needs read access to that repository: ask an Ostorlab engineer with GCP admin rights to grant your account `roles/artifactregistry.reader` on `rasp-packer`.

First sign in to Google Cloud:

- on your machine, run `gcloud auth application-default login`;
- in CI or an image build, set `GOOGLE_APPLICATION_CREDENTIALS` to the key file of a service account granted `roles/artifactregistry.reader` on `rasp-packer`.

Then install the Artifact Registry keyring helper, the packer from Artifact Registry alone, and the packer's dependencies from PyPI. Replace `X.Y.Z` with the release version:

```
pip install keyring keyrings.google-artifactregistry-auth
pip install --force-reinstall --no-deps --index-url https://us-central1-python.pkg.dev/adr-rasp/rasp-packer/simple/ rasp-packer==X.Y.Z
pip install rasp-packer==X.Y.Z
```

When pip needs credentials for Artifact Registry, it asks keyring, and the helper gets a short-lived access token from the Google Cloud credentials above. The second command points `--index-url` at Artifact Registry only, so pip can't take `rasp-packer` from PyPI even if a package with that name exists there, and `--force-reinstall` replaces a copy of `rasp-packer` installed from anywhere else. The third command finds `rasp-packer==X.Y.Z` already installed, reads the dependencies it declares, and installs them from PyPI.

Only a release has the prebuilt runtime in it: the iOS framework, and the Android stub and native libraries. A checkout of `main` has none of them, so its packer raises `InvalidRuntimeError` when it packs an IPA, and `MissingRuntimeArtifactError` when it packs an APK.

## Layout

- `src/rasp_packer/packer.py`: `pack`, the entry point.
- `src/rasp_packer/platforms.py`: the platforms, Android and iOS.
- `src/rasp_packer/identity.py`: `AppIdentity`, the package name and version read from the app.
- `src/rasp_packer/plugins.py`: reading and checking plugin bundles.
- `src/rasp_packer/protection_versions.py`: the protection version of each platform, part of every build id. It is public: the caller reads it to compute the build id.
- `src/rasp_packer/cli.py`: the `rasp` command line.
- `src/rasp_packer/ios/`: packing of IPAs.
  - `ipa.py`: unpacks and repacks the IPA, keeping file permissions, and reads the app's identity (`CFBundleIdentifier` and `CFBundleShortVersionString`) from its `Info.plist`.
  - `macho.py`: makes the main executable load the runtime (`LC_LOAD_DYLIB` and `LC_RPATH`) and removes its code signature.
  - `packer.py`: embeds `RaspRuntime.framework`, writes the build id (`RaspBuildId`) into its `Info.plist`, and removes the app's `_CodeSignature`.
  - `resources.py`: locates the `RaspRuntime.framework` that ships with the packer, under `resources/` (see the README there). The framework is prebuilt by the runtime build; without it the packer raises `InvalidRuntimeError`.
- `src/rasp_packer/android/`: packing of APKs.
  - `packer.py`: the Android `pack`. It encrypts the dex files into the payload, puts the stub in place of `classes.dex`, adds `librasp.so` for the app's ABIs, sets the manifest's `appComponentFactory` to the stub, raises its `minSdkVersion`, writes `config.json`, and removes the v1 signature files.
  - `apk/`: reading and editing the APK.
    - `archive.py`: reading and repacking the APK (a ZIP).
    - `axml.py`: reading and editing the binary `AndroidManifest.xml`.
    - `manifest.py`: the layer over `axml.py` for the component factory, the app's package and version, and its minimum API level.
  - `cipher.py`: the authenticated cipher for the payload.
  - `payload.py`: packing the dex files into the encrypted payload.
  - `config.py`: the runtime config written into the APK.
  - `resources.py`: locating the prebuilt stub and native libraries.
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

Every protected build has a build id, which the packer writes into the app. The caller computes it and passes it to `pack` (or to `rasp pack --build-id`); the packer writes it as it is and does not check its format. It only refuses an id it cannot write: an empty one, or one with control characters.

The build id is the lowercase hex SHA-256 over the organisation id, the SHA-256 of the input app file, the platform name, and the platform's protection version. The caller reads the protection version from `rasp_packer.protection_versions.PROTECTION_VERSIONS`.

Each platform's protection version is a whole number in `src/rasp_packer/protection_versions.py`. Bump it when a change alters what protected apps do on that platform: the runtime's behaviour, or how the packer transforms the app. Changes that leave protected apps the same, such as comments, refactors, tests or docs, do not bump it.

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

`pack` returns the path of the protected app, the app's package name and version (on iOS, `CFBundleIdentifier` and `CFBundleShortVersionString` from its `Info.plist`), and the build id.

The runtime is bundled in the packer.

## Install

Install a release straight from the repository, with your access to it. Replace `vX.Y.Z` with the release tag:

```
pip install "rasp-packer @ git+ssh://git@github.com/Ostorlab/rasp.git@vX.Y.Z#subdirectory=packer"
```

Only a release tag has the runtime in it. A checkout of `main` has no runtime, so its packer raises `InvalidRuntimeError` when it packs an app.

## Layout

- `src/rasp_packer/packer.py`: `pack`, the entry point.
- `src/rasp_packer/platforms.py`: the platforms, Android and iOS.
- `src/rasp_packer/identity.py`: `AppIdentity`, the package name and version read from the app.
- `src/rasp_packer/protection_versions.py`: the protection version of each platform, part of every build id. It is public: the caller reads it to compute the build id.
- `src/rasp_packer/cli.py`: the `rasp` command line.
- `src/rasp_packer/ios/`: packing of IPAs.
  - `ipa.py`: unpacks and repacks the IPA, keeping file permissions, and reads the app's identity (`CFBundleIdentifier` and `CFBundleShortVersionString`) from its `Info.plist`.
  - `macho.py`: makes the main executable load the runtime (`LC_LOAD_DYLIB` and `LC_RPATH`) and removes its code signature.
  - `packer.py`: embeds `RaspRuntime.framework`, writes the build id (`RaspBuildId`) into its `Info.plist`, and removes the app's `_CodeSignature`.
  - `resources.py`: locates the `RaspRuntime.framework` that ships with the packer, under `resources/` (see the README there). The framework is prebuilt by the runtime build; without it the packer raises `InvalidRuntimeError`.
- `src/rasp_packer/android/`: packing of APKs.
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

The Reporting Engine computes the build id before it packs an app: the lowercase hex SHA-256 over the organisation id, the SHA-256 of the input app file, the platform name, and the platform's protection version. If a build with that id already exists, it does not pack the app again. It reads the protection version from `rasp_packer.protection_versions.PROTECTION_VERSIONS`.

Each platform's protection version is a whole number in `src/rasp_packer/protection_versions.py`. Bump it when a change alters what protected apps do on that platform: the runtime's behaviour, or how the packer transforms the app. Changes that leave protected apps the same, such as comments, refactors, tests or docs, do not bump it.

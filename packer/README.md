# Packer

Adds the RASP runtime to a built app: an APK or an AAB for Android, an IPA for iOS. It returns the protected app unsigned, and you sign it before you ship it.

The packer is a Python library, and the `rasp` command line is a thin client of it.

```
rasp pack app.apk --platform android --build-id my-build-1 --checks root,debugger,hooks --output app-protected.apk
```

```python
import pathlib

from rasp_packer import packer
from rasp_packer import platforms

result = packer.pack(
    app=pathlib.Path("app.ipa"),
    platform=platforms.Platform.IOS,
    output=pathlib.Path("app-protected.ipa"),
    build_id="my-build-1",
    checks=["jailbreak", "debugger", "hooks"],
)
```

## Options

- `--build-id` (`build_id=`): the id of the protected build, written into the app as it is.
- `--checks` (`checks=`): the check groups the app keeps running. `identity` is always added. Without `--checks`, only `identity` is chosen. An unknown group is skipped with a warning. The warning suggests the closest matching group name. With `--strict`, the pack fails instead. See the groups in the [repository's README](../README.md#checks).
- `--strict`: print an error for every unknown check group and write nothing, instead of skipping it with a warning.
- `--mapping` (Android): the app's R8 or ProGuard mapping file, so the packer finds the app's own classes after R8 renamed them.
- `--pin-certificate` (Android): the certificate the app will be signed with, PEM or DER. The protected app then works only when it is signed with that certificate.

`pack` returns the path of the protected app, the app's package name, version and build id, and the check groups it skipped.

## What a protected app gets

On Android, the packer encrypts the app's own classes, adds a small stub and the runtime library, and points the manifest at the stub. The keys are not stored in the app: the runtime rebuilds them on the device from the app and the device, so a modified app, library or environment cannot decrypt them. The protected app needs Android 12 (API 31) or later, and the packer raises a lower minimum SDK. An app with native libraries for an ABI the runtime is not built for is refused.

On iOS, the packer embeds the runtime framework and makes the app load it.

## Development

Python 3.14 and [uv](https://docs.astral.sh/uv/). CI runs the same commands (`.github/workflows/packer.yml`).

```
cd packer
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

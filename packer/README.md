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
- `--checks` (`checks=`): the check groups the app keeps running. `identity` is always added, an unknown group is skipped with a warning, and without `--checks` only `identity` is chosen. See the groups in the [repository's README](../README.md#checks).
- `--mapping` (Android): the app's R8 or ProGuard mapping file, so the packer finds the app's own classes after R8 renamed them.
- `--pin-certificate` (Android): the certificate the app will be signed with, PEM or DER. The protected app then works only when it is signed with that certificate.
- `--json`: prints the result as one JSON object with sorted keys instead of text: `build_id`, `checks`, `output`, `package_name`, `skipped_checks` and `version`. Warnings still go to stderr.

`pack` returns a result with:

- the path of the protected app (`output`)
- the app's package name (`package_name`), version (`version`) and build id (`build_id`)
- the check groups the app runs (`checks`)
- the check groups it skipped (`skipped_checks`)

## How do I check whether an app is protected?

**`rasp inspect`** opens a built app, never modifies it, and reports whether it carries the RASP runtime. For a protected app it also prints the build id and the check groups from the runtime's config, and on Android the ABIs that carry the runtime. It does not run the app, so it cannot tell whether a check actually fires, only that the runtime and its config are present.

```
rasp inspect app-protected.apk --platform android
```

```
protected  yes
package    com.example.app
version    2.4.1
build id   my-build-1
checks     debugger,hooks,identity,root
abis       arm64-v8a,armeabi-v7a
```

<<<<<<< HEAD
An app without the runtime prints `protected  no` with its package and version. With `--json`, `inspect` prints one JSON object with sorted keys instead: `abis`, `build_id` (null for an unprotected app), `checks`, `package_name`, `protected` and `version`. From Python, `rasp_packer.inspection.inspect(app=..., platform=...)` returns the same fields.
=======
An app without the runtime is not an error: `inspect` prints `protected  no` with its package and version and exits 0. From Python, `rasp_packer.inspection.inspect(app=..., platform=...)` returns the same fields.
>>>>>>> feature/cli-inspect

## When does `rasp` print the banner?

**The banner** is the shaded ASCII-art RASP logo the CLI prints above the help text. `rasp` and `rasp --help` start with it, and bare `rasp` exits 0. Subcommands never print it.

The banner shows only when all of these hold:

- stdout is a terminal
- `NO_COLOR` is unset or empty
- `TERM` is not `dumb`

Otherwise, a pipe, a redirect or CI gets the plain help. The color depth follows `COLORTERM`: 24-bit when it is `truecolor` or `24bit`, and the closest match in the 256-color palette otherwise.

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

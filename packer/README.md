# Packer

Adds the RASP runtime to a built app: an APK or an AAB for Android, an IPA for iOS. It returns the protected app unsigned, and you sign it before you ship it.

The packer is a Python library, and the `rasp` command line is a thin client of it.

```
rasp pack app.apk --build-id my-build-1 --checks root,debugger,hooks --output app-protected.apk
```

To see a platform's check groups, listed in the order the runtime runs them with what each detects:

```
rasp checks --platform android
```

Without `--platform`, `rasp checks` lists both platforms, each under a heading. `identity` is marked as always on.

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

- `--platform` (`platform=`): `android` or `ios`. When it is not given, the command line infers the platform from the app's extension, case-insensitively: `.apk` and `.aab` are Android, `.ipa` is iOS. Any other extension requires `--platform`.
- `--build-id` (`build_id=`): the id of the protected build, written into the app as it is. `rasp pack` derives it when it is not given: the SHA-256 of the app's contents, the platform, the installed packer version, the resolved checks and their actions. The same inputs give the same id, and any change to the app, the packer version, the checks or their actions gives a new one. `pack` requires it.
- `--checks` (`checks=`): the check groups the app keeps running. `identity` is always added. Without `--checks`, the command line runs every group the target platform supports (`checks=` in Python is required). An unknown group is skipped with a warning. The warning suggests the closest matching group name. With `--strict`, `rasp pack` exits with status 1 instead. See the groups in the [repository's README](../README.md#checks).
- `--report-only` (`report_only=`): enabled groups whose detections only report, in the same comma-separated syntax as `--checks`. Overrides the defaults.
- `--block` (`block=`): enabled groups whose detections end the app. Overrides the defaults. A group in both options, or a known but disabled group, is an error. By default, `rasp pack` warns about each unknown id and skips it. With `--strict`, it prints an error for each unknown id and exits with status 1 before writing output. See [actions, defaults and Android key-schedule limits](../README.md#report-or-block).
- `--strict`: print an error for every unknown check group, write nothing, and exit with status 1, instead of skipping it with a warning.
- `--output` (`output=`): where to write the protected app; an existing file at that path is refused. The command line defaults to `<name>-protected<extension>` next to the app, such as `app-protected.apk` for `app.apk`.
- `--mapping` (Android): the app's R8 or ProGuard mapping file, so the packer finds the app's own classes after R8 renamed them.
- `--pin-certificate` (Android): the certificate the app will be signed with, PEM or DER. The protected app then works only when it is signed with that certificate.
- `--json`: prints the result as one JSON object with sorted keys instead of text: `build_id`, `checks` (an array of check ids), `output` (the path as a string), `package_name`, `skipped_checks` (an array of check ids) and `version`. Warnings still go to stderr.

`pack` returns a result with:

- the path of the protected app (`output`)
- the app's package name (`package_name`), version (`version`) and build id (`build_id`)
- the check groups the app runs (`checks`)
- the check groups it skipped (`skipped_checks`)

## How do report-only and block change what a check does?

A group is Off when it is omitted from the resolved `--checks` list; monitoring skips it. Startup and Android
loader checkpoints may still observe it, but those detections arm no panic. An enabled group set to `report`
reports through monitoring plugins (including ADR) and arms no panic at startup, in monitoring or at checkpoints.
An enabled group set to `block` arms the delayed process end on detection at any of those call sites.
Previously, startup and checkpoint detections blocked the app regardless of `--checks`.

If the runtime can read neither the enabled-check mask nor the check list, every detection uses `block`.
Enabled groups also use `block` when action metadata is missing. Unknown runtime signals and platform groups also block. Android's independent DEX key schedule
is unchanged by Off and report-only. See the [defaults and remaining key-schedule limits](../README.md#report-or-block).

## How do I sign the protected app?

The packer returns the app unsigned and prints a reminder after a successful `rasp pack`. Sign it with your upload key (Play App Signing then signs the copy users install) or your release key, and on iOS with your distribution certificate and provisioning profile.

## How do I check whether an app is protected?

**`rasp inspect`** opens a built app, never modifies it, and reports whether it carries the RASP runtime. For a protected app it also prints each group's action, the build id and the check groups from the runtime's config, and on Android the ABIs that carry the runtime. It does not run the app, so it cannot tell whether a check actually fires, only that the runtime and its config are present.

```
rasp inspect app-protected.apk --platform android
```

```
protected  yes
package    com.example.app
version    2.4.1
build id   my-build-1
checks     debugger,hooks,identity,root
actions    debugger=block,hooks=block,identity=block,root=report
abis       arm64-v8a,armeabi-v7a
```

For an app without the runtime, `inspect` prints `protected  no` with the package and version and exits 0.
With `--json`, `inspect` prints a single object with these keys.

- `abis` lists the Android ABIs that carry the runtime.
- `actions` maps enabled check group IDs to `report` or `block`. It is empty for an unprotected app or a config
  written before actions.
- `build_id` is the build ID string or null for an unprotected app.
- `checks` lists the IDs of enabled check groups.
- `package_name` is the app's package name or iOS bundle ID.
- `protected` is true when the app carries the runtime.
- `version` is the app's version string.

`checks` and `abis` are always present. Both are empty arrays for an unprotected app, and `abis` is also empty on iOS.
From Python, `rasp_packer.inspection.inspect(app=pathlib.Path("app-protected.apk"), platform=platforms.Platform.ANDROID)`
returns the same fields.

A protected app packed before actions has no `r` key, so `inspect` cannot infer its runtime behavior from the config.
It omits the text `actions` line and returns an empty `actions` object in JSON. The action-aware runtime keeps
every enabled group on `block` when it reads a config without `r`.

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

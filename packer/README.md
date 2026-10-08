# Packer

Adds the RASP runtime to a built app: an APK for Android, an IPA for iOS. The packer returns the protected app unsigned: the customer signs it before shipping it.

The packer is a library. `rasp_packer.packer.pack` is its entry point, and the `rasp` command line is a thin client of it, so a job can pack an app without starting a process.

```python
import pathlib
import uuid

from rasp_packer import packer
from rasp_packer import platforms

result = packer.pack(
    app=pathlib.Path("app.ipa"),
    platform=platforms.Platform.IOS,
    output=pathlib.Path("app-protected.ipa"),
    rasp_app_id=uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90"),
)
```

```
rasp pack app.ipa --platform ios --rasp-app-id 5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90 --output app-protected.ipa
```

## Layout

- `src/rasp_packer/packer.py`: `pack`, the entry point.
- `src/rasp_packer/platforms.py`: the platforms, Android and iOS.
- `src/rasp_packer/build.py`: the identity of a protected build (the app id and a new build id).
- `src/rasp_packer/cli.py`: the `rasp` command line.
- `src/rasp_packer/android/`, `src/rasp_packer/ios/`: packing of each platform.
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

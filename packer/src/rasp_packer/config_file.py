"""Reads the options of `rasp pack <platform>` from a TOML config file."""

import collections.abc
import dataclasses
import pathlib
import tomllib

from rasp_packer import errors
from rasp_packer import platforms

_SHARED_KEYS = frozenset({"build-id", "output", "checks", "strict", "json"})
_PLATFORM_KEYS: dict[platforms.Platform, frozenset[str]] = {
    platforms.Platform.ANDROID: _SHARED_KEYS | {"mapping", "pin-certificate"},
    platforms.Platform.IOS: _SHARED_KEYS,
}


@dataclasses.dataclass(frozen=True)
class PackOptions:
    """The options a config file sets for one platform's pack; None or False where it sets nothing."""

    build_id: str | None = None
    output: pathlib.Path | None = None
    checks: tuple[str, ...] | None = None
    strict: bool = False
    json: bool = False
    mapping: pathlib.Path | None = None
    pin_certificate: pathlib.Path | None = None


@dataclasses.dataclass(frozen=True)
class _Table:
    """One platform's table of a config file, whose values are read with their type checked."""

    file: pathlib.Path
    platform: platforms.Platform
    values: collections.abc.Mapping[str, object]

    def string(self, key: str) -> str | None:
        """Returns the key's string, or None when the table does not set it."""
        value = self.values.get(key)
        if value is None or isinstance(value, str):
            return value
        raise self._wrong_type(key, "a string")

    def path(self, key: str) -> pathlib.Path | None:
        """Returns the key's path resolved against the file's directory, or None when the table does not set it."""
        value = self.string(key)
        if value is None:
            return None
        return self.file.parent / value

    def strings(self, key: str) -> tuple[str, ...] | None:
        """Returns the key's array of strings, or None when the table does not set it."""
        value = self.values.get(key)
        if value is None:
            return None
        if not isinstance(value, list):
            raise self._wrong_type(key, "an array of strings")
        strings = tuple(item for item in value if isinstance(item, str))
        if len(strings) != len(value):
            raise self._wrong_type(key, "an array of strings")
        if len(strings) == 0:
            raise errors.InvalidConfigFileError(
                f"{self.file}: {key!r} in [{self.platform}] must name at least one value"
            )
        return strings

    def boolean(self, key: str) -> bool:
        """Returns the key's boolean, or False when the table does not set it."""
        value = self.values.get(key, False)
        if isinstance(value, bool):
            return value
        raise self._wrong_type(key, "a boolean")

    def _wrong_type(self, key: str, expected: str) -> errors.InvalidConfigFileError:
        """Returns the error saying the key's value is not of the expected type."""
        return errors.InvalidConfigFileError(
            f"{self.file}: {key!r} in [{self.platform}] must be {expected}"
        )


def read(path: pathlib.Path, platform: platforms.Platform) -> PackOptions:
    """Reads the options the config file sets in the platform's table.

    Raises:
        errors.InvalidConfigFileError: The file cannot be read, or is not a valid config file for the platform.
    """
    table = _platform_table(path, platform)
    return PackOptions(
        build_id=table.string("build-id"),
        output=table.path("output"),
        checks=table.strings("checks"),
        strict=table.boolean("strict"),
        json=table.boolean("json"),
        mapping=table.path("mapping"),
        pin_certificate=table.path("pin-certificate"),
    )


def _platform_table(path: pathlib.Path, platform: platforms.Platform) -> _Table:
    """Returns the platform's table of the file, empty when the file has none, after refusing unknown tables and keys."""
    document = _load(path)
    tables = " and ".join(f"[{each}]" for each in platforms.Platform)
    values: collections.abc.Mapping[str, object] = {}
    for name, value in document.items():
        if not isinstance(value, dict):
            raise errors.InvalidConfigFileError(
                f"{path}: {name!r} is outside a table; the tables are {tables}"
            )
        if name not in {each.value for each in platforms.Platform}:
            raise errors.InvalidConfigFileError(
                f"{path}: unknown table [{name}]; the tables are {tables}"
            )
        if name == platform:
            values = value
    for key in values:
        if key not in _PLATFORM_KEYS[platform]:
            raise errors.InvalidConfigFileError(
                f"{path}: {key!r} in [{platform}] is not an option of rasp pack {platform}"
            )
    return _Table(file=path, platform=platform, values=values)


def _load(path: pathlib.Path) -> dict[str, object]:
    """Returns the file parsed as TOML."""
    try:
        content = path.read_bytes()
    except OSError as error:
        raise errors.InvalidConfigFileError(
            f"{path}: cannot read the config file: {error.strerror}"
        ) from error
    try:
        return tomllib.loads(content.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise errors.InvalidConfigFileError(
            f"{path}: not valid TOML: {error}"
        ) from error

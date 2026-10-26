"""Plugin bundles: the plugins the packer adds next to the runtime.

A plugin adds checks to the runtime and sees each pass's observations, through the C API in
`runtime/core/include/rasp/plugin.h`. A plugin bundle is a directory that holds:

- `plugin.json`: the plugin's `name`, `version` and `api_version`;
- `android/<abi>/librasp_plugin_<name>.so`: its Android library for each ABI it is built for, if any;
- `ios/rasp_plugin_<name>.framework`: its iOS framework, if any;
- `config`: bytes the runtime gives the plugin when it starts it, at most 64 KiB, if any.

The runtime loads the plugins in the order the packer lists them.
"""

import collections
import collections.abc
import dataclasses
import json
import pathlib
import re

from rasp_packer import errors

PLUGIN_API_VERSION = 1
MAX_PLUGINS = 16
MAX_CONFIG_SIZE = 64 * 1024
MANIFEST_FILE = "plugin.json"
CONFIG_FILE = "config"
ANDROID_DIRECTORY = "android"
IOS_DIRECTORY = "ios"

_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_MANIFEST_KEYS = frozenset({"name", "version", "api_version"})
_MAX_MANIFEST_SIZE = 64 * 1024
_MAX_VERSION_SIZE = 128
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_IOS_FRAMEWORK_FILES = ("Info.plist",)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Plugin:
    """A plugin bundle, read and checked.

    Attributes:
        name: The plugin's name, which its signals start with.
        version: The plugin's version.
        api_version: The plugin API version it was built for.
        android_libraries: Its Android library, by ABI. Empty when it has no Android build.
        ios_framework: Its iOS framework directory, or None when it has no iOS build.
        config: The bytes the runtime gives the plugin. Empty when it has none.
    """

    name: str
    version: str
    api_version: int
    android_libraries: collections.abc.Mapping[str, bytes]
    ios_framework: pathlib.Path | None
    config: bytes


def android_library_name(name: str) -> str:
    """Returns the file name of the Android library of the plugin `name`.

    Args:
        name: The plugin's name.

    Returns:
        `librasp_plugin_<name>.so`.
    """
    return f"librasp_plugin_{name}.so"


def ios_binary_name(name: str) -> str:
    """Returns the name of the binary of the iOS framework of the plugin `name`.

    Args:
        name: The plugin's name.

    Returns:
        `rasp_plugin_<name>`.
    """
    return f"rasp_plugin_{name}"


def ios_framework_name(name: str) -> str:
    """Returns the directory name of the iOS framework of the plugin `name`.

    Args:
        name: The plugin's name.

    Returns:
        `rasp_plugin_<name>.framework`.
    """
    return f"{ios_binary_name(name)}.framework"


def load_all(directories: collections.abc.Sequence[pathlib.Path]) -> tuple[Plugin, ...]:
    """Reads and checks plugin bundles, in load order.

    Args:
        directories: The bundle directories, in the order the runtime loads them.

    Returns:
        The plugins, in the same order.

    Raises:
        InvalidPluginError: There are more than MAX_PLUGINS bundles, two share a name, or a
            bundle is malformed.
    """
    if len(directories) > MAX_PLUGINS:
        raise errors.InvalidPluginError(
            f"{len(directories)} plugins given, at most {MAX_PLUGINS} are supported"
        )
    plugins = tuple(load(directory) for directory in directories)
    counts = collections.Counter(plugin.name for plugin in plugins)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if len(duplicates) > 0:
        raise errors.InvalidPluginError(
            f"plugins given more than once: {', '.join(duplicates)}"
        )
    return plugins


def load(directory: pathlib.Path) -> Plugin:
    """Reads and checks one plugin bundle.

    Args:
        directory: The bundle directory.

    Returns:
        The plugin.

    Raises:
        InvalidPluginError: The bundle has no valid `plugin.json`, its name, version or API
            version is invalid, a build doesn't follow the naming convention, its config is
            larger than MAX_CONFIG_SIZE, or it has neither an Android nor an iOS build.
    """
    if directory.is_dir() is False:
        raise errors.InvalidPluginError(f"plugin bundle {directory} is not a directory")
    manifest = _read_manifest(directory / MANIFEST_FILE)
    name = _check_name(manifest.get("name"), directory)
    version = _check_version(manifest.get("version"), name)
    api_version = _check_api_version(manifest.get("api_version"), name)
    android_libraries = _read_android_libraries(directory / ANDROID_DIRECTORY, name)
    ios_framework = _find_ios_framework(directory / IOS_DIRECTORY, name)
    if len(android_libraries) == 0 and ios_framework is None:
        raise errors.InvalidPluginError(f"plugin {name} has no Android or iOS build")
    return Plugin(
        name=name,
        version=version,
        api_version=api_version,
        android_libraries=android_libraries,
        ios_framework=ios_framework,
        config=_read_config(directory / CONFIG_FILE, name),
    )


def plugin_list(plugins: collections.abc.Sequence[Plugin]) -> bytes:
    """Returns the plugin list the runtime reads: one name per line, in load order.

    Args:
        plugins: The plugins, in load order.

    Returns:
        The list, as UTF-8 text.
    """
    return "".join(f"{plugin.name}\n" for plugin in plugins).encode("utf-8")


def _read_manifest(path: pathlib.Path) -> dict[str, object]:
    """Reads `plugin.json`, which must be a JSON object with exactly the keys name, version and api_version."""
    if path.is_file() is False:
        raise errors.InvalidPluginError(f"{path} not found")
    if path.stat().st_size > _MAX_MANIFEST_SIZE:
        raise errors.InvalidPluginError(
            f"{path} is larger than {_MAX_MANIFEST_SIZE} bytes"
        )
    try:
        manifest = json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise errors.InvalidPluginError(f"cannot read {path}: {error}") from error
    if not isinstance(manifest, dict):
        raise errors.InvalidPluginError(f"{path} is not a JSON object")
    if set(manifest) != _MANIFEST_KEYS:
        raise errors.InvalidPluginError(
            f"{path} must hold exactly the keys {', '.join(sorted(_MANIFEST_KEYS))}"
        )
    return manifest


def _check_name(name: object, directory: pathlib.Path) -> str:
    """Returns the plugin's name when it matches `[a-z][a-z0-9_]{0,31}`."""
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise errors.InvalidPluginError(
            f"plugin bundle {directory} has the name {name!r}, which doesn't match [a-z][a-z0-9_]{{0,31}}"
        )
    return name


def _check_version(version: object, name: str) -> str:
    """Returns the plugin's version when it is a non-empty string the runtime accepts."""
    if (
        not isinstance(version, str)
        or len(version) == 0
        or len(version.encode("utf-8")) > _MAX_VERSION_SIZE
        or _CONTROL_CHARACTERS.search(version) is not None
    ):
        raise errors.InvalidPluginError(
            f"plugin {name} has the version {version!r}: a version is 1 to {_MAX_VERSION_SIZE} bytes, without control characters"
        )
    return version


def _check_api_version(api_version: object, name: str) -> int:
    """Returns the plugin's API version when this packer's runtime supports it."""
    if (
        not isinstance(api_version, int)
        or isinstance(api_version, bool)
        or api_version < 1
        or api_version > PLUGIN_API_VERSION
    ):
        raise errors.InvalidPluginError(
            f"plugin {name} is built for API version {api_version!r}, and the runtime supports 1 to {PLUGIN_API_VERSION}"
        )
    return api_version


def _read_android_libraries(directory: pathlib.Path, name: str) -> dict[str, bytes]:
    """Reads the plugin's Android library for each ABI folder, which must hold exactly that library."""
    if directory.exists() is False:
        return {}
    _check_real_directory(directory, name)
    expected = android_library_name(name)
    libraries: dict[str, bytes] = {}
    for abi in sorted(directory.iterdir()):
        _check_real_directory(abi, name)
        found = sorted(entry.name for entry in abi.iterdir())
        library = abi / expected
        if found != [expected] or library.is_symlink() is True:
            raise errors.InvalidPluginError(
                f"plugin {name}: {abi} must hold only the file {expected}"
            )
        libraries[abi.name] = library.read_bytes()
    if len(libraries) == 0:
        raise errors.InvalidPluginError(f"plugin {name}: {directory} holds no ABI")
    return libraries


def _find_ios_framework(directory: pathlib.Path, name: str) -> pathlib.Path | None:
    """Returns the plugin's iOS framework, which must be the only entry of the folder and hold its binary and Info.plist."""
    if directory.exists() is False:
        return None
    _check_real_directory(directory, name)
    expected = ios_framework_name(name)
    found = sorted(entry.name for entry in directory.iterdir())
    framework = directory / expected
    if found != [expected]:
        raise errors.InvalidPluginError(
            f"plugin {name}: {directory} must hold only the framework {expected}"
        )
    _check_real_directory(framework, name)
    for file_name in (ios_binary_name(name), *_IOS_FRAMEWORK_FILES):
        if (framework / file_name).is_file() is False:
            raise errors.InvalidPluginError(
                f"plugin {name}: {framework} has no {file_name}"
            )
    links = sorted(
        str(path) for path in framework.rglob("*") if path.is_symlink() is True
    )
    if len(links) > 0:
        raise errors.InvalidPluginError(
            f"plugin {name}: symbolic links are not supported: {', '.join(links)}"
        )
    return framework


def _read_config(path: pathlib.Path, name: str) -> bytes:
    """Reads the plugin's config, which is optional and at most MAX_CONFIG_SIZE bytes."""
    if path.exists() is False:
        return b""
    if path.is_file() is False or path.is_symlink() is True:
        raise errors.InvalidPluginError(f"plugin {name}: {path} is not a file")
    if path.stat().st_size > MAX_CONFIG_SIZE:
        raise errors.InvalidPluginError(
            f"plugin {name}: {path} is larger than {MAX_CONFIG_SIZE} bytes"
        )
    return path.read_bytes()


def _check_real_directory(path: pathlib.Path, name: str) -> None:
    """Refuses a path that is not a directory, or is a symbolic link to one."""
    if path.is_dir() is False or path.is_symlink() is True:
        raise errors.InvalidPluginError(f"plugin {name}: {path} is not a directory")

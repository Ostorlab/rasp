"""Unpacking and repacking of an IPA.

An IPA is a zip archive with the app bundle at `Payload/<Name>.app/`. The bundle holds the main
executable, named by `CFBundleExecutable` in its `Info.plist`, and its frameworks under `Frameworks/`.
The `Info.plist` also gives the app's identity: `CFBundleIdentifier` and `CFBundleShortVersionString`.
"""

import dataclasses
import os
import pathlib
import plistlib
import stat
import zipfile
import zlib
from typing import Any
from xml.parsers import expat

from rasp_packer import archive_validation
from rasp_packer import errors
from rasp_packer import identity

_PAYLOAD = "Payload"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AppBundle:
    """The app bundle of an extracted IPA.

    Attributes:
        payload_dir: The `Payload` directory.
        app_dir: The `<Name>.app` directory.
        executable: The main executable of the app.
        identity: The app's bundle identifier and short version string.
    """

    payload_dir: pathlib.Path
    app_dir: pathlib.Path
    executable: pathlib.Path
    identity: identity.AppIdentity

    @property
    def frameworks_dir(self) -> pathlib.Path:
        """The directory of the frameworks the app embeds."""
        return self.app_dir / "Frameworks"


def extract(ipa: pathlib.Path, destination: pathlib.Path) -> AppBundle:
    """Extracts an IPA and finds its app bundle.

    File permissions are restored from the archive, so the main executable stays executable.

    Args:
        ipa: Path to the IPA.
        destination: An empty directory to extract into.

    Returns:
        The app bundle.

    Raises:
        InvalidAppError: The file cannot be read or is not a zip archive, an entry would be
            written outside the destination, an entry is a symbolic link, the content is too large,
            or the archive does not hold exactly one app bundle with an `Info.plist` naming an
            existing executable.
    """
    try:
        archive_validation.check_file(ipa)
        archive = zipfile.ZipFile(ipa)
    except zipfile.BadZipFile as error:
        raise errors.InvalidAppError(f"{ipa} is not a zip archive") from error
    except OSError as error:
        raise errors.InvalidAppError(f"cannot read {ipa}: {error.strerror}") from error
    try:
        with archive:
            entries = archive.infolist()
            archive_validation.check_entries(entries)
            root = destination.resolve()
            for entry in entries:
                target = (destination / entry.filename).resolve()
                if target != root and root not in target.parents:
                    raise errors.InvalidAppError(
                        f"the entry {entry.filename} is outside the archive root"
                    )
            for entry in entries:
                path = pathlib.Path(archive.extract(entry, destination))
                mode = _mode(entry)
                if mode != 0:
                    os.chmod(path, mode)
    except (
        zipfile.BadZipFile,
        OSError,
        RuntimeError,
        NotImplementedError,
        EOFError,
        zlib.error,
    ) as error:
        raise errors.InvalidAppError(f"cannot extract IPA: {error}") from error
    return _find_bundle(destination / _PAYLOAD)


def archive(payload_dir: pathlib.Path, output: pathlib.Path) -> None:
    """Writes a `Payload` directory to an IPA, keeping file permissions.

    Args:
        payload_dir: The `Payload` directory.
        output: Path of the IPA to write.

    Raises:
        InvalidAppError: The directory holds a symbolic link.
    """
    root = payload_dir.parent
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as out:
        for path in sorted(payload_dir.rglob("*")):
            if path.is_symlink() is True:
                raise errors.InvalidAppError(
                    f"symbolic links are not supported: {path.relative_to(root)}"
                )
            entry = zipfile.ZipInfo.from_file(
                path, path.relative_to(root).as_posix(), strict_timestamps=False
            )
            if path.is_dir() is True:
                out.writestr(entry, b"")
            else:
                entry.compress_type = zipfile.ZIP_DEFLATED
                out.writestr(entry, path.read_bytes())


def _mode(entry: zipfile.ZipInfo) -> int:
    return stat.S_IMODE(entry.external_attr >> 16)


def _find_bundle(payload_dir: pathlib.Path) -> AppBundle:
    if payload_dir.is_dir() is False:
        raise errors.InvalidAppError("the archive has no Payload directory")
    apps = [
        path
        for path in payload_dir.iterdir()
        if path.is_dir() is True and path.suffix == ".app"
    ]
    if len(apps) != 1:
        raise errors.InvalidAppError(
            f"Payload holds {len(apps)} app bundles, expected 1"
        )
    app_dir = apps[0]
    info = read_info(app_dir / "Info.plist")
    executable = app_dir / _executable_name(info)
    if executable.is_file() is False:
        raise errors.InvalidAppError(
            f"the main executable {executable.name} is missing"
        )
    return AppBundle(
        payload_dir=payload_dir,
        app_dir=app_dir,
        executable=executable,
        identity=identity.AppIdentity(
            package_name=_info_string(info, "CFBundleIdentifier"),
            version=_info_string(info, "CFBundleShortVersionString"),
        ),
    )


def read_info(info_plist: pathlib.Path) -> dict[str, Any]:
    """Reads the app's `Info.plist`, which must be a dictionary."""
    if info_plist.is_file() is False:
        raise errors.InvalidAppError("the app bundle has no Info.plist")
    try:
        info = plistlib.loads(info_plist.read_bytes())
    except (ValueError, expat.ExpatError) as error:
        raise errors.InvalidAppError(
            "the app's Info.plist is not a property list"
        ) from error
    if not isinstance(info, dict):
        raise errors.InvalidAppError("the app's Info.plist is not a dictionary")
    return info


def _executable_name(info: dict[str, Any]) -> str:
    """Returns the main executable's file name, which must not leave the app bundle."""
    name = _info_string(info, "CFBundleExecutable")
    if "/" in name:
        raise errors.InvalidAppError(
            "the app's Info.plist has no valid CFBundleExecutable"
        )
    return name


def _info_string(info: dict[str, Any], key: str) -> str:
    """Returns the non-empty string the `Info.plist` holds at `key`."""
    value = info.get(key)
    if not isinstance(value, str) or value == "":
        raise errors.InvalidAppError(f"the app's Info.plist has no valid {key}")
    return value

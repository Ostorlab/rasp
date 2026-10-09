"""Unpacking and repacking of an IPA.

An IPA is a zip archive with the app bundle at `Payload/<Name>.app/`. The bundle holds the main
executable, named by `CFBundleExecutable` in its `Info.plist`, and its frameworks under `Frameworks/`.
"""

import dataclasses
import os
import pathlib
import plistlib
import stat
import zipfile
from xml.parsers import expat

from rasp_packer import errors

_PAYLOAD = "Payload"
_MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AppBundle:
    """The app bundle of an extracted IPA.

    Attributes:
        payload_dir: The `Payload` directory.
        app_dir: The `<Name>.app` directory.
        executable: The main executable of the app.
    """

    payload_dir: pathlib.Path
    app_dir: pathlib.Path
    executable: pathlib.Path

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
        InvalidAppError: The file is not a zip archive, an entry would be written outside the
            destination, an entry is a symbolic link, the content is too large, or the archive does
            not hold exactly one app bundle with an `Info.plist` naming an existing executable.
    """
    try:
        archive = zipfile.ZipFile(ipa)
    except zipfile.BadZipFile as error:
        raise errors.InvalidAppError(f"{ipa} is not a zip archive") from error
    with archive:
        entries = archive.infolist()
        _check_entries(entries, destination)
        for entry in entries:
            path = pathlib.Path(archive.extract(entry, destination))
            mode = _mode(entry)
            if mode != 0:
                os.chmod(path, mode)
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


def _check_entries(entries: list[zipfile.ZipInfo], destination: pathlib.Path) -> None:
    root = destination.resolve()
    if sum(entry.file_size for entry in entries) > _MAX_EXTRACTED_BYTES:
        raise errors.InvalidAppError(
            f"the archive holds more than {_MAX_EXTRACTED_BYTES} bytes"
        )
    for entry in entries:
        if stat.S_ISLNK(entry.external_attr >> 16) is True:
            raise errors.InvalidAppError(
                f"symbolic links are not supported: {entry.filename}"
            )
        target = (destination / entry.filename).resolve()
        if target != root and root not in target.parents:
            raise errors.InvalidAppError(
                f"the entry {entry.filename} is outside the archive root"
            )


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
    executable = app_dir / _executable_name(app_dir / "Info.plist")
    if executable.is_file() is False:
        raise errors.InvalidAppError(
            f"the main executable {executable.name} is missing"
        )
    return AppBundle(payload_dir=payload_dir, app_dir=app_dir, executable=executable)


def _executable_name(info_plist: pathlib.Path) -> str:
    if info_plist.is_file() is False:
        raise errors.InvalidAppError("the app bundle has no Info.plist")
    try:
        info = plistlib.loads(info_plist.read_bytes())
    except (ValueError, expat.ExpatError) as error:
        raise errors.InvalidAppError(
            "the app's Info.plist is not a property list"
        ) from error
    name = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    if not isinstance(name, str) or name == "" or "/" in name:
        raise errors.InvalidAppError(
            "the app's Info.plist has no valid CFBundleExecutable"
        )
    return name

"""Shared ZIP trust-boundary limits and canonical member paths."""

from __future__ import annotations

import collections.abc
import pathlib
import re
import stat
import zipfile

from rasp_packer import errors

_MAX_ARCHIVE_BYTES = 4 * 1024**3
_MAX_MEMBER_BYTES = _MAX_ARCHIVE_BYTES
_MAX_RUNTIME_BYTES = 256 * 1024**2
_MAX_ENTRIES = 100_000
_MAX_MANIFEST_BYTES = 4 * 1024**2


def check(app: pathlib.Path) -> None:
    """Bound archive metadata and reads and refuse aliases, links and encryption."""
    check_file(app)
    with zipfile.ZipFile(app) as archive:
        check_entries(archive.infolist())


def check_file(app: pathlib.Path) -> None:
    """Bound ZIP metadata input before constructing the ZIP reader."""
    if app.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise errors.InvalidAppError("archive exceeds the 4 GiB limit")


def check_entries(infos: collections.abc.Sequence[zipfile.ZipInfo]) -> None:
    """Validate all entries before decompression or filesystem extraction."""
    if (
        len(infos) > _MAX_ENTRIES
        or sum(info.file_size for info in infos) > _MAX_ARCHIVE_BYTES
    ):
        raise errors.InvalidAppError("archive exceeds verification entry/size limits")
    names: set[str] = set()
    for info in infos:
        name = info.filename.removesuffix("/")
        if name in names:
            raise errors.InvalidAppError(f"duplicate archive entry: {name}")
        names.add(name)
        if (
            name == ""
            or "\\" in name
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or re.search(r"[\x00-\x1f\x7f:]", name) is not None
            or info.orig_filename != info.filename
        ):
            raise errors.InvalidAppError(
                f"ambiguous archive path (possibly outside the archive root): {info.orig_filename!r}"
            )
        if stat.S_ISLNK(info.external_attr >> 16) is True:
            raise errors.InvalidAppError(f"symbolic links are not supported: {name}")
        if info.flag_bits & 1 != 0:
            raise errors.InvalidAppError(f"encrypted archive entry: {name}")
        limit = (
            _MAX_MANIFEST_BYTES
            if pathlib.PurePosixPath(name).name in {"AndroidManifest.xml", "Info.plist"}
            else _MAX_RUNTIME_BYTES
            if pathlib.PurePosixPath(name).name in {"librasp.so", "RaspRuntime"}
            else _MAX_MEMBER_BYTES
        )
        if info.file_size > limit:
            raise errors.InvalidAppError(
                f"archive member exceeds size limit once uncompressed: {name}"
            )
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise errors.InvalidAppError(
                f"archive uses compression the runtime can't decompress: {name}"
            )
    files = {info.filename for info in infos if info.is_dir() is False}
    for name in names:
        if any(
            parent.as_posix() in files for parent in pathlib.PurePosixPath(name).parents
        ):
            raise errors.InvalidAppError(
                f"file/directory archive path conflict: {name}"
            )

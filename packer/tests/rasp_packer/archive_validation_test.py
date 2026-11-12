"""Shared ZIP boundary regression coverage, using real ZIP metadata."""

from __future__ import annotations

import pathlib
import stat
import zipfile

import pytest

from rasp_packer import archive_validation
from rasp_packer import errors


@pytest.mark.parametrize(
    "name",
    ["../escape", "a/../b", "a/./b", "a//b", "/root", "a\\b", "a:stream", "a\x00b"],
)
def testCheckEntries_whenPathAmbiguous_rejects(name: str) -> None:
    with pytest.raises(errors.InvalidAppError, match="path"):
        archive_validation.check_entries([zipfile.ZipInfo(name)])


@pytest.mark.parametrize("conflict", ["duplicate", "directory", "parent"])
def testCheckEntries_whenNamesConflict_rejects(conflict: str) -> None:
    names = {"duplicate": ["a", "a"], "directory": ["a", "a/"], "parent": ["a", "a/b"]}[
        conflict
    ]
    with pytest.raises(errors.InvalidAppError, match=r"duplicate|conflict"):
        archive_validation.check_entries([zipfile.ZipInfo(name) for name in names])


@pytest.mark.parametrize(
    "kind",
    ["member", "manifest", "entries", "total", "encrypted", "link", "compression"],
)
def testCheckEntries_whenLimitsExceededOrUnsupported_rejects(kind: str) -> None:
    entry = zipfile.ZipInfo("data")
    entries = [entry]
    if kind == "member":
        entry.filename = "lib/arm64-v8a/librasp.so"
        entry.orig_filename = entry.filename
        entry.file_size = 256 * 1024**2 + 1
    elif kind == "manifest":
        entry.filename = "base/manifest/AndroidManifest.xml"
        entry.file_size = 4 * 1024**2 + 1
    elif kind == "entries":
        entries *= 100_001
    elif kind == "total":
        entry.file_size = 4 * 1024**3 + 1
    elif kind == "encrypted":
        entry.flag_bits = 1
    elif kind == "link":
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    else:
        entry.compress_type = zipfile.ZIP_BZIP2
    with pytest.raises(errors.InvalidAppError):
        archive_validation.check_entries(entries)


def testCheck_whenLargeArchive_rejectsBeforeZipRead(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "large.zip"
    with path.open("wb") as stream:
        stream.truncate(4 * 1024**3 + 1)
    with pytest.raises(errors.InvalidAppError, match="4 GiB"):
        archive_validation.check(path)

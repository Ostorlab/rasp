"""Tests of the archive safety check."""

import pathlib
import zipfile

from rasp_packer import archive_safety

# The Unix mode of a symbolic link, in the high half of a zip entry's external attributes.
_SYMLINK_EXTERNAL_ATTR = (0o120777) << 16


def _write_zip(path: pathlib.Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"data")


def testIsDangerous_whenEveryEntryStaysInRoot_returnsFalse(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["classes.dex", "res/layout/main.xml", "AndroidManifest.xml"])

    assert archive_safety.is_dangerous(app) is False


def testIsDangerous_whenEntryHasParentComponent_returnsTrue(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["classes.dex", "../../etc/passwd"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryIsAbsolute_returnsTrue(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["/etc/passwd"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryHasBackslashSeparator_returnsTrue(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["..\\..\\windows\\system32"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryIsSymlink_returnsTrue(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    with zipfile.ZipFile(app, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = _SYMLINK_EXTERNAL_ATTR
        archive.writestr(info, b"/etc/passwd")

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenNameHasDoubleDotButNoParentComponent_returnsFalse(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["assets/a..b/c.txt"])

    assert archive_safety.is_dangerous(app) is False


def testIsDangerous_whenFileIsNotAZip_returnsFalse(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"not a zip archive")

    assert archive_safety.is_dangerous(app) is False


def testIsDangerous_whenFileIsMissing_returnsFalse(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "missing.apk"

    assert archive_safety.is_dangerous(app) is False

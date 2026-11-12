"""Tests of the archive safety check."""

import pathlib
import zipfile

from rasp_packer import archive_safety

# Bit 0 of a zip entry's general-purpose flags marks it encrypted.
_ENCRYPTED_FLAG = 0x1


def _write_zip(path: pathlib.Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"data")


def _mark_encrypted(path: pathlib.Path) -> None:
    """Sets the encrypted flag on every header of a single-entry zip, in place."""
    data = bytearray(path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = data.find(signature)
        while start != -1:
            data[start + flag_offset] |= _ENCRYPTED_FLAG
            start = data.find(signature, start + 4)
    path.write_bytes(data)


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


def testIsDangerous_whenEntryIsPosixAbsolute_returnsTrue(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["/etc/passwd"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryIsWindowsAbsolute_returnsTrue(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["C:\\Windows\\System32\\drivers\\etc\\hosts"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryTraversesWithBackslashes_returnsTrue(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["..\\..\\windows\\system32"])

    assert archive_safety.is_dangerous(app) is True


def testIsDangerous_whenEntryIsEncrypted_returnsTrue(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _write_zip(app, ["classes.dex"])
    _mark_encrypted(app)

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

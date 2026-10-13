"""Tests of APK reading and repacking."""

import pathlib
import struct
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer.android.apk import archive

_STORED = zipfile.ZIP_STORED
_DEFLATED = zipfile.ZIP_DEFLATED


def _build(path: pathlib.Path, entries: list[tuple[str, bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w") as zip_file:
        for name, data, compress_type in entries:
            zip_file.writestr(name, data, compress_type=compress_type)


def _data_offset(path: pathlib.Path, name: str) -> int:
    with zipfile.ZipFile(path) as zip_file:
        header = zip_file.getinfo(name).header_offset
    with path.open("rb") as stream:
        stream.seek(header + 26)
        name_length, extra_length = struct.unpack("<HH", stream.read(4))
    return int(header + 30 + name_length + extra_length)


def _edit_central_directory(path: pathlib.Path, offset: int, value: bytes) -> None:
    """Overwrites bytes of the first entry's central directory header, which zipfile reads entries from."""
    data = bytearray(path.read_bytes())
    header = data.index(b"PK\x01\x02")
    data[header + offset : header + offset + len(value)] = value
    path.write_bytes(bytes(data))


def testRead_whenValidApk_exposesEntriesNamesAndManifest(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(
        path,
        [
            ("AndroidManifest.xml", b"manifest", _STORED),
            ("classes.dex", b"dex", _DEFLATED),
        ],
    )
    app = archive.Apk.read(path)
    assert app.get("classes.dex") == b"dex"
    assert app.get("missing") is None
    assert app.names() == ["AndroidManifest.xml", "classes.dex"]
    assert app.manifest() == b"manifest"


def testDexNames_whenSeveralDexFiles_sortsThemByLoadOrder(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(
        path,
        [
            ("classes2.dex", b"2", _DEFLATED),
            ("classes.dex", b"1", _DEFLATED),
            ("classes10.dex", b"10", _DEFLATED),
            ("res/raw/classesX.dex", b"x", _DEFLATED),
            ("classesfoo.dex", b"foo", _DEFLATED),
        ],
    )
    app = archive.Apk.read(path)
    assert app.dex_names() == ["classes.dex", "classes2.dex", "classes10.dex"]


def testWrite_whenEntriesChange_replacesAddsAndRemovesThem(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.apk"
    output = tmp_path / "out.apk"
    _build(
        source,
        [
            ("AndroidManifest.xml", b"m", _STORED),
            ("classes.dex", b"old", _DEFLATED),
            ("classes2.dex", b"two", _DEFLATED),
        ],
    )
    archive.Apk.read(source).write(
        output,
        replace={"classes.dex": b"new"},
        add={"assets/rasp/payload.bin": b"payload"},
        remove={"classes2.dex"},
    )
    result = archive.Apk.read(output)
    assert result.get("classes.dex") == b"new"
    assert result.get("classes2.dex") is None
    assert result.get("assets/rasp/payload.bin") == b"payload"


def testWrite_whenEntriesKept_preservesTheirCompression(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "in.apk"
    output = tmp_path / "out.apk"
    _build(
        source,
        [
            ("resources.arsc", b"arsc", _STORED),
            ("classes.dex", b"dex", _DEFLATED),
        ],
    )
    archive.Apk.read(source).write(output, replace={}, add={}, remove=set())
    with zipfile.ZipFile(output) as zip_file:
        assert zip_file.getinfo("resources.arsc").compress_type == _STORED
        assert zip_file.getinfo("classes.dex").compress_type == _DEFLATED


def testWrite_whenAddedNameExists_overwritesTheEntry(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "in.apk"
    output = tmp_path / "out.apk"
    _build(source, [("lib/arm64-v8a/librasp.so", b"old", _STORED)])
    archive.Apk.read(source).write(
        output,
        replace={},
        add={"lib/arm64-v8a/librasp.so": b"new"},
        remove=set(),
    )
    with zipfile.ZipFile(output) as zip_file:
        assert zip_file.namelist().count("lib/arm64-v8a/librasp.so") == 1
    assert archive.Apk.read(output).get("lib/arm64-v8a/librasp.so") == b"new"


def testWrite_whenEntriesStored_alignsThem(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "in.apk"
    output = tmp_path / "out.apk"
    _build(
        source,
        [
            ("AndroidManifest.xml", b"m", _STORED),
            ("lib/arm64-v8a/libexisting.so", b"a" * 1234, _STORED),
            ("resources.arsc", b"arsc" * 10, _STORED),
            ("classes.dex", b"dex", _DEFLATED),
        ],
    )
    archive.Apk.read(source).write(
        output,
        replace={},
        add={"lib/armeabi-v7a/librasp.so": b"b" * 4321},
        remove=set(),
    )
    assert _data_offset(output, "lib/arm64-v8a/libexisting.so") % 16384 == 0
    assert _data_offset(output, "lib/armeabi-v7a/librasp.so") % 16384 == 0
    assert _data_offset(output, "resources.arsc") % 4 == 0


def testWrite_whenSameInputs_writesTheSameBytes(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "in.apk"
    _build(
        source,
        [
            ("AndroidManifest.xml", b"m", _STORED),
            ("classes.dex", b"dex", _DEFLATED),
            ("lib/arm64-v8a/librasp.so", b"so", _STORED),
        ],
    )
    app = archive.Apk.read(source)
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    app.write(first, replace={}, add={"assets/x": b"x"}, remove=set())
    app.write(second, replace={}, add={"assets/x": b"x"}, remove=set())
    assert first.read_bytes() == second.read_bytes()


def testRead_whenNotAZip_raisesInvalidApkError(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "app.apk"
    path.write_bytes(b"not a zip file")

    with pytest.raises(errors.InvalidApkError):
        archive.Apk.read(path)


def testManifest_whenTheApkHasNoManifest_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", b"dex", _DEFLATED)])

    with pytest.raises(errors.InvalidApkError, match="has no AndroidManifest"):
        archive.Apk.read(path).manifest()


def testRead_whenTwoEntriesShareAName_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _build(
            path,
            [
                ("classes.dex", b"first", _DEFLATED),
                ("classes.dex", b"second", _DEFLATED),
            ],
        )

    with pytest.raises(errors.InvalidApkError, match="duplicate"):
        archive.Apk.read(path)


def testRead_whenAnEntryUsesBzip2_raisesInvalidApkError(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", b"dex", zipfile.ZIP_BZIP2)])

    with pytest.raises(errors.InvalidApkError, match="can't decompress"):
        archive.Apk.read(path)


def testRead_whenTheEntriesAreTooBigOnceUncompressed_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", b"dex", _DEFLATED)])
    _edit_central_directory(path, 24, struct.pack("<I", 1024 * 1024 * 1024 + 1))

    with pytest.raises(errors.InvalidApkError, match="once uncompressed"):
        archive.Apk.read(path)


def testRead_whenAnEntryIsEncrypted_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", b"dex", _DEFLATED)])
    _edit_central_directory(path, 8, struct.pack("<H", 0x0001))

    with pytest.raises(errors.InvalidApkError):
        archive.Apk.read(path)


def testRead_whenAnEntryIsCorrupt_raisesInvalidApkError(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", bytes(range(256)) * 64, _DEFLATED)])
    data = bytearray(path.read_bytes())
    start = 30 + len("classes.dex")
    data[start : start + 16] = b"\xff" * 16
    path.write_bytes(bytes(data))

    with pytest.raises(errors.InvalidApkError):
        archive.Apk.read(path)


def testRead_whenAnEntryIsCutShort_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(path, [("classes.dex", bytes(range(256)) * 64, _DEFLATED)])
    with zipfile.ZipFile(path) as zip_file:
        compressed_size = zip_file.getinfo("classes.dex").compress_size
    _edit_central_directory(path, 20, struct.pack("<I", compressed_size // 2))

    with pytest.raises(errors.InvalidApkError):
        archive.Apk.read(path)


def testDexNames_whenNamesAreNotOnesAndroidLoads_leavesThemOut(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.apk"
    _build(
        path,
        [
            ("classes.dex", b"1", _DEFLATED),
            ("classes0.dex", b"0", _DEFLATED),
            ("classes1.dex", b"1", _DEFLATED),
            ("classes02.dex", b"02", _DEFLATED),
            ("classes\u00b2.dex", b"superscript", _DEFLATED),
            ("classes2.dex", b"2", _DEFLATED),
        ],
    )

    assert archive.Apk.read(path).dex_names() == ["classes.dex", "classes2.dex"]

"""Tests of APK reading and repacking."""

import pathlib
import struct
import zipfile

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


def testRead_exposesEntriesNamesAndManifest(tmp_path: pathlib.Path) -> None:
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


def testDexNames_sortedByLoadOrderNotLexically(tmp_path: pathlib.Path) -> None:
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


def testWrite_replacesAddsAndRemoves(tmp_path: pathlib.Path) -> None:
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


def testWrite_preservesPerEntryCompression(tmp_path: pathlib.Path) -> None:
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


def testWrite_addOfExistingNameOverwritesInPlace(tmp_path: pathlib.Path) -> None:
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


def testWrite_alignsStoredEntries(tmp_path: pathlib.Path) -> None:
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


def testWrite_isReproducible(tmp_path: pathlib.Path) -> None:
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

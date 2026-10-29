"""Tests of AAB reading and repacking."""

import pathlib
import struct
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer.android.aab import archive

_STORED = zipfile.ZIP_STORED
_DEFLATED = zipfile.ZIP_DEFLATED


def _build(path: pathlib.Path, entries: list[tuple[str, bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w") as zip_file:
        for name, data, compress_type in entries:
            zip_file.writestr(name, data, compress_type=compress_type)


def _minimal_aab_entries() -> list[tuple[str, bytes, int]]:
    """Returns the entries of a minimal valid AAB."""
    return [
        ("BundleConfig.pb", b"config", _STORED),
        ("base/manifest/AndroidManifest.xml", b"proto-manifest", _STORED),
        ("base/dex/classes.dex", b"dex-data", _STORED),
        ("base/resources.pb", b"resources", _STORED),
    ]


def _edit_central_directory(path: pathlib.Path, offset: int, value: bytes) -> None:
    """Overwrites bytes of the first entry's central directory header."""
    data = bytearray(path.read_bytes())
    header = data.index(b"PK\x01\x02")
    data[header + offset : header + offset + len(value)] = value
    path.write_bytes(bytes(data))


def testRead_whenValidAab_exposesEntriesNamesAndManifest(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, _minimal_aab_entries())

    aab = archive.Aab.read(path)

    assert aab.get("base/dex/classes.dex") == b"dex-data"
    assert aab.get("missing") is None
    assert "BundleConfig.pb" in aab.names()
    assert "base/manifest/AndroidManifest.xml" in aab.names()
    assert aab.manifest() == b"proto-manifest"


def testDexNames_whenSeveralDexFiles_sortsThemByLoadOrder(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(
        path,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/manifest/AndroidManifest.xml", b"manifest", _STORED),
            ("base/dex/classes2.dex", b"2", _STORED),
            ("base/dex/classes.dex", b"1", _STORED),
            ("base/dex/classes10.dex", b"10", _STORED),
        ],
    )

    aab = archive.Aab.read(path)

    assert aab.dex_names() == [
        "base/dex/classes.dex",
        "base/dex/classes2.dex",
        "base/dex/classes10.dex",
    ]


def testDexNames_whenDexFilesOutsideBaseDex_ignoresThem(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(
        path,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/manifest/AndroidManifest.xml", b"manifest", _STORED),
            ("base/dex/classes.dex", b"1", _STORED),
            ("classes.dex", b"root-level", _STORED),
            ("feature/dex/classes.dex", b"feature-level", _STORED),
        ],
    )

    aab = archive.Aab.read(path)

    assert aab.dex_names() == ["base/dex/classes.dex"]


def testDexNames_whenNamesAreNotOnesAndroidLoads_leavesThemOut(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(
        path,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/manifest/AndroidManifest.xml", b"manifest", _STORED),
            ("base/dex/classes.dex", b"1", _STORED),
            ("base/dex/classes0.dex", b"0", _STORED),
            ("base/dex/classes1.dex", b"1b", _STORED),
            ("base/dex/classes02.dex", b"02", _STORED),
            ("base/dex/classes2.dex", b"2", _STORED),
        ],
    )

    aab = archive.Aab.read(path)

    assert aab.dex_names() == ["base/dex/classes.dex", "base/dex/classes2.dex"]


def testWrite_whenEntriesChange_replacesAddsAndRemovesThem(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(source, _minimal_aab_entries())

    archive.Aab.read(source).write(
        output,
        replace={"base/dex/classes.dex": b"new-dex"},
        add={"base/assets/rasp/payload.bin": b"payload"},
        remove={"base/resources.pb"},
    )

    result = archive.Aab.read(output)
    assert result.get("base/dex/classes.dex") == b"new-dex"
    assert result.get("base/resources.pb") is None
    assert result.get("base/assets/rasp/payload.bin") == b"payload"


def testWrite_whenEntriesKept_preservesTheirCompression(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(
        source,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/manifest/AndroidManifest.xml", b"manifest", _DEFLATED),
            ("base/dex/classes.dex", b"dex", _STORED),
        ],
    )

    archive.Aab.read(source).write(output, replace={}, add={}, remove=set())

    with zipfile.ZipFile(output) as zip_file:
        assert zip_file.getinfo("BundleConfig.pb").compress_type == _STORED
        assert (
            zip_file.getinfo("base/manifest/AndroidManifest.xml").compress_type
            == _DEFLATED
        )
        assert zip_file.getinfo("base/dex/classes.dex").compress_type == _STORED


def testWrite_whenAddedNameExists_overwritesTheEntry(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(
        source,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/lib/arm64-v8a/librasp.so", b"old", _STORED),
        ],
    )

    archive.Aab.read(source).write(
        output,
        replace={},
        add={"base/lib/arm64-v8a/librasp.so": b"new"},
        remove=set(),
    )

    with zipfile.ZipFile(output) as zip_file:
        assert zip_file.namelist().count("base/lib/arm64-v8a/librasp.so") == 1
    assert archive.Aab.read(output).get("base/lib/arm64-v8a/librasp.so") == b"new"


def testWrite_whenNoAlignment_doesNotPadEntries(
    tmp_path: pathlib.Path,
) -> None:
    """AAB does not need zipalign -- Google Play handles alignment."""
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(
        source,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/lib/arm64-v8a/librasp.so", b"a" * 1234, _STORED),
        ],
    )

    archive.Aab.read(source).write(output, replace={}, add={}, remove=set())

    with zipfile.ZipFile(output) as zip_file:
        for info in zip_file.infolist():
            assert len(info.extra) == 0


def testWrite_whenSameInputs_writesTheSameBytes(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    _build(source, _minimal_aab_entries())

    aab = archive.Aab.read(source)
    first = tmp_path / "first.aab"
    second = tmp_path / "second.aab"
    aab.write(first, replace={}, add={"base/assets/x": b"x"}, remove=set())
    aab.write(second, replace={}, add={"base/assets/x": b"x"}, remove=set())

    assert first.read_bytes() == second.read_bytes()


def testRead_whenNotAZip_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    path.write_bytes(b"not a zip file")

    with pytest.raises(errors.InvalidAabError):
        archive.Aab.read(path)


def testManifest_whenTheAabHasNoManifest_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(
        path,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/dex/classes.dex", b"dex", _STORED),
        ],
    )

    with pytest.raises(errors.InvalidAabError, match="has no"):
        archive.Aab.read(path).manifest()


def testRead_whenTwoEntriesShareAName_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _build(
            path,
            [
                ("base/dex/classes.dex", b"first", _STORED),
                ("base/dex/classes.dex", b"second", _STORED),
            ],
        )

    with pytest.raises(errors.InvalidAabError, match="duplicate"):
        archive.Aab.read(path)


def testRead_whenAnEntryUsesBzip2_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, [("base/dex/classes.dex", b"dex", zipfile.ZIP_BZIP2)])

    with pytest.raises(errors.InvalidAabError, match="can't decompress"):
        archive.Aab.read(path)


def testRead_whenTheEntriesAreTooBigOnceUncompressed_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, [("base/dex/classes.dex", b"dex", _DEFLATED)])
    _edit_central_directory(path, 24, struct.pack("<I", 1024 * 1024 * 1024 + 1))

    with pytest.raises(errors.InvalidAabError, match="once uncompressed"):
        archive.Aab.read(path)


# ── _READ_ERRORS branch coverage ───────────────────────────


def testRead_whenAnEntryIsEncrypted_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, [("base/dex/classes.dex", b"dex", _DEFLATED)])
    _edit_central_directory(path, 8, struct.pack("<H", 0x0001))

    with pytest.raises(errors.InvalidAabError):
        archive.Aab.read(path)


def testRead_whenAnEntryIsCorrupt_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, [("base/dex/classes.dex", bytes(range(256)) * 64, _DEFLATED)])
    data = bytearray(path.read_bytes())
    start = 30 + len("base/dex/classes.dex")
    data[start : start + 16] = b"\xff" * 16
    path.write_bytes(bytes(data))

    with pytest.raises(errors.InvalidAabError):
        archive.Aab.read(path)


def testRead_whenAnEntryIsCutShort_raisesInvalidAabError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "app.aab"
    _build(path, [("base/dex/classes.dex", bytes(range(256)) * 64, _DEFLATED)])
    with zipfile.ZipFile(path) as zip_file:
        compressed_size = zip_file.getinfo("base/dex/classes.dex").compress_size
    _edit_central_directory(path, 20, struct.pack("<I", compressed_size // 2))

    with pytest.raises(errors.InvalidAabError):
        archive.Aab.read(path)


# ── write compression for add entries ───────────────────────


def testWrite_whenAddingNewEntry_storesItUncompressed(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(source, _minimal_aab_entries())

    archive.Aab.read(source).write(
        output,
        replace={},
        add={"base/assets/rasp/payload.bin": b"payload"},
        remove=set(),
    )

    with zipfile.ZipFile(output) as zip_file:
        assert zip_file.getinfo("base/assets/rasp/payload.bin").compress_type == _STORED


def testWrite_whenAddCollidesWithDeflatedEntry_keepsDeflated(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "in.aab"
    output = tmp_path / "out.aab"
    _build(
        source,
        [
            ("BundleConfig.pb", b"config", _STORED),
            ("base/lib/arm64-v8a/librasp.so", b"old-lib-data", _DEFLATED),
        ],
    )

    archive.Aab.read(source).write(
        output,
        replace={},
        add={"base/lib/arm64-v8a/librasp.so": b"new-lib-data"},
        remove=set(),
    )

    with zipfile.ZipFile(output) as zip_file:
        assert (
            zip_file.getinfo("base/lib/arm64-v8a/librasp.so").compress_type == _DEFLATED
        )
        assert zip_file.read("base/lib/arm64-v8a/librasp.so") == b"new-lib-data"

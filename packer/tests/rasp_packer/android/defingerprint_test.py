"""Tests of the per-app names and the stub dex patch that removes the packer's fingerprints."""

import random

import pytest

from rasp_packer.android import defingerprint
from rasp_packer.android import resources

_STUB_DEX = resources.load().stub_dex


def testGenerateNames_whenGivenTheSameSeed_repeatsTheNames() -> None:
    first = defingerprint.generate_names(random.Random(7), frozenset(), _STUB_DEX)
    second = defingerprint.generate_names(random.Random(7), frozenset(), _STUB_DEX)
    assert first == second


def testGenerateNames_drawsNamesOfTheRightShape() -> None:
    for seed in range(16):
        names = defingerprint.generate_names(
            random.Random(seed), frozenset(), _STUB_DEX
        )
        assert len(names.library_name) == 4
        assert names.library_filename == f"lib{names.library_name}.so"
        assert len(names.stub_class.encode("utf-8")) == len("co/ostorlab/rasp/RaspStub")
        assert len(names.arm_class.encode("utf-8")) == len("co/ostorlab/rasp/JArm")
        assert len(names.source_file.encode("utf-8")) == len("RaspStub.java")
        assert names.stub_class_dotted == names.stub_class.replace("/", ".")
        for banned in ("ostorlab", "rasp", "Rasp"):
            assert banned not in names.library_name
            assert banned not in names.stub_class
            assert banned not in names.arm_class
            assert banned not in names.source_file


def testGenerateNames_keepsEveryStringInsideItsRangeInTheSortedTable() -> None:
    ranges = defingerprint._string_ranges(_STUB_DEX)
    arm_range = ranges["Lco/ostorlab/rasp/JArm;"]
    stub_range = ranges["Lco/ostorlab/rasp/RaspStub;"]
    library_range = ranges["rasp"]
    assert arm_range.lower is not None
    assert stub_range.upper is not None
    assert library_range.lower is not None
    assert library_range.upper is not None
    for seed in range(16):
        names = defingerprint.generate_names(
            random.Random(seed), frozenset(), _STUB_DEX
        )
        stub = f"L{names.stub_class};"
        arm = f"L{names.arm_class};"
        assert arm_range.lower < arm
        assert arm < stub
        assert stub < stub_range.upper
        assert library_range.lower < names.library_name < library_range.upper


def testGenerateNames_whenAFilenameIsTaken_drawsAnother() -> None:
    taken: frozenset[str] = frozenset()
    for _ in range(16):
        names = defingerprint.generate_names(random.Random(3), taken, _STUB_DEX)
        taken = taken | {names.library_filename}
    assert len(taken) == 16


def testPatchStubDex_replacesEveryFingerprintWithTheNames() -> None:
    names = defingerprint.generate_names(random.Random(11), frozenset(), _STUB_DEX)
    patched = defingerprint.patch_stub_dex(
        _STUB_DEX,
        library_name=names.library_name,
        stub_class=names.stub_class,
        arm_class=names.arm_class,
        source_file=names.source_file,
    )
    assert len(patched) == len(_STUB_DEX)
    assert f"L{names.stub_class};".encode() in patched
    assert f"L{names.arm_class};".encode() in patched
    assert b"\x04" + names.library_name.encode("utf-8") + b"\x00" in patched
    for banned in (b"ostorlab", b"rasp", b"Rasp"):
        assert banned not in patched


def testPatchStubDex_keepsTheStringTableSortedAndTheHeaderConsistent() -> None:
    import hashlib
    import struct
    import zlib

    names = defingerprint.generate_names(random.Random(5), frozenset(), _STUB_DEX)
    patched = defingerprint.patch_stub_dex(
        _STUB_DEX,
        library_name=names.library_name,
        stub_class=names.stub_class,
        arm_class=names.arm_class,
        source_file=names.source_file,
    )
    # The table stays sorted, the format's requirement, and the header's checksum and signature
    # match the patched bytes.
    strings = defingerprint.dex_strings(patched)
    assert strings == sorted(strings)
    (checksum,) = struct.unpack_from("<I", patched, 8)
    assert checksum == zlib.adler32(patched[12:]) & 0xFFFFFFFF
    assert patched[12:32] == hashlib.sha1(patched[32:]).digest()


def testPatchStubDex_whenANameLeavesItsRange_refusesThePatch() -> None:
    # A name drawn outside its string's range breaks the table's order; the patch must refuse it
    # rather than ship a dex the runtime rejects. The stub class sorts far below the arm class,
    # which leaves both outside the table's order.
    with pytest.raises(ValueError, match="not sorted"):
        defingerprint.patch_stub_dex(
            _STUB_DEX,
            library_name="q0cq",
            stub_class="aa/" + "B" + "b" * 21,
            arm_class="zz/" + "C" + "c" * 17,
            source_file="a" * 13,
        )


def testPatchStubDex_whenALengthIsWrong_refusesThePatch() -> None:
    names = defingerprint.generate_names(random.Random(9), frozenset(), _STUB_DEX)
    for wrong in (
        {"library_name": "toolongname"},
        {"stub_class": "short"},
        {"arm_class": "short"},
        {"source_file": "short"},
    ):
        fields = {
            "library_name": names.library_name,
            "stub_class": names.stub_class,
            "arm_class": names.arm_class,
            "source_file": names.source_file,
        }
        fields.update(wrong)
        with pytest.raises(ValueError, match="must be"):
            defingerprint.patch_stub_dex(_STUB_DEX, **fields)

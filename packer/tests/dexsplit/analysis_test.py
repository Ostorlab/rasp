"""Tests for the DEX analysis the splitter reads, over a small committed DEX fixture."""

import gc
import hashlib
import pathlib
import struct
import zlib

import pytest

from dexsplit import _dex

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"
_CHANGE_PASSWORD = "Lcom/android/insecurebankv2/ChangePassword;"


def _context() -> _dex.AnalysisContext:
    return _dex.AnalysisContext.from_dex_buffers([_SAMPLE.read_bytes()])


def _with_bytes_in_a_class_name(replacement: bytes) -> bytes:
    """The sample DEX with `replacement` written over a class name, the checksums fixed."""
    data = bytearray(_SAMPLE.read_bytes())
    position = data.index(_CHANGE_PASSWORD.encode()) + 1
    data[position : position + len(replacement)] = replacement
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]))
    return bytes(data)


def _class(name: str) -> _dex.Class:
    for cls in _context().classes:
        if cls.name == name:
            return cls
    raise AssertionError(f"class not found: {name}")


def testClasses_whenValidDex_returnsEveryClass() -> None:
    names = [cls.name for cls in _context().classes]

    assert len(names) == 12
    assert _CHANGE_PASSWORD in names


def testClass_whenItHasASuperclass_namesItAsADescriptor() -> None:
    superclass = _class(_CHANGE_PASSWORD).superclass

    assert superclass is not None
    assert superclass.descriptor.startswith("L")
    assert superclass.descriptor.endswith(";")


def testClass_whenItHasCode_exposesItsMethods() -> None:
    methods = _class(_CHANGE_PASSWORD).methods

    assert len(methods) > 0


def testMethods_whenTheyHaveBodies_exposeCallsFieldsAndTypes() -> None:
    has_call = False
    has_field = False
    has_type = False
    for cls in _context().classes:
        for method in cls.methods:
            for call in method.calls:
                has_call = has_call or call.target.class_descriptor.startswith("L")
            for access in method.field_accesses:
                has_field = has_field or access.field.class_descriptor.startswith("L")
            for use in method.type_uses:
                has_type = has_type or len(use.descriptor) > 0

    assert has_call is True
    assert has_field is True
    assert has_type is True


@pytest.mark.parametrize(
    "replacement",
    [
        b"\xc2\x41",
        b"\xc0\x41",
        b"\xe0\x81\x81",
        b"\xf0\x9f\x98\x80",
        b"\xed\xa0\x80\xed\xb0\x41",
    ],
)
def testClasses_whenAClassNameIsMalformed_namesThatClassWithAnEmptyString(
    replacement: bytes,
) -> None:
    context = _dex.AnalysisContext.from_dex_buffers(
        [_with_bytes_in_a_class_name(replacement)]
    )

    names = [cls.name for cls in context.classes]

    assert len(names) == 12
    assert "" in names
    assert _CHANGE_PASSWORD not in names


def testClass_whenItImplementsAnInterface_namesItAsADescriptor() -> None:
    interfaces = _class("Lcom/android/insecurebankv2/ChangePassword$1;").interfaces

    assert [interface.descriptor for interface in interfaces] == [
        "Landroid/view/View$OnClickListener;"
    ]


def testClass_whenItImplementsNoInterface_hasNoInterfaces() -> None:
    assert _class(_CHANGE_PASSWORD).interfaces == []


def testTypeUse_whenTheContextIsGone_stillGivesItsDescriptor() -> None:
    context = _context()
    uses = [
        use
        for cls in context.classes
        for method in cls.methods
        for use in method.type_uses
    ]
    descriptors = [use.descriptor for use in uses]
    del context
    gc.collect()

    assert len(uses) > 0
    assert [use.descriptor for use in uses] == descriptors

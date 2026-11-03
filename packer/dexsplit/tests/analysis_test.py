"""Tests for the DEX analysis the splitter reads, over a small committed DEX fixture."""

import pathlib

from dexsplit import _dex

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"
_CHANGE_PASSWORD = "Lcom/android/insecurebankv2/ChangePassword;"


def _context() -> _dex.AnalysisContext:
    return _dex.AnalysisContext.from_dex_buffers([_SAMPLE.read_bytes()])


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

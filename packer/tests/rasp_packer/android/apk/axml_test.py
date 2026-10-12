"""Tests of the binary AndroidManifest.xml editor.

The fixtures are real manifests compiled with aapt2; see the .source.xml files
next to them.
"""

import pathlib

import pytest

from rasp_packer.android.apk import axml

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"
_STUB = "co.ostorlab.rasp.RaspStub"


def _with_application() -> bytes:
    return (_FIXTURES / "manifest_with_application.bin").read_bytes()


def _without_application() -> bytes:
    return (_FIXTURES / "manifest_without_application.bin").read_bytes()


def testReadApplicationClass_whenPresent_returnsName() -> None:
    assert (
        axml.read_application_class(_with_application()) == "com.example.withapp.MyApp"
    )


def testReadApplicationClass_whenAbsent_returnsNone() -> None:
    assert axml.read_application_class(_without_application()) is None


def testReadManifestPackage_whenValidManifest_returnsThePackage() -> None:
    assert axml.read_manifest_package(_with_application()) == "com.example.withapp"


def testSetApplicationClass_whenPresent_repointsTheName() -> None:
    edited = axml.set_application_class(_with_application(), _STUB)
    assert axml.read_application_class(edited) == _STUB


def testSetApplicationClass_whenAbsent_insertsTheName() -> None:
    edited = axml.set_application_class(_without_application(), _STUB)
    assert axml.read_application_class(edited) == _STUB


def testSetApplicationClass_whenNameSet_keepsOtherStringsReadable() -> None:
    edited = axml.set_application_class(_with_application(), _STUB)
    assert axml.read_manifest_package(edited) == "com.example.withapp"


def testSetApplicationClass_whenReapplied_returnsTheSameBytes() -> None:
    once = axml.set_application_class(_with_application(), _STUB)
    twice = axml.set_application_class(once, _STUB)
    assert once == twice


def testReadApplicationClass_whenNotAxml_raisesAxmlError() -> None:
    with pytest.raises(axml.AxmlError):
        axml.read_application_class(b"<manifest>plain text</manifest>")


def testSetApplicationClass_whenPresent_matchesTheAapt2Fixture() -> None:
    expected = (_FIXTURES / "manifest_with_application.stub.bin").read_bytes()
    assert axml.set_application_class(_with_application(), _STUB) == expected


def testSetApplicationClass_whenAbsent_matchesTheAapt2Fixture() -> None:
    expected = (_FIXTURES / "manifest_without_application.stub.bin").read_bytes()
    assert axml.set_application_class(_without_application(), _STUB) == expected


@pytest.mark.parametrize("is_utf8", [True, False])
@pytest.mark.parametrize(
    "text", ["co.ostorlab.rasp.RaspStub", "", "x", "astral \U0001f600 end"]
)
def testEncodeString_whenReadBack_givesTheSameText(text: str, is_utf8: bool) -> None:
    encoded = axml._encode_string(text, is_utf8)
    length, decoded = axml._read_string(encoded, 0, is_utf8)
    assert decoded == text
    assert length == len(encoded)

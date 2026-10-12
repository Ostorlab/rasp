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


def _with_string_values(data: bytes, *, data_type: int, index: int) -> bytes:
    """Rewrites every string-typed attribute value: its type byte and the pool index it points to."""
    string_value = bytes([0x08, 0x00, 0x00, 0x03])
    edited = bytearray(data)
    start = edited.find(string_value)
    while start != -1:
        edited[start + 3] = data_type
        edited[start + 4 : start + 8] = index.to_bytes(4, "little")
        start = edited.find(string_value, start + 8)
    return bytes(edited)


def testReadApplicationClass_whenPresent_returnsName() -> None:
    assert (
        axml.read_application_class(_with_application()) == "com.example.withapp.MyApp"
    )


def testReadApplicationClass_whenAbsent_returnsNone() -> None:
    assert axml.read_application_class(_without_application()) is None


def testReadManifestPackage_whenValidManifest_returnsThePackage() -> None:
    assert axml.read_manifest_package(_with_application()) == "com.example.withapp"


def testReadApplicationClass_whenNotAxml_raisesAxmlError() -> None:
    with pytest.raises(axml.AxmlError):
        axml.read_application_class(b"<manifest>plain text</manifest>")


@pytest.mark.parametrize("is_utf8", [True, False])
@pytest.mark.parametrize(
    "text", ["co.ostorlab.rasp.RaspStub", "", "x", "astral \U0001f600 end"]
)
def testEncodeString_whenReadBack_givesTheSameText(text: str, is_utf8: bool) -> None:
    encoded = axml._encode_string(text, is_utf8)
    length, decoded = axml._read_string(encoded, 0, is_utf8)
    assert decoded == text
    assert length == len(encoded)


def testReadVersionName_whenLiteral_returnsIt() -> None:
    data = (_FIXTURES / "manifest_with_application_and_version.bin").read_bytes()

    assert axml.read_version_name(data) == "2.4.1"


def testReadVersionName_whenAbsent_returnsNone() -> None:
    assert axml.read_version_name(_with_application()) is None


def testReadVersionName_whenAResourceReference_returnsNone() -> None:
    data = (_FIXTURES / "manifest_with_version_reference.bin").read_bytes()

    assert axml.read_version_name(data) is None


def testReadApplicationClass_whenTheNameIsNotALiteralString_raisesAxmlError() -> None:
    data = _with_string_values(_with_application(), data_type=0x01, index=0)

    with pytest.raises(axml.AxmlError, match="not a literal string"):
        axml.read_application_class(data)


def testReadManifestPackage_whenAStringIndexIsOutsideThePool_raisesAxmlError() -> None:
    data = _with_string_values(_with_application(), data_type=0x03, index=0x7FFFFFFF)

    with pytest.raises(axml.AxmlError, match="outside the string pool"):
        axml.read_manifest_package(data)


def testReadMinSdkVersion_whenLiteral_returnsIt() -> None:
    assert axml.read_min_sdk_version(_with_application()) == 21


def testReadMinSdkVersion_whenAbsent_returnsNone() -> None:
    data = (_FIXTURES / "manifest_without_min_sdk.bin").read_bytes()

    assert axml.read_min_sdk_version(data) is None


def testSetMinSdkVersion_whenPresent_setsItAndKeepsTheRestReadable() -> None:
    edited = axml.set_min_sdk_version(_with_application(), 26)

    assert axml.read_min_sdk_version(edited) == 26
    assert axml.read_manifest_package(edited) == "com.example.withapp"
    assert axml.read_application_class(edited) == "com.example.withapp.MyApp"


def testSetMinSdkVersion_whenAbsent_raisesAxmlError() -> None:
    data = (_FIXTURES / "manifest_without_min_sdk.bin").read_bytes()

    with pytest.raises(axml.AxmlError, match="minSdkVersion"):
        axml.set_min_sdk_version(data, 26)


def testReadAppComponentFactory_whenAbsent_returnsNone() -> None:
    assert axml.read_app_component_factory(_with_application()) is None


def testSetAppComponentFactory_whenAbsent_addsItAndKeepsTheRestReadable() -> None:
    edited = axml.set_app_component_factory(_with_application(), _STUB)

    assert axml.read_app_component_factory(edited) == _STUB
    assert axml.read_application_class(edited) == "com.example.withapp.MyApp"
    assert axml.read_manifest_package(edited) == "com.example.withapp"


def testSetAppComponentFactory_whenAbsentOnAppWithoutName_addsIt() -> None:
    edited = axml.set_app_component_factory(_without_application(), _STUB)

    assert axml.read_app_component_factory(edited) == _STUB


def testSetAppComponentFactory_whenReapplied_repointsToTheSameValue() -> None:
    once = axml.set_app_component_factory(_with_application(), _STUB)
    twice = axml.set_app_component_factory(once, _STUB)

    assert axml.read_app_component_factory(twice) == _STUB
    assert axml.read_application_class(twice) == "com.example.withapp.MyApp"

"""Tests of the binary AndroidManifest.xml editor.

The fixtures are real manifests compiled with aapt2; see the .source.xml files
next to them.
"""

import pathlib
import struct

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


def _chunk_offsets(data: bytes) -> list[int]:
    """Returns the offset of every chunk after the root header of a well-formed manifest."""
    offsets: list[int] = []
    offset = 8
    while offset < len(data):
        offsets.append(offset)
        offset += struct.unpack_from("<I", data, offset + 4)[0]
    return offsets


def _with_chunk_size(data: bytes, chunk: int, size: int) -> bytes:
    """Sets the declared size of the manifest's `chunk`-th chunk after the root header."""
    edited = bytearray(data)
    struct.pack_into("<I", edited, _chunk_offsets(data)[chunk] + 4, size)
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


def _debuggable_attribute(data: bytes) -> tuple[int, int] | None:
    """The type and data of the application's android:debuggable value, or None when it declares none."""
    pool, region = axml._split(data)
    element = axml._find_element(region, pool, axml.APPLICATION_ELEMENT)
    assert element is not None
    attribute = axml._find_attribute(
        region, element, axml._resource_map(region), axml.ATTR_DEBUGGABLE_RESOURCE_ID
    )
    if attribute is None:
        return None
    _raw, _size, _res0, data_type, value = struct.unpack_from(
        "<IHBBI", region, attribute + 8
    )
    return data_type, value


def testClearDebuggable_whenTheAppIsDebuggable_shipsTheAttributeAsBooleanFalse() -> (
    None
):
    data = (_FIXTURES / "manifest_debuggable_true.bin").read_bytes()

    cleared = axml.clear_debuggable(data)

    assert _debuggable_attribute(data) == (0x12, 0xFFFFFFFF)
    assert _debuggable_attribute(cleared) == (0x12, 0)
    assert axml.read_application_class(cleared) == "com.example.withapp.MyApp"


def testClearDebuggable_whenTheAppDeclaresItFalse_returnsTheManifestUnchanged() -> None:
    data = (_FIXTURES / "manifest_debuggable_false.bin").read_bytes()

    assert axml.clear_debuggable(data) == data


def testClearDebuggable_whenTheAppDoesNotDeclareIt_returnsTheManifestUnchanged() -> (
    None
):
    data = _with_application()

    assert axml.clear_debuggable(data) == data


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize("chunk", [0, 1])
def testReadApplicationClass_whenAChunkHasSizeZero_raisesAxmlError(chunk: int) -> None:
    data = _with_chunk_size(_with_application(), chunk, 0)

    with pytest.raises(axml.AxmlError, match="smaller than its"):
        axml.read_application_class(data)


@pytest.mark.usefixtures("deadline")
def testSetAppComponentFactory_whenTheLastChunkHasSizeZero_raisesAxmlError() -> None:
    data = _with_application()
    data = _with_chunk_size(data, len(_chunk_offsets(data)) - 1, 0)

    with pytest.raises(axml.AxmlError, match="smaller than its"):
        axml.set_app_component_factory(data, _STUB)


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize(("chunk", "size"), [(1, 4), (2, 12)])
def testReadApplicationClass_whenAChunkIsSmallerThanItsHeader_raisesAxmlError(
    chunk: int, size: int
) -> None:
    data = _with_chunk_size(_with_application(), chunk, size)

    with pytest.raises(axml.AxmlError, match="smaller than its"):
        axml.read_application_class(data)


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize("chunk", [0, 1])
def testReadApplicationClass_whenAChunkRunsPastTheEnd_raisesAxmlError(
    chunk: int,
) -> None:
    data = _with_application()
    data = _with_chunk_size(data, chunk, len(data))

    with pytest.raises(axml.AxmlError, match="past the end"):
        axml.read_application_class(data)


@pytest.mark.usefixtures("deadline")
def testSetAppComponentFactory_whenTheManifestEndsInsideAChunkHeader_raisesAxmlError() -> (
    None
):
    data = _with_application() + bytes(4)

    with pytest.raises(axml.AxmlError, match="past the end"):
        axml.set_app_component_factory(data, _STUB)

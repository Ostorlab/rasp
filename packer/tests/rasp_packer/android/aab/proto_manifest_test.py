"""Tests for the low-level AAB protobuf manifest parser."""

import pathlib
import zipfile

import pytest

from rasp_packer.android.aab import proto_manifest

_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "apps"
    / "android"
    / "InsecureBankv2.aab"
)


@pytest.fixture
def manifest_bytes() -> bytes:
    """Return the raw proto manifest from the test AAB."""
    with zipfile.ZipFile(_FIXTURE) as zf:
        return zf.read("base/manifest/AndroidManifest.xml")


# ── read_package ─────────────────────────────────────────────


def testReadPackage_whenValidManifest_shouldReturnPackageName(
    manifest_bytes: bytes,
) -> None:
    result = proto_manifest.read_package(manifest_bytes)

    assert result == "com.android.insecurebankv2"


# ── read_version_name ────────────────────────────────────────


def testReadVersionName_whenValidManifest_shouldReturnVersionName(
    manifest_bytes: bytes,
) -> None:
    result = proto_manifest.read_version_name(manifest_bytes)

    assert result == "1.0"


# ── read_min_sdk_version ─────────────────────────────────────


def testReadMinSdkVersion_whenValidManifest_shouldReturnMinSdk(
    manifest_bytes: bytes,
) -> None:
    result = proto_manifest.read_min_sdk_version(manifest_bytes)

    assert result == 15


# ── set_min_sdk_version ──────────────────────────────────────


def testSetMinSdkVersion_whenHigherThanCurrent_shouldUpdate(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_min_sdk_version(manifest_bytes, 21)

    assert proto_manifest.read_min_sdk_version(edited) == 21


def testSetMinSdkVersion_whenChanged_shouldPreservePackage(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_min_sdk_version(manifest_bytes, 21)

    assert proto_manifest.read_package(edited) == "com.android.insecurebankv2"


def testSetMinSdkVersion_whenChanged_shouldPreserveVersionName(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_min_sdk_version(manifest_bytes, 21)

    assert proto_manifest.read_version_name(edited) == "1.0"


# ── read_app_component_factory ───────────────────────────────


def testReadAppComponentFactory_whenAbsent_shouldReturnNone(
    manifest_bytes: bytes,
) -> None:
    result = proto_manifest.read_app_component_factory(manifest_bytes)

    assert result is None


# ── set_app_component_factory ────────────────────────────────


def testSetAppComponentFactory_whenAbsent_shouldAddAttribute(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_app_component_factory(
        manifest_bytes, "com.ostorlab.rasp.RaspStub"
    )

    assert (
        proto_manifest.read_app_component_factory(edited)
        == "com.ostorlab.rasp.RaspStub"
    )


def testSetAppComponentFactory_whenAdded_shouldPreservePackage(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_app_component_factory(
        manifest_bytes, "com.ostorlab.rasp.RaspStub"
    )

    assert proto_manifest.read_package(edited) == "com.android.insecurebankv2"


def testSetAppComponentFactory_whenAdded_shouldPreserveMinSdk(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_app_component_factory(
        manifest_bytes, "com.ostorlab.rasp.RaspStub"
    )

    assert proto_manifest.read_min_sdk_version(edited) == 15


def testSetAppComponentFactory_whenAlreadySet_shouldReplace(
    manifest_bytes: bytes,
) -> None:
    first = proto_manifest.set_app_component_factory(
        manifest_bytes, "com.example.OldFactory"
    )
    second = proto_manifest.set_app_component_factory(
        first, "com.ostorlab.rasp.RaspStub"
    )

    assert (
        proto_manifest.read_app_component_factory(second)
        == "com.ostorlab.rasp.RaspStub"
    )


# ── round-trip ───────────────────────────────────────────────


def testRoundTrip_whenBothEditsApplied_shouldPreserveAll(
    manifest_bytes: bytes,
) -> None:
    edited = proto_manifest.set_min_sdk_version(manifest_bytes, 24)
    edited = proto_manifest.set_app_component_factory(
        edited, "com.ostorlab.rasp.RaspStub"
    )

    assert proto_manifest.read_package(edited) == "com.android.insecurebankv2"
    assert proto_manifest.read_version_name(edited) == "1.0"
    assert proto_manifest.read_min_sdk_version(edited) == 24
    assert (
        proto_manifest.read_app_component_factory(edited)
        == "com.ostorlab.rasp.RaspStub"
    )


# ── error cases ──────────────────────────────────────────────


def testReadPackage_whenEmptyBytes_shouldRaise() -> None:
    with pytest.raises(proto_manifest.ProtoManifestError):
        proto_manifest.read_package(b"")


def testSetMinSdkVersion_whenNoUsesSdk_shouldRaise() -> None:
    # A minimal proto with just a <manifest> element but no <uses-sdk> child:
    # XmlNode { element: XmlElement { name: "manifest" } }
    element = b"\x0a\x0a\x1a\x08manifest"
    with pytest.raises(proto_manifest.ProtoManifestError, match="no <uses-sdk>"):
        proto_manifest.set_min_sdk_version(element, 21)


def testSetMinSdkVersion_whenUsesSdkHasNoMinSdk_shouldRaise() -> None:
    # <manifest> with a <uses-sdk android:targetSdkVersion="30"> child but no
    # minSdkVersion attribute.  set_min_sdk_version should raise because the
    # replacement finds no attribute to update.
    element = (
        b"\nc\x1a\x08manifest*W\nU\x1a\x08uses-sdk"
        b'"I\n*http://schemas.android.com/apk/res/android'
        b"\x12\x10targetSdkVersion(\xf0\x84\x84\x082\x04:\x020\x1e"
    )
    with pytest.raises(
        proto_manifest.ProtoManifestError, match="no android:minSdkVersion"
    ):
        proto_manifest.set_min_sdk_version(element, 21)


_DEBUGGABLE_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("declared", ["true", "false"])
def testRemoveDebuggable_whenTheAppDeclaresIt_removesTheAttribute(
    declared: str,
) -> None:
    data = (_DEBUGGABLE_FIXTURES / f"manifest_debuggable_{declared}.pb").read_bytes()

    removed = proto_manifest.remove_debuggable(data)

    assert b"debuggable" in data
    assert b"debuggable" not in removed
    assert proto_manifest.read_package(removed) == "com.example.withapp"


def testRemoveDebuggable_whenTheAppDoesNotDeclareIt_returnsTheManifestUnchanged() -> (
    None
):
    data = (_DEBUGGABLE_FIXTURES / "manifest_not_debuggable.pb").read_bytes()

    assert proto_manifest.remove_debuggable(data) == data


# ── semantics ────────────────────────────────────────────────


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _length_delimited(field_number: int, payload: bytes) -> bytes:
    return _varint((field_number << 3) | 2) + _varint(len(payload)) + payload


def _manifest_with_stamped_attributes(manifest: bytes) -> bytes:
    """The fixture manifest with the two attributes bundletool stamps on the base module added to <manifest>."""
    # The root XmlNode's first field is the <manifest> XmlElement; append two XmlAttribute (field 4) entries to it.
    assert manifest[0] == 0x0A
    length, size = _decode_varint(manifest, 1)
    header = 1 + size
    element = manifest[header : header + length]
    for name in ("requiredSplitTypes", "splitTypes"):
        name_field = _length_delimited(2, name.encode("utf-8"))
        value_field = _length_delimited(3, b"")
        element += _length_delimited(4, name_field + value_field)
    return bytes([0x0A]) + _varint(len(element)) + element + manifest[header + length :]


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    size = 0
    while True:
        byte = data[pos + size]
        value |= (byte & 0x7F) << shift
        size += 1
        if not byte & 0x80:
            return value, size
        shift += 7


def testSemantics_whenTheStoreStampsSplitTypeAttributes_isUnchanged(
    manifest_bytes: bytes,
) -> None:
    stamped = _manifest_with_stamped_attributes(manifest_bytes)

    assert b"requiredSplitTypes" in stamped
    assert proto_manifest.semantics(stamped) == proto_manifest.semantics(manifest_bytes)

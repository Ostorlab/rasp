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

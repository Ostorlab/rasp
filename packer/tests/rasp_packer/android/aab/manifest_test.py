"""Tests for the AAB semantic manifest layer."""

import pathlib
import zipfile
from unittest import mock

import pytest

from rasp_packer import errors
from rasp_packer.android.aab import manifest
from rasp_packer.android.aab import proto_manifest

_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "apps"
    / "android"
    / "InsecureBankv2.aab"
)


def testCapturePermissions_whenSelected_addsOnlySelectedAndIsIdempotent(
    manifest_bytes: bytes,
) -> None:
    edited = manifest.ensure_capture_permissions(manifest_bytes, ("screenshot",))
    assert edited != manifest_bytes
    assert manifest.ensure_capture_permissions(edited, ("screenshot",)) == edited
    assert manifest.ensure_capture_permissions(manifest_bytes, ()) == manifest_bytes
    assert manifest.app_identity(edited) == manifest.app_identity(manifest_bytes)
    assert proto_manifest.read_min_sdk_version(
        edited
    ) == proto_manifest.read_min_sdk_version(manifest_bytes)
    assert b"DETECT_SCREEN_RECORDING" not in edited
    both = manifest.ensure_capture_permissions(edited, ("screen_recording",))
    assert (
        manifest.ensure_capture_permissions(both, ("screenshot", "screen_recording"))
        == both
    )


def testCapturePermissions_whenMalformedSelected_raisesManifestError() -> None:
    with pytest.raises(errors.ManifestError):
        manifest.ensure_capture_permissions(b"bad", ("screenshot",))


def testCapturePermissions_whenHostRestrictsPermission_refusesPolicyWidening() -> None:
    data = (
        pathlib.Path(__file__).parent / "fixtures/capture_restricted.proto.bin"
    ).read_bytes()
    with pytest.raises(errors.ManifestError, match="restricted"):
        manifest.ensure_capture_permissions(data, ("screenshot",))
    assert manifest.ensure_capture_permissions(data, ()) == data
    assert manifest.ensure_capture_permissions(data, ("screen_recording",)) != data


@pytest.fixture
def manifest_bytes() -> bytes:
    """Return the raw proto manifest from the test AAB."""
    with zipfile.ZipFile(_FIXTURE) as zf:
        return zf.read("base/manifest/AndroidManifest.xml")


# ── app_identity ─────────────────────────────────────────────


def testAppIdentity_whenValidManifest_shouldReturnIdentity(
    manifest_bytes: bytes,
) -> None:
    result = manifest.app_identity(manifest_bytes)

    assert result.package_name == "com.android.insecurebankv2"
    assert result.version == "1.0"


def testAppIdentity_whenEmptyManifest_shouldRaiseManifestError() -> None:
    with pytest.raises(errors.ManifestError):
        manifest.app_identity(b"")


# ── app_component_factory ────────────────────────────────────


def testAppComponentFactory_whenAbsent_shouldReturnNone(
    manifest_bytes: bytes,
) -> None:
    result = manifest.app_component_factory(manifest_bytes)

    assert result is None


# ── set_app_component_factory ────────────────────────────────


def testSetAppComponentFactory_whenAbsent_shouldAddAndReturn(
    manifest_bytes: bytes,
) -> None:
    edited = manifest.set_app_component_factory(
        manifest_bytes, "com.ostorlab.rasp.RaspStub"
    )

    assert manifest.app_component_factory(edited) == "com.ostorlab.rasp.RaspStub"


def testSetAppComponentFactory_whenAdded_shouldPreserveIdentity(
    manifest_bytes: bytes,
) -> None:
    edited = manifest.set_app_component_factory(
        manifest_bytes, "com.ostorlab.rasp.RaspStub"
    )
    result = manifest.app_identity(edited)

    assert result.package_name == "com.android.insecurebankv2"
    assert result.version == "1.0"


# ── raise_min_sdk_version ────────────────────────────────────


def testRaiseMinSdkVersion_whenCurrentIsLower_shouldRaise(
    manifest_bytes: bytes,
) -> None:
    edited = manifest.raise_min_sdk_version(manifest_bytes, 21)

    assert proto_manifest.read_min_sdk_version(edited) == 21


def testRaiseMinSdkVersion_whenCurrentIsHigherOrEqual_shouldReturnUnchanged(
    manifest_bytes: bytes,
) -> None:
    result = manifest.raise_min_sdk_version(manifest_bytes, 10)

    assert result is manifest_bytes


def testRaiseMinSdkVersion_whenCurrentIsEqual_shouldReturnUnchanged(
    manifest_bytes: bytes,
) -> None:
    result = manifest.raise_min_sdk_version(manifest_bytes, 15)

    assert result is manifest_bytes


# ── InvalidAabError paths ───────────────────────────────────


def testAppIdentity_whenNoVersionName_shouldRaiseInvalidAabError(
    manifest_bytes: bytes,
) -> None:
    with (
        mock.patch.object(proto_manifest, "read_version_name", return_value=None),
        pytest.raises(errors.InvalidAabError, match="versionName"),
    ):
        manifest.app_identity(manifest_bytes)


def testAppIdentity_whenNoPackage_shouldRaiseInvalidAabError(
    manifest_bytes: bytes,
) -> None:
    with (
        mock.patch.object(proto_manifest, "read_package", return_value=None),
        pytest.raises(errors.InvalidAabError, match="package"),
    ):
        manifest.app_identity(manifest_bytes)


def testRaiseMinSdkVersion_whenNoMinSdk_shouldRaiseInvalidAabError(
    manifest_bytes: bytes,
) -> None:
    with (
        mock.patch.object(proto_manifest, "read_min_sdk_version", return_value=None),
        pytest.raises(errors.InvalidAabError, match="minSdkVersion"),
    ):
        manifest.raise_min_sdk_version(manifest_bytes, 31)

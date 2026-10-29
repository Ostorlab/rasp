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

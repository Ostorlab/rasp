"""Tests of the manifest semantic layer."""

import pathlib

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android.apk import axml
from rasp_packer.android.apk import manifest

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def testAppIdentity_whenPackageAndVersionAreDeclared_returnsThem() -> None:
    data = (_FIXTURES / "manifest_with_application_and_version.bin").read_bytes()

    assert manifest.app_identity(data) == identity.AppIdentity(
        package_name="com.example.withapp", version="2.4.1"
    )


def testAppIdentity_whenNoVersionName_raisesInvalidApkError() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()

    with pytest.raises(errors.InvalidApkError, match="versionName"):
        manifest.app_identity(data)


def testAppIdentity_whenTheVersionNameIsAResourceReference_raisesInvalidApkError() -> (
    None
):
    data = (_FIXTURES / "manifest_with_version_reference.bin").read_bytes()

    with pytest.raises(errors.InvalidApkError, match="versionName"):
        manifest.app_identity(data)


def testRaiseMinSdkVersion_whenLower_raisesIt() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()

    edited = manifest.raise_min_sdk_version(data, 26)

    assert axml.read_min_sdk_version(edited) == 26


def testRaiseMinSdkVersion_whenNotLower_returnsTheManifestUnchanged() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()

    assert manifest.raise_min_sdk_version(data, 21) == data


def testRaiseMinSdkVersion_whenAbsent_raisesInvalidApkError() -> None:
    data = (_FIXTURES / "manifest_without_min_sdk.bin").read_bytes()

    with pytest.raises(errors.InvalidApkError, match="minSdkVersion"):
        manifest.raise_min_sdk_version(data, 26)


def testAppComponentFactory_whenAbsent_returnsNone() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()

    assert manifest.app_component_factory(data) is None


def testSetAppComponentFactory_whenAbsent_addsIt() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()

    edited = manifest.set_app_component_factory(data, "co.ostorlab.rasp.RaspStub")

    assert manifest.app_component_factory(edited) == "co.ostorlab.rasp.RaspStub"

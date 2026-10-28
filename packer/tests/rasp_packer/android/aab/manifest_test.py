"""Tests of the bundle manifest semantic layer."""

import collections.abc

import pytest

from rasp_packer import errors
from rasp_packer.android.aab import manifest as manifest_module
from rasp_packer.android.aab import proto_manifest

type ManifestBuilder = collections.abc.Callable[..., bytes]

_STUB = "co.ostorlab.rasp.RaspStub"


def testAppIdentity_whenValid_returnsPackageAndVersion(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(package="dev.ostorlab.demo", version_name="1.2.3")

    app_identity = manifest_module.app_identity(manifest)

    assert app_identity.package_name == "dev.ostorlab.demo"
    assert app_identity.version == "1.2.3"


def testAppIdentity_whenNoVersionName_raisesInvalidBundleError(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(version_name=None)

    with pytest.raises(errors.InvalidBundleError, match="versionName"):
        manifest_module.app_identity(manifest)


def testAppIdentity_whenNotProtobuf_raisesManifestError() -> None:
    with pytest.raises(errors.ManifestError):
        manifest_module.app_identity(b"\xff\xff not a manifest")


def testAppComponentFactory_whenAbsent_returnsNone(
    build_manifest: ManifestBuilder,
) -> None:
    assert manifest_module.app_component_factory(build_manifest()) is None


def testAppComponentFactory_whenPresent_returnsIt(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(app_component_factory=_STUB)

    assert manifest_module.app_component_factory(manifest) == _STUB


def testProtect_whenMinSdkIsLower_raisesItAndSetsTheFactory(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(min_sdk=21)

    patched = manifest_module.protect(manifest, factory=_STUB, minimum_api_level=31)

    node = proto_manifest.parse(patched)
    assert proto_manifest.read_min_sdk_version(node) == 31
    assert proto_manifest.read_app_component_factory(node) == _STUB


def testProtect_whenMinSdkIsHigher_leavesItAndSetsTheFactory(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(min_sdk=33)

    patched = manifest_module.protect(manifest, factory=_STUB, minimum_api_level=31)

    node = proto_manifest.parse(patched)
    assert proto_manifest.read_min_sdk_version(node) == 33
    assert proto_manifest.read_app_component_factory(node) == _STUB


def testProtect_whenNoMinSdk_raisesInvalidBundleError(
    build_manifest: ManifestBuilder,
) -> None:
    manifest = build_manifest(min_sdk=None)

    with pytest.raises(errors.InvalidBundleError, match="minSdkVersion"):
        manifest_module.protect(manifest, factory=_STUB, minimum_api_level=31)

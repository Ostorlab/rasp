"""Tests of the protobuf manifest reader and editor."""

import collections.abc

import pytest

from rasp_packer.android.aab import proto_manifest
from rasp_packer.android.apk import axml

type ManifestBuilder = collections.abc.Callable[..., bytes]

_STUB = "co.ostorlab.rasp.RaspStub"


def testParse_whenNotProtobuf_raisesProtoManifestError() -> None:
    with pytest.raises(proto_manifest.ProtoManifestError):
        proto_manifest.parse(b"\xff\xff\xff\xff not a manifest")


def testReadPackage_whenManifestHasPackage_returnsIt(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(package="dev.ostorlab.demo"))

    assert proto_manifest.read_package(node) == "dev.ostorlab.demo"


def testReadVersionName_whenLiteral_returnsIt(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(version_name="2.4.1"))

    assert proto_manifest.read_version_name(node) == "2.4.1"


def testReadVersionName_whenReference_returnsNone(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(version_name_reference=True))

    assert proto_manifest.read_version_name(node) is None


def testReadMinSdkVersion_whenLiteral_returnsIt(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(min_sdk=23))

    assert proto_manifest.read_min_sdk_version(node) == 23


def testReadMinSdkVersion_whenNoUsesSdk_returnsNone(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(min_sdk=None))

    assert proto_manifest.read_min_sdk_version(node) is None


def testSetMinSdkVersion_whenSet_updatesTheCompiledValue(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(min_sdk=21))

    proto_manifest.set_min_sdk_version(node, 31)

    assert proto_manifest.read_min_sdk_version(node) == 31


def testSetMinSdkVersion_whenNoUsesSdk_raisesProtoManifestError(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(min_sdk=None))

    with pytest.raises(proto_manifest.ProtoManifestError):
        proto_manifest.set_min_sdk_version(node, 31)


def testReadAppComponentFactory_whenAbsent_returnsNone(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest())

    assert proto_manifest.read_app_component_factory(node) is None


def testReadAppComponentFactory_whenPresent_returnsIt(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(app_component_factory="a.B"))

    assert proto_manifest.read_app_component_factory(node) == "a.B"


def testSetAppComponentFactory_whenAbsent_addsItWithTheResourceId(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest())

    proto_manifest.set_app_component_factory(node, _STUB)

    assert proto_manifest.read_app_component_factory(node) == _STUB
    application = node.element.child[-1].element
    factory = application.attribute[-1]
    assert factory.resource_id == axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    assert factory.namespace_uri == axml.ANDROID_NAMESPACE


def testSetAppComponentFactory_whenPresent_replacesTheValue(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(app_component_factory="old.Factory"))

    proto_manifest.set_app_component_factory(node, _STUB)

    assert proto_manifest.read_app_component_factory(node) == _STUB
    application = node.element.child[-1].element
    factories = [
        attribute
        for attribute in application.attribute
        if attribute.resource_id == axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    ]
    assert len(factories) == 1


def testSetAppComponentFactory_whenNoApplication_raisesProtoManifestError(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(application=False))

    with pytest.raises(proto_manifest.ProtoManifestError):
        proto_manifest.set_app_component_factory(node, _STUB)


def testManifestElement_whenRootIsNotManifest_raisesProtoManifestError(
    build_manifest: ManifestBuilder,
) -> None:
    node = proto_manifest.parse(build_manifest(root_element="widget"))

    with pytest.raises(proto_manifest.ProtoManifestError):
        proto_manifest.read_package(node)


def testSerialize_whenManifestUnchanged_reproducesTheBytes(
    build_manifest: ManifestBuilder,
) -> None:
    data = build_manifest(package="dev.ostorlab.demo", version_name="1.2.3", min_sdk=23)

    node = proto_manifest.parse(data)

    assert proto_manifest.serialize(node) == data

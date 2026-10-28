"""Fixtures for the bundle tests: builders for protobuf manifests and in-memory bundles."""

import collections.abc
import pathlib
import zipfile

import pytest

from rasp_packer.android.aab import bundle
from rasp_packer.android.aab.proto import Resources_pb2
from rasp_packer.android.apk import axml


def _string_attribute(
    element: Resources_pb2.XmlElement,
    *,
    namespace: str,
    name: str,
    resource_id: int,
    value: str,
) -> Resources_pb2.XmlAttribute:
    attribute = element.attribute.add()
    attribute.namespace_uri = namespace
    attribute.name = name
    attribute.resource_id = resource_id
    attribute.value = value
    return attribute


def _int_attribute(
    element: Resources_pb2.XmlElement, *, name: str, resource_id: int, value: int
) -> None:
    attribute = element.attribute.add()
    attribute.namespace_uri = axml.ANDROID_NAMESPACE
    attribute.name = name
    attribute.resource_id = resource_id
    attribute.value = str(value)
    attribute.compiled_item.prim.int_decimal_value = value


def _build_manifest(
    *,
    package: str = "com.example.app",
    version_name: str | None = "1.0",
    version_name_reference: bool = False,
    min_sdk: int | None = 21,
    application: bool = True,
    app_component_factory: str | None = None,
    root_element: str = axml.MANIFEST_ELEMENT,
) -> bytes:
    node = Resources_pb2.XmlNode()
    manifest = node.element
    manifest.name = root_element
    namespace = manifest.namespace_declaration.add()
    namespace.prefix = "android"
    namespace.uri = axml.ANDROID_NAMESPACE
    package_attribute = manifest.attribute.add()
    package_attribute.name = axml.PACKAGE_ATTRIBUTE
    package_attribute.value = package
    if version_name_reference is True:
        reference = manifest.attribute.add()
        reference.namespace_uri = axml.ANDROID_NAMESPACE
        reference.name = "versionName"
        reference.resource_id = axml.ATTR_VERSION_NAME_RESOURCE_ID
        reference.compiled_item.ref.id = 0x7F010000
    elif version_name is not None:
        _string_attribute(
            manifest,
            namespace=axml.ANDROID_NAMESPACE,
            name="versionName",
            resource_id=axml.ATTR_VERSION_NAME_RESOURCE_ID,
            value=version_name,
        )
    if min_sdk is not None:
        uses_sdk = manifest.child.add().element
        uses_sdk.name = axml.USES_SDK_ELEMENT
        _int_attribute(
            uses_sdk,
            name="minSdkVersion",
            resource_id=axml.ATTR_MIN_SDK_VERSION_RESOURCE_ID,
            value=min_sdk,
        )
    if application is True:
        application_element = manifest.child.add().element
        application_element.name = axml.APPLICATION_ELEMENT
        if app_component_factory is not None:
            _string_attribute(
                application_element,
                namespace=axml.ANDROID_NAMESPACE,
                name=axml.APP_COMPONENT_FACTORY_ATTRIBUTE,
                resource_id=axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID,
                value=app_component_factory,
            )
    return node.SerializeToString()


@pytest.fixture
def build_manifest() -> collections.abc.Callable[..., bytes]:
    """Returns a builder for a protobuf AndroidManifest.xml with the fields a test needs."""
    return _build_manifest


def _make_bundle(
    path: pathlib.Path,
    *,
    manifest: bytes | None = None,
    base_dexes: collections.abc.Sequence[str] = (
        "base/dex/classes.dex",
        "base/dex/classes2.dex",
    ),
    native_libraries: collections.abc.Sequence[str] = (),
    extra: collections.abc.Mapping[str, bytes] | None = None,
) -> pathlib.Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(bundle.BUNDLE_CONFIG_ENTRY, b"\x08\x01")
        archive.writestr(
            bundle.BASE_MANIFEST_ENTRY,
            _build_manifest() if manifest is None else manifest,
        )
        for index, name in enumerate(base_dexes):
            archive.writestr(name, f"base dex {index}".encode())
        for name in native_libraries:
            archive.writestr(name, b"app native code")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return path


@pytest.fixture
def make_bundle() -> collections.abc.Callable[..., pathlib.Path]:
    """Returns a builder that writes an .aab to disk and returns its path."""
    return _make_bundle

"""Editing Android's binary XML (AXML), the form of a built AndroidManifest.xml.

A built APK stores its manifest as binary XML, not text. The packer makes two
changes to it: it sets the application's ``android:appComponentFactory`` to the
stub, and it can raise the app's ``android:minSdkVersion``. This module makes those
changes on the binary form directly, so the packer needs no Android build tool at
pack time.

The format is a sequence of chunks: an 8-byte root header, a pool holding every
string in the file, a map from the first strings to resource ids, then the XML
tree. Attributes name their namespace, name and value by index into that string
pool, and the resource map gives the numeric resource id (for example
`android:name` is `0x01010003`) of each attribute-name string.

The minimum API level is a number stored in the attribute itself, so raising it
only rewrites the value of the existing ``android:minSdkVersion`` attribute.

Setting the component factory needs one of two edits. In both, the stub class
name is appended at the end of the pool when the pool doesn't hold it yet:

- if ``<application>`` already has ``android:appComponentFactory``, repoint its
  value to the stub class;
- otherwise add the attribute to ``<application>``, in resource-id order.

Most manifests don't have the ``appComponentFactory`` attribute-name string. Adding
the attribute then also inserts that string into the pool, right after the strings
the resource map covers, and adds its resource id to the resource map. Every string
index at or after the inserted string moves up by one, so the edit shifts every
reference to those strings.

The parser is checked against manifests produced by aapt2; see the tests.
"""

import collections.abc
import dataclasses
import struct
from typing import Self

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

_ROOT_HEADER_SIZE = 8
_POOL_HEADER_SIZE = 28
_NODE_HEADER_SIZE = 16
_ATTR_EXT_SIZE = 20
_ATTRIBUTE_SIZE = 20

_UTF8_FLAG = 0x100
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_NO_ENTRY = 0xFFFFFFFF

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
APPLICATION_ELEMENT = "application"
MANIFEST_ELEMENT = "manifest"
USES_SDK_ELEMENT = "uses-sdk"
PACKAGE_ATTRIBUTE = "package"
ATTR_NAME_RESOURCE_ID = 0x01010003
ATTR_VERSION_NAME_RESOURCE_ID = 0x0101021C
ATTR_MIN_SDK_VERSION_RESOURCE_ID = 0x0101020C
ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID = 0x0101057A
APP_COMPONENT_FACTORY_ATTRIBUTE = "appComponentFactory"


type _Buffer = bytes | bytearray


class AxmlError(Exception):
    """The bytes are not AXML this module can edit."""


def _u16(data: _Buffer, offset: int) -> int:
    """Reads the little-endian 16-bit unsigned integer at `offset`."""
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: _Buffer, offset: int) -> int:
    """Reads the little-endian 32-bit unsigned integer at `offset`."""
    return int(struct.unpack_from("<I", data, offset)[0])


@dataclasses.dataclass(slots=True)
class _StringPool:
    """The string pool chunk, decoded enough to read strings and append one.

    Each string's original encoded bytes are kept verbatim, so re-serializing a
    pool that was not changed reproduces the same strings. Only the offset table
    is recomputed, which yields the same offsets for the untouched strings.

    Attributes:
        header_size: The chunk header size, 28 for every pool aapt2 writes.
        flags: The pool flags; the UTF-8 bit decides the string encoding.
        encoded: The encoded bytes of each string, in index order.
        decoded: The text of each string, in index order.
    """

    header_size: int
    flags: int
    encoded: list[bytes]
    decoded: list[str]

    @property
    def is_utf8(self) -> bool:
        return (self.flags & _UTF8_FLAG) != 0

    @classmethod
    def parse(cls, data: bytes, start: int) -> tuple[Self, int]:
        chunk_type = _u16(data, start)
        if chunk_type != RES_STRING_POOL_TYPE:
            raise AxmlError(
                f"expected a string pool at offset {start}, found type {chunk_type:#06x}"
            )
        header_size = _u16(data, start + 2)
        size = _u32(data, start + 4)
        string_count = _u32(data, start + 8)
        style_count = _u32(data, start + 12)
        flags = _u32(data, start + 16)
        strings_start = _u32(data, start + 20)
        if style_count != 0:
            raise AxmlError("string pool has styles, which the packer does not edit")
        if header_size != _POOL_HEADER_SIZE:
            raise AxmlError(f"unexpected string pool header size {header_size}")
        is_utf8 = (flags & _UTF8_FLAG) != 0
        data_base = start + strings_start
        offsets = [_u32(data, start + header_size + i * 4) for i in range(string_count)]
        encoded: list[bytes] = []
        decoded: list[str] = []
        for offset in offsets:
            length, text = _read_string(data, data_base + offset, is_utf8)
            encoded.append(data[data_base + offset : data_base + offset + length])
            decoded.append(text)
        return cls(header_size, flags, encoded, decoded), size

    def index(self, text: str) -> int | None:
        for i, value in enumerate(self.decoded):
            if value == text:
                return i
        return None

    def append(self, text: str) -> int:
        self.encoded.append(_encode_string(text, self.is_utf8))
        self.decoded.append(text)
        return len(self.decoded) - 1

    def insert(self, index: int, text: str) -> None:
        self.encoded.insert(index, _encode_string(text, self.is_utf8))
        self.decoded.insert(index, text)

    def serialize(self) -> bytes:
        string_count = len(self.encoded)
        string_data = b"".join(self.encoded)
        padding = (-len(string_data)) % 4
        string_data += b"\x00" * padding
        strings_start = self.header_size + string_count * 4
        size = strings_start + len(string_data)
        offsets = bytearray()
        running = 0
        for chunk in self.encoded:
            offsets += struct.pack("<I", running)
            running += len(chunk)
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE,
            self.header_size,
            size,
            string_count,
            0,
            self.flags,
            strings_start,
            0,
        )
        return header + bytes(offsets) + string_data


def _read_string(data: bytes, offset: int, is_utf8: bool) -> tuple[int, str]:
    """Reads one pool string, returning its full encoded length and its text."""
    position = offset
    if is_utf8:
        _char_length, position = _read_utf8_length(data, position)
        byte_length, position = _read_utf8_length(data, position)
        text = data[position : position + byte_length].decode("utf-8", "replace")
        position += byte_length + 1
        return position - offset, text
    units = _u16(data, position)
    position += 2
    if (units & 0x8000) != 0:
        units = ((units & 0x7FFF) << 16) | _u16(data, position)
        position += 2
    text = data[position : position + units * 2].decode("utf-16-le", "replace")
    position += units * 2 + 2
    return position - offset, text


def _read_utf8_length(data: bytes, offset: int) -> tuple[int, int]:
    """Reads a UTF-8 pool length of one or two bytes at `offset` and returns it with the offset after it."""
    value = data[offset]
    if (value & 0x80) != 0:
        return ((value & 0x7F) << 8) | data[offset + 1], offset + 2
    return value, offset + 1


def _encode_string(text: str, is_utf8: bool) -> bytes:
    """Encodes `text` as a string pool entry, in UTF-8 or UTF-16 as the pool uses."""
    if is_utf8:
        content = text.encode("utf-8")
        units = len(text.encode("utf-16-le")) // 2
        return _utf8_length(units) + _utf8_length(len(content)) + content + b"\x00"
    content = text.encode("utf-16-le")
    units = len(content) // 2
    if units < 0x8000:
        prefix = struct.pack("<H", units)
    else:
        prefix = struct.pack("<HH", 0x8000 | (units >> 16), units & 0xFFFF)
    return prefix + content + b"\x00\x00"


def _utf8_length(value: int) -> bytes:
    """Encodes a UTF-8 pool length in one byte, or in two when it is 0x80 or more."""
    if value < 0x80:
        return struct.pack("<B", value)
    return struct.pack("<BB", 0x80 | (value >> 8), value & 0xFF)


@dataclasses.dataclass(frozen=True, slots=True)
class _Element:
    """The location of a start-element chunk and its attribute block.

    Offsets are relative to the start of the region that follows the string pool.

    Attributes:
        offset: Start of the element chunk.
        attributes_offset: Start of the first attribute.
        attribute_count: Number of attributes.
    """

    offset: int
    attributes_offset: int
    attribute_count: int


def _resource_map(region: _Buffer) -> list[int]:
    """Returns the resource ids of the resource map chunk, or an empty list when there is none."""
    offset = 0
    while offset < len(region):
        chunk_type = _u16(region, offset)
        header_size = _u16(region, offset + 2)
        size = _u32(region, offset + 4)
        if chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (size - header_size) // 4
            return [_u32(region, offset + header_size + i * 4) for i in range(count)]
        offset += size
    return []


def _string(pool: _StringPool, index: int) -> str:
    """Returns the pool's string at `index`, an index read from the manifest, which may point outside the pool."""
    if index >= len(pool.decoded):
        raise AxmlError(f"string index {index} is outside the string pool")
    return pool.decoded[index]


def _find_element(region: _Buffer, pool: _StringPool, name: str) -> _Element | None:
    """Returns the first start element named `name`, or None when there is none."""
    offset = 0
    while offset < len(region):
        chunk_type = _u16(region, offset)
        size = _u32(region, offset + 4)
        if chunk_type == RES_XML_START_ELEMENT_TYPE:
            name_index = _u32(region, offset + 20)
            if name_index != _NO_ENTRY and _string(pool, name_index) == name:
                attributes_offset = (
                    offset + _NODE_HEADER_SIZE + _u16(region, offset + 24)
                )
                attribute_count = _u16(region, offset + 28)
                return _Element(offset, attributes_offset, attribute_count)
        offset += size
    return None


def _attribute_resource_id(
    region: _Buffer, attribute_offset: int, resource_map: list[int]
) -> int:
    """Returns the resource id of the attribute at `attribute_offset`, or 0 when its name has none."""
    name_index = _u32(region, attribute_offset + 4)
    if name_index < len(resource_map):
        return resource_map[name_index]
    return 0


def read_application_class(data: bytes) -> str | None:
    """Returns the ``android:name`` of ``<application>``, or None if it has none.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The application class name declared in the manifest, or None.

    Raises:
        AxmlError: The bytes are not AXML, have no ``<application>``, or its
            ``android:name`` is not a literal string, such as a ``@string``
            resource reference.
    """
    pool, region = _split(data)
    element = _find_element(region, pool, APPLICATION_ELEMENT)
    if element is None:
        raise AxmlError("manifest has no <application> element")
    resource_map = _resource_map(region)
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if (
            _attribute_resource_id(region, attribute, resource_map)
            == ATTR_NAME_RESOURCE_ID
        ):
            if region[attribute + 15] != _TYPE_STRING:
                raise AxmlError(
                    "the android:name of <application> is not a literal string"
                )
            return _string(pool, _u32(region, attribute + 16))
    return None


def read_app_component_factory(data: bytes) -> str | None:
    """Returns the ``android:appComponentFactory`` of ``<application>``, or None if it has none.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The component factory class declared on the application, or None.

    Raises:
        AxmlError: The bytes are not AXML, or have no ``<application>``.
    """
    pool, region = _split(data)
    element = _find_element(region, pool, APPLICATION_ELEMENT)
    if element is None:
        raise AxmlError("manifest has no <application> element")
    resource_map = _resource_map(region)
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if (
            _attribute_resource_id(region, attribute, resource_map)
            == ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
        ):
            if region[attribute + 15] != _TYPE_STRING:
                return None
            return _string(pool, _u32(region, attribute + 16))
    return None


def read_manifest_package(data: bytes) -> str | None:
    """Returns the package declared on ``<manifest>``, or None if it has none.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The app package.
    """
    pool, region = _split(data)
    element = _find_element(region, pool, MANIFEST_ELEMENT)
    if element is None:
        return None
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if _u32(region, attribute) != _NO_ENTRY:
            continue
        name_index = _u32(region, attribute + 4)
        if _string(pool, name_index) == PACKAGE_ATTRIBUTE:
            return _string(pool, _u32(region, attribute + 16))
    return None


def read_version_name(data: bytes) -> str | None:
    """Returns the ``android:versionName`` of ``<manifest>``, or None if it has no literal one.

    A version name written as a resource reference (``@string/...``) gives
    None as well: resolving it needs the app's resource table.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The version name declared in the manifest, or None.

    Raises:
        AxmlError: The bytes are not AXML.
    """
    pool, region = _split(data)
    element = _find_element(region, pool, MANIFEST_ELEMENT)
    if element is None:
        return None
    resource_map = _resource_map(region)
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if (
            _attribute_resource_id(region, attribute, resource_map)
            != ATTR_VERSION_NAME_RESOURCE_ID
        ):
            continue
        if region[attribute + 15] != _TYPE_STRING:
            return None
        return _string(pool, _u32(region, attribute + 16))
    return None


def read_min_sdk_version(data: bytes) -> int | None:
    """Returns the ``android:minSdkVersion`` of ``<uses-sdk>``, or None if it has no literal one.

    A manifest without ``<uses-sdk>``, or without the attribute, gives None. So
    does a value that is not a whole number, such as a resource reference.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The minimum API level declared in the manifest, or None.

    Raises:
        AxmlError: The bytes are not AXML.
    """
    pool, region = _split(data)
    attribute = _find_min_sdk_attribute(region, pool)
    if attribute is None:
        return None
    if region[attribute + 15] not in (_TYPE_INT_DEC, _TYPE_INT_HEX):
        return None
    return _u32(region, attribute + 16)


def set_min_sdk_version(data: bytes, version: int) -> bytes:
    """Returns the manifest with the ``android:minSdkVersion`` of ``<uses-sdk>`` set to ``version``.

    Args:
        data: The binary AndroidManifest.xml.
        version: The API level to set.

    Returns:
        The edited binary AndroidManifest.xml.

    Raises:
        AxmlError: The bytes are not AXML, or have no ``<uses-sdk>`` with an
            ``android:minSdkVersion``.
    """
    pool, region_bytes = _split(data)
    region = bytearray(region_bytes)
    attribute = _find_min_sdk_attribute(region, pool)
    if attribute is None:
        raise AxmlError("manifest has no android:minSdkVersion on <uses-sdk>")
    struct.pack_into(
        "<IHBBI", region, attribute + 8, _NO_ENTRY, 8, 0, _TYPE_INT_DEC, version
    )
    return _assemble(pool, region)


def _find_min_sdk_attribute(region: _Buffer, pool: _StringPool) -> int | None:
    """Returns the offset of the android:minSdkVersion attribute of <uses-sdk>, or None when there is none."""
    element = _find_element(region, pool, USES_SDK_ELEMENT)
    if element is None:
        return None
    resource_map = _resource_map(region)
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if (
            _attribute_resource_id(region, attribute, resource_map)
            == ATTR_MIN_SDK_VERSION_RESOURCE_ID
        ):
            return attribute
    return None


def set_app_component_factory(data: bytes, class_name: str) -> bytes:
    """Returns the manifest with ``<application android:appComponentFactory>`` set to ``class_name``.

    If the application already declares the attribute, its value is repointed.
    Otherwise the attribute is added, in resource-id order. Most manifests have
    neither the ``appComponentFactory`` attribute-name string nor its resource-map
    entry, so adding it inserts that string into the pool, inserts the resource id
    into the resource map, and shifts every pool reference that comes after it.

    Args:
        data: The binary AndroidManifest.xml.
        class_name: The fully qualified component factory to set.

    Returns:
        The edited binary AndroidManifest.xml.

    Raises:
        AxmlError: The bytes are not AXML, have no ``<application>``, or lack the
            android namespace string the attribute needs.
    """
    pool, region_bytes = _split(data)
    region = bytearray(region_bytes)
    element = _find_element(region, pool, APPLICATION_ELEMENT)
    if element is None:
        raise AxmlError("manifest has no <application> element")
    resource_map = _resource_map(region)
    existing = _find_attribute(
        region, element, resource_map, ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    )
    if existing is not None:
        value_index = pool.index(class_name)
        if value_index is None:
            value_index = pool.append(class_name)
        _repoint_attribute(region, existing, value_index)
        return _assemble(pool, region)

    name_index = _attribute_name_index(
        resource_map, ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    )
    if name_index is None:
        name_index = len(resource_map)
        _shift_string_references(region, name_index)
        _insert_resource_map_entry(
            region, name_index, ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
        )
        pool.insert(name_index, APP_COMPONENT_FACTORY_ATTRIBUTE)
    namespace_index = pool.index(ANDROID_NAMESPACE)
    if namespace_index is None:
        raise AxmlError("manifest has no android namespace string")
    value_index = pool.index(class_name)
    if value_index is None:
        value_index = pool.append(class_name)
    element = _find_element(region, pool, APPLICATION_ELEMENT)
    assert element is not None
    resource_map = _resource_map(region)
    _insert_attribute(
        region,
        element,
        resource_map,
        ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID,
        namespace_index,
        name_index,
        value_index,
    )
    return _assemble(pool, region)


def _find_attribute(
    region: _Buffer, element: _Element, resource_map: list[int], resource_id: int
) -> int | None:
    """Returns the offset of the element's attribute with `resource_id`, or None when it has none."""
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if _attribute_resource_id(region, attribute, resource_map) == resource_id:
            return attribute
    return None


def _attribute_name_index(resource_map: list[int], resource_id: int) -> int | None:
    """Returns the pool index the resource map gives `resource_id`, or None when it has none."""
    for index, mapped in enumerate(resource_map):
        if mapped == resource_id:
            return index
    return None


def _insert_resource_map_entry(region: bytearray, index: int, resource_id: int) -> None:
    """Inserts `resource_id` into the resource map chunk at `index`, growing the chunk by four bytes."""
    offset = 0
    while offset < len(region):
        chunk_type = _u16(region, offset)
        header_size = _u16(region, offset + 2)
        size = _u32(region, offset + 4)
        if chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            at = offset + header_size + index * 4
            region[at:at] = struct.pack("<I", resource_id)
            struct.pack_into("<I", region, offset + 4, size + 4)
            return
        offset += size
    raise AxmlError("manifest has no resource map chunk")


def _shift_string_references(region: bytearray, threshold: int) -> None:
    """Adds one to every pool string index in `region` that is `threshold` or more, for a string inserted there."""
    offset = 0
    while offset < len(region):
        chunk_type = _u16(region, offset)
        size = _u32(region, offset + 4)
        if chunk_type in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            _shift_index(region, offset + 12, threshold)
            _shift_index(region, offset + 16, threshold)
            _shift_index(region, offset + 20, threshold)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            _shift_index(region, offset + 12, threshold)
            _shift_index(region, offset + 16, threshold)
            _shift_index(region, offset + 20, threshold)
            attributes_offset = offset + _NODE_HEADER_SIZE + _u16(region, offset + 24)
            count = _u16(region, offset + 28)
            for i in range(count):
                attribute = attributes_offset + i * _ATTRIBUTE_SIZE
                _shift_index(region, attribute, threshold)
                _shift_index(region, attribute + 4, threshold)
                _shift_index(region, attribute + 8, threshold)
                if region[attribute + 15] == _TYPE_STRING:
                    _shift_index(region, attribute + 16, threshold)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            _shift_index(region, offset + 12, threshold)
            _shift_index(region, offset + 16, threshold)
            _shift_index(region, offset + 20, threshold)
        elif chunk_type == RES_XML_CDATA_TYPE:
            _shift_index(region, offset + 12, threshold)
            _shift_index(region, offset + 16, threshold)
            if region[offset + 23] == _TYPE_STRING:
                _shift_index(region, offset + 24, threshold)
        offset += size


def _shift_index(region: bytearray, position: int, threshold: int) -> None:
    """Adds one to the pool index at `position` when it is set and is `threshold` or more."""
    value = _u32(region, position)
    if value != _NO_ENTRY and value >= threshold:
        struct.pack_into("<I", region, position, value + 1)


def _insert_attribute(
    region: bytearray,
    element: _Element,
    resource_map: list[int],
    resource_id: int,
    namespace_index: int,
    name_index: int,
    value_index: int,
) -> None:
    """Inserts a string-valued attribute into the element, keeping the attributes in resource-id order."""
    slot = _attribute_slot(region, element, resource_map, resource_id)
    attribute = struct.pack(
        "<IIIHBBI",
        namespace_index,
        name_index,
        value_index,
        8,
        0,
        _TYPE_STRING,
        value_index,
    )
    at = element.attributes_offset + slot * _ATTRIBUTE_SIZE
    region[at:at] = attribute
    struct.pack_into("<H", region, element.offset + 28, element.attribute_count + 1)
    new_size = _u32(region, element.offset + 4) + _ATTRIBUTE_SIZE
    struct.pack_into("<I", region, element.offset + 4, new_size)
    _shift_special_indices(region, element.offset, slot)


def _attribute_slot(
    region: _Buffer, element: _Element, resource_map: list[int], resource_id: int
) -> int:
    """Returns the position for an attribute with `resource_id` among the element's, which are sorted by resource id."""
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        mapped = _attribute_resource_id(region, attribute, resource_map)
        if mapped == 0 or mapped > resource_id:
            return i
    return element.attribute_count


def _split(data: bytes) -> tuple[_StringPool, bytes]:
    """Splits the manifest into its string pool and the chunks that follow it."""
    if len(data) < _ROOT_HEADER_SIZE or _u16(data, 0) != RES_XML_TYPE:
        raise AxmlError("not a binary AndroidManifest.xml")
    pool, pool_size = _StringPool.parse(data, _ROOT_HEADER_SIZE)
    region = data[_ROOT_HEADER_SIZE + pool_size :]
    return pool, region


def _repoint_attribute(region: bytearray, attribute: int, value_index: int) -> None:
    """Points the attribute at `attribute` to the string at `value_index`."""
    struct.pack_into("<I", region, attribute + 8, value_index)
    struct.pack_into("<HBBI", region, attribute + 12, 8, 0, _TYPE_STRING, value_index)


def _shift_special_indices(region: bytearray, element_offset: int, slot: int) -> None:
    """Shifts the element's id, class and style attribute indices that sit at or after the inserted slot."""
    for field in (30, 32, 34):
        value = _u16(region, element_offset + field)
        if value != 0 and value - 1 >= slot:
            struct.pack_into("<H", region, element_offset + field, value + 1)


def _assemble(pool: _StringPool, region: bytearray) -> bytes:
    """Builds the manifest bytes from the string pool and the chunks that follow it."""
    pool_bytes = pool.serialize()
    total = _ROOT_HEADER_SIZE + len(pool_bytes) + len(region)
    header = struct.pack("<HHI", RES_XML_TYPE, _ROOT_HEADER_SIZE, total)
    return header + pool_bytes + bytes(region)


def _query_nodes(
    region: _Buffer, pool: _StringPool
) -> collections.abc.Iterator[tuple[int, int, int, tuple[str, ...]]]:
    """Walk validated element chunks without modifying host query intents/providers or nesting."""
    stack: list[str] = []
    offset = 0
    while offset < len(region):
        if len(region) - offset < 8:
            raise AxmlError("truncated XML chunk")
        kind, header, size = struct.unpack_from("<HHI", region, offset)
        if size < header or header < 8 or size > len(region) - offset:
            raise AxmlError("invalid XML chunk size")
        if kind in (RES_XML_START_ELEMENT_TYPE, RES_XML_END_ELEMENT_TYPE):
            if size < (36 if kind == RES_XML_START_ELEMENT_TYPE else 24):
                raise AxmlError("truncated element")
            name = _string(pool, _u32(region, offset + 20))
            if kind == RES_XML_START_ELEMENT_TYPE:
                stack.append(name)
                attributes = _u16(region, offset + 24) + _NODE_HEADER_SIZE
                if (
                    _u16(region, offset + 26) != _ATTRIBUTE_SIZE
                    or attributes < 36
                    or attributes + _u16(region, offset + 28) * _ATTRIBUTE_SIZE > size
                ):
                    raise AxmlError("invalid element attributes")
                if len(stack) > 256:
                    raise AxmlError("XML nesting exceeds limit")
            elif len(stack) == 0 or stack[-1] != name:
                raise AxmlError("unbalanced XML elements")
            yield offset, size, kind, tuple(stack)
            if kind == RES_XML_END_ELEMENT_TYPE:
                stack.pop()
        offset += size
    if len(stack) != 0:
        raise AxmlError("unclosed XML element")


def read_package_queries(data: bytes) -> tuple[str, ...]:
    """Read exact direct package queries in order, without enumerating or changing intents/providers."""
    pool, region = _split(data)
    result: list[str] = []
    for offset, _, kind, path in _query_nodes(region, pool):
        if kind != RES_XML_START_ELEMENT_TYPE or path != (
            "manifest",
            "queries",
            "package",
        ):
            continue
        attributes = offset + _NODE_HEADER_SIZE + _u16(region, offset + 24)
        for index in range(_u16(region, offset + 28)):
            attribute = attributes + index * _ATTRIBUTE_SIZE
            namespace = _u32(region, attribute)
            if (
                namespace != _NO_ENTRY
                and _string(pool, namespace) == ANDROID_NAMESPACE
                and _string(pool, _u32(region, attribute + 4)) == "name"
            ):
                if region[attribute + 15] != _TYPE_STRING:
                    raise AxmlError("package query name must be literal")
                result.append(_string(pool, _u32(region, attribute + 16)))
    return tuple(result)


def add_package_queries(data: bytes, packages: tuple[str, ...]) -> bytes:
    """Append missing exact package queries, retaining every original host element and attribute.

    Only the caller's fixed selected list is added; no permission or broad query is introduced.
    Reapplication is byte-identical. Missing queries are inserted in the first direct queries element.
    """
    existing = read_package_queries(data)
    missing = tuple(
        dict.fromkeys(package for package in packages if package not in existing)
    )
    if len(missing) == 0:
        return data
    pool, raw = _split(data)
    region = bytearray(raw)
    resource_map = _resource_map(region)
    name_index = _attribute_name_index(resource_map, ATTR_NAME_RESOURCE_ID)
    if name_index is None:
        name_index = len(resource_map)
        _shift_string_references(region, name_index)
        _insert_resource_map_entry(region, name_index, ATTR_NAME_RESOURCE_ID)
        pool.insert(name_index, "name")
    namespace = pool.index(ANDROID_NAMESPACE)
    if namespace is None:
        raise AxmlError("manifest has no android namespace string")

    def index(text: str) -> int:
        found = pool.index(text)
        return pool.append(text) if found is None else found

    def start(tag: int, attribute: bytes = b"") -> bytes:
        return (
            struct.pack(
                "<HHIII",
                RES_XML_START_ELEMENT_TYPE,
                16,
                36 + len(attribute),
                0,
                _NO_ENTRY,
            )
            + struct.pack(
                "<IIHHHHHH",
                _NO_ENTRY,
                tag,
                20,
                20,
                1 if len(attribute) > 0 else 0,
                0,
                0,
                0,
            )
            + attribute
        )

    def end(tag: int) -> bytes:
        return struct.pack(
            "<HHIIIII", RES_XML_END_ELEMENT_TYPE, 16, 24, 0, _NO_ENTRY, _NO_ENTRY, tag
        )

    package_tag = index("package")
    added = bytearray()
    for package in missing:
        value = index(package)
        attribute = struct.pack(
            "<IIIHBBI", namespace, name_index, value, 8, 0, _TYPE_STRING, value
        )
        added.extend(start(package_tag, attribute) + end(package_tag))
    insertion = next(
        (
            offset
            for offset, _, kind, path in _query_nodes(region, pool)
            if kind == RES_XML_END_ELEMENT_TYPE and path == ("manifest", "queries")
        ),
        None,
    )
    if insertion is None:
        insertion = next(
            (
                offset
                for offset, _, kind, path in _query_nodes(region, pool)
                if kind == RES_XML_END_ELEMENT_TYPE and path == ("manifest",)
            ),
            None,
        )
        if insertion is None:
            raise AxmlError("manifest has no root closing element")
        tag = index("queries")
        added = bytearray(start(tag) + added + end(tag))
    region[insertion:insertion] = added
    return _assemble(pool, region)

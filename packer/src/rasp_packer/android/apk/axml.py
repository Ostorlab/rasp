"""Editing Android's binary XML (AXML), the form of a built AndroidManifest.xml.

A built APK stores its manifest as binary XML, not text. The packer makes one
change to it: it points the application's entry class at the stub. This module
makes that change on the binary form directly, so the packer needs no Android
build tool at pack time.

The format is a sequence of chunks: an 8-byte root header, a pool holding every
string in the file, a map from the first strings to resource ids, then the XML
tree. Attributes name their namespace, name and value by index into that string
pool, and the resource map gives the numeric resource id (for example
`android:name` is `0x01010003`) of each attribute-name string.

Only two edits are needed, and both reuse the strings already in the pool, so the
pool only ever grows by one entry, the stub class name appended at the end:

- if ``<application>`` already has ``android:name``, repoint its value to the
  stub class;
- otherwise add an ``android:name`` attribute to ``<application>``.

Because the appended string goes at the end, past the resource map, every
existing string keeps its index and the resource map needs no change.

The parser is checked against manifests produced by aapt2; see the tests.
"""

import dataclasses
import struct
from typing import Self

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102

_ROOT_HEADER_SIZE = 8
_POOL_HEADER_SIZE = 28
_NODE_HEADER_SIZE = 16
_ATTR_EXT_SIZE = 20
_ATTRIBUTE_SIZE = 20

_UTF8_FLAG = 0x100
_TYPE_STRING = 0x03
_NO_ENTRY = 0xFFFFFFFF

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
APPLICATION_ELEMENT = "application"
MANIFEST_ELEMENT = "manifest"
PACKAGE_ATTRIBUTE = "package"
ATTR_NAME_RESOURCE_ID = 0x01010003


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


def _find_element(region: _Buffer, pool: _StringPool, name: str) -> _Element | None:
    """Returns the first start element named `name`, or None when there is none."""
    offset = 0
    while offset < len(region):
        chunk_type = _u16(region, offset)
        size = _u32(region, offset + 4)
        if chunk_type == RES_XML_START_ELEMENT_TYPE:
            name_index = _u32(region, offset + 20)
            if name_index != _NO_ENTRY and pool.decoded[name_index] == name:
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
            == ATTR_NAME_RESOURCE_ID
        ):
            value_index = _u32(region, attribute + 16)
            return pool.decoded[value_index]
    return None


def read_manifest_package(data: bytes) -> str | None:
    """Returns the package declared on ``<manifest>``, or None if it has none.

    Args:
        data: The binary AndroidManifest.xml.

    Returns:
        The app package, used to resolve a relative application class name.
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
        if pool.decoded[name_index] == PACKAGE_ATTRIBUTE:
            return pool.decoded[_u32(region, attribute + 16)]
    return None


def set_application_class(data: bytes, class_name: str) -> bytes:
    """Returns the manifest with ``<application android:name>`` set to ``class_name``.

    If the application already declares a name, its value is repointed. Otherwise
    an ``android:name`` attribute is added, kept in resource-id order.

    Args:
        data: The binary AndroidManifest.xml.
        class_name: The fully qualified class to set as the application entry.

    Returns:
        The edited binary AndroidManifest.xml.

    Raises:
        AxmlError: The bytes are not AXML, have no ``<application>``, or lack the
            strings needed to add the attribute.
    """
    pool, region_bytes = _split(data)
    region = bytearray(region_bytes)
    element = _find_element(region, pool, APPLICATION_ELEMENT)
    if element is None:
        raise AxmlError("manifest has no <application> element")
    resource_map = _resource_map(region)
    value_index = pool.index(class_name)
    if value_index is None:
        value_index = pool.append(class_name)
    existing = _find_name_attribute(region, element, resource_map)
    if existing is not None:
        _repoint_attribute(region, existing, value_index)
    else:
        _insert_name_attribute(region, element, pool, resource_map, value_index)
    return _assemble(pool, region)


def _split(data: bytes) -> tuple[_StringPool, bytes]:
    """Splits the manifest into its string pool and the chunks that follow it."""
    if len(data) < _ROOT_HEADER_SIZE or _u16(data, 0) != RES_XML_TYPE:
        raise AxmlError("not a binary AndroidManifest.xml")
    pool, pool_size = _StringPool.parse(data, _ROOT_HEADER_SIZE)
    region = data[_ROOT_HEADER_SIZE + pool_size :]
    return pool, region


def _find_name_attribute(
    region: _Buffer, element: _Element, resource_map: list[int]
) -> int | None:
    """Returns the offset of the element's android:name attribute, or None when it has none."""
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        if (
            _attribute_resource_id(region, attribute, resource_map)
            == ATTR_NAME_RESOURCE_ID
        ):
            return attribute
    return None


def _repoint_attribute(region: bytearray, attribute: int, value_index: int) -> None:
    """Points the attribute at `attribute` to the string at `value_index`."""
    struct.pack_into("<I", region, attribute + 8, value_index)
    struct.pack_into("<HBBI", region, attribute + 12, 8, 0, _TYPE_STRING, value_index)


def _insert_name_attribute(
    region: bytearray,
    element: _Element,
    pool: _StringPool,
    resource_map: list[int],
    value_index: int,
) -> None:
    """Inserts an android:name attribute with the string at `value_index` into the element, in resource id order."""
    name_index = _name_string_index(resource_map)
    if name_index is None:
        raise AxmlError("manifest has no attribute-name string for android:name")
    namespace_index = pool.index(ANDROID_NAMESPACE)
    if namespace_index is None:
        raise AxmlError("manifest has no android namespace string")
    slot = _insertion_slot(region, element, resource_map)
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


def _name_string_index(resource_map: list[int]) -> int | None:
    """Returns the string index that the resource map gives android:name, or None when it has none."""
    for index, resource_id in enumerate(resource_map):
        if resource_id == ATTR_NAME_RESOURCE_ID:
            return index
    return None


def _insertion_slot(region: _Buffer, element: _Element, resource_map: list[int]) -> int:
    """Returns the position at which android:name goes among the element's attributes, which are sorted by resource id."""
    for i in range(element.attribute_count):
        attribute = element.attributes_offset + i * _ATTRIBUTE_SIZE
        resource_id = _attribute_resource_id(region, attribute, resource_map)
        if resource_id == 0 or resource_id > ATTR_NAME_RESOURCE_ID:
            return i
    return element.attribute_count


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

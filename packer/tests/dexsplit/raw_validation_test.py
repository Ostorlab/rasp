"""Malformed real DEX mutations exercise both public native parsing boundaries."""

import hashlib
import pathlib
import struct
import zlib

import pytest

from dexsplit import _dex

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"


def _map(data: bytes | bytearray) -> dict[int, tuple[int, int, int]]:
    position = struct.unpack_from("<I", data, 52)[0]
    count = struct.unpack_from("<I", data, position)[0]
    return {
        kind: (size, offset, position + 4 + index * 12)
        for index, (kind, _, size, offset) in enumerate(
            struct.iter_unpack("<HHII", data[position + 4 : position + 4 + count * 12])
        )
    }


def _resign(data: bytearray) -> bytes:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return bytes(data)


@pytest.mark.parametrize(
    "mutation",
    [
        "string_interior",
        "proto_index",
        "field_index",
        "unused_opcode",
        "branch_interior",
        "annotation_visibility",
        "encoded_value_tag",
        "duplicate_map",
        "leb_overflow",
        "unterminated_debug",
        "unknown_section",
        "annotation_set_order",
        "unused_mapped_opcode",
        "unused_debug_index",
    ],
)
@pytest.mark.parametrize("boundary", ["model", "analysis"])
def testRead_whenRealDexHasMalformedStructure_refuses(
    mutation: str, boundary: str
) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    sections = _map(data)
    if mutation.startswith("unused_"):
        count, offset, _ = sections[6]
        for index in range(count):
            for field in (20, 24, 28):
                struct.pack_into("<I", data, offset + index * 32 + field, 0)
    if mutation == "annotation_set_order":
        count, position, _ = sections[0x1003]
        for _ in range(count):
            size = struct.unpack_from("<I", data, position)[0]
            if size >= 2:
                data[position + 4 : position + 12] = (
                    data[position + 8 : position + 12]
                    + data[position + 4 : position + 8]
                )
                break
            position += 4 + 4 * size
        else:
            raise AssertionError("fixture needs two annotations with different types")
    elif mutation == "unused_mapped_opcode":
        struct.pack_into("<H", data, sections[0x2001][1] + 16, 0x73)
    elif mutation == "unused_debug_index":
        _damage_unused_debug_index(data, sections)
    elif mutation == "string_interior":
        table = sections[1][1]
        struct.pack_into(
            "<I", data, table, struct.unpack_from("<I", data, table)[0] + 1
        )
    elif mutation == "proto_index":
        struct.pack_into("<I", data, sections[3][1], 0xFFFFFFFF)
    elif mutation == "field_index":
        struct.pack_into("<H", data, sections[4][1] + 2, 65535)
    elif mutation == "unused_opcode":
        struct.pack_into("<H", data, sections[0x2001][1] + 16, 0x73)
    elif mutation == "branch_interior":
        struct.pack_into("<HH", data, sections[0x2001][1] + 16, 0x29, 1)
    elif mutation == "annotation_visibility":
        data[sections[0x2004][1]] = 3
    elif mutation == "encoded_value_tag":
        data[sections[0x2005][1] + 1] = 1
    elif mutation == "duplicate_map":
        struct.pack_into("<H", data, sections[0x2001][2], 0)
    elif mutation == "leb_overflow":
        offset = sections[0x2000][1]
        data[offset : offset + 5] = b"\xff\xff\xff\xff\x1f"
    elif mutation == "unterminated_debug":
        offset = sections[0x2003][1]
        limit = min(
            position for _, position, _ in sections.values() if position > offset
        )
        data[offset:limit] = b"\x0a" * (limit - offset)
    else:
        struct.pack_into("<H", data, sections[0x2005][2], 0xFFFF)
    damaged = _resign(data)
    expression = r"(?i)(dex|index|opcode|instruction|annotation|encoded|leb|string|map|bound|debug)"
    if boundary == "model":
        with pytest.raises(ValueError, match=expression):
            _dex.Model.read(damaged)
    else:
        with pytest.raises(ValueError, match=expression):
            _dex.AnalysisContext.from_dex_buffers([damaged])


def testRead_whenUnsupportedVersion_hasControlledError() -> None:
    for version in (b"036", b"041", b"999"):
        data = bytearray(_SAMPLE.read_bytes())
        data[4:7] = version
        with pytest.raises(ValueError, match="version"):
            _dex.Model.read(_resign(data))


def _damage_unused_debug_index(
    data: bytearray, sections: dict[int, tuple[int, int, int]]
) -> None:
    count, position, _ = sections[0x2003]

    def leb() -> tuple[int, int]:
        nonlocal position
        begin = position
        value = shift = 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, position - begin
            shift += 7

    for _ in range(count):
        leb()
        parameters, _ = leb()
        for _ in range(parameters):
            begin = position
            _, width = leb()
            if width == 2:
                data[begin:position] = bytes((255, 127))
                return
        while True:
            opcode = data[position]
            position += 1
            if opcode == 0:
                break
            arguments = (
                3
                if opcode == 3
                else 4
                if opcode == 4
                else 1
                if opcode in (1, 2, 5, 6, 9)
                else 0
            )
            for _ in range(arguments):
                leb()
    raise AssertionError("fixture needs a two-byte debug parameter index")


def testRead_whenMappedCodeIsUnusedButValid_preservesBareDefinitions() -> None:
    data = bytearray(_SAMPLE.read_bytes())
    count, offset, _ = _map(data)[6]
    for index in range(count):
        for field in (20, 24, 28):
            struct.pack_into("<I", data, offset + index * 32 + field, 0)
    valid = _resign(data)
    assert len(_dex.Model.read(valid).class_descriptors) == 12
    assert len(_dex.AnalysisContext.from_dex_buffers([valid]).classes) == 12

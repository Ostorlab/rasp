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


def _mapped_code_items(data: bytearray) -> list[tuple[int, int]]:
    """Locate complete real mapped code items, including encoded handlers."""
    count, position, _ = _map(data)[0x2001]
    found: list[tuple[int, int]] = []

    def leb(signed: bool = False) -> int:
        nonlocal position
        value = shift = 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                return value - (1 << shift) if signed and byte & 64 else value

    for _ in range(count):
        position = (position + 3) & ~3
        start = position
        tries = struct.unpack_from("<H", data, start + 6)[0]
        units = struct.unpack_from("<I", data, start + 12)[0]
        position += 16 + 2 * units
        if tries:
            position += 2 * (units % 2)
        found.append((start, position))
        if tries:
            position += 8 * tries
            for _ in range(leb()):
                size = leb(signed=True)
                for _ in range(abs(size)):
                    leb()
                    leb()
                if size <= 0:
                    leb()
    return found


@pytest.mark.parametrize("boundary", ["model", "analysis"])
@pytest.mark.parametrize(
    "damage",
    ["valid", "branch", "register", "try-empty", "try-interior", "handler-offset"],
)
def testRead_whenMappedCodeIsUnused_validatesAllStructuralBounds(
    damage: str, boundary: str
) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    count, offset, _ = _map(data)[6]
    for index in range(count):
        for field in (20, 24, 28):
            struct.pack_into("<I", data, offset + index * 32 + field, 0)
    codes = _mapped_code_items(data)
    code, _ = codes[0]
    if damage == "branch":
        struct.pack_into("<HH", data, code + 16, 0x29, 0x7FFF)
    elif damage == "register":
        struct.pack_into("<H", data, code, 0)
    elif damage.startswith("try-") or damage == "handler-offset":
        _, position = next(
            (start, end)
            for start, end in codes
            if struct.unpack_from("<H", data, start + 6)[0]
        )
        if damage == "try-empty":
            struct.pack_into("<H", data, position + 4, 0)
        elif damage == "try-interior":
            struct.pack_into("<I", data, position, 1)
        else:
            struct.pack_into("<H", data, position + 6, 0xFFFF)
    payload = _resign(data)
    if damage == "valid":
        if boundary == "model":
            _dex.Model.read(payload).write()
        else:
            _dex.AnalysisContext.from_dex_buffers([payload])
    elif boundary == "model":
        with pytest.raises(
            ValueError, match=r"(?i)(code|register|branch|try|handler|instruction)"
        ):
            _dex.Model.read(payload)
    else:
        with pytest.raises(
            ValueError, match=r"(?i)(code|register|branch|try|handler|instruction)"
        ):
            _dex.AnalysisContext.from_dex_buffers([payload])


@pytest.mark.parametrize("boundary", ["model", "analysis"])
def testRead_whenCompleteCodeItemHasMultipleOwners_accepts(boundary: str) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    sections = _map(data)
    methods_offset = sections[5][1]
    candidates: dict[tuple[int, int, int], tuple[int, int]] = {}
    shared = False

    def leb(position: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                return value, position

    count, offset, _ = sections[6]
    for index in range(count):
        position = struct.unpack_from("<I", data, offset + 32 * index + 24)[0]
        if position == 0:
            continue
        sizes = []
        for _ in range(4):
            size, position = leb(position)
            sizes.append(size)
        for _ in range(sizes[0] + sizes[1]):
            _, position = leb(position)
            _, position = leb(position)
        for size in sizes[2:]:
            method_index = 0
            for _ in range(size):
                delta, position = leb(position)
                method_index += delta
                _, position = leb(position)
                begin = position
                code, position = leb(position)
                if code == 0:
                    continue
                prototype = struct.unpack_from(
                    "<H", data, methods_offset + 8 * method_index + 2
                )[0]
                incoming = struct.unpack_from("<H", data, code + 2)[0]
                key = (prototype, incoming, position - begin)
                if key in candidates and candidates[key][0] != code and shared is False:
                    original, original_begin = candidates[key]
                    assert original != code
                    data[begin:position] = data[
                        original_begin : original_begin + position - begin
                    ]
                    shared = True
                else:
                    candidates[key] = (code, begin)
    assert shared is True
    payload = _resign(data)
    if boundary == "model":
        model = _dex.Model.read(payload)
        assert len(model.class_descriptors) == 12
        _dex.Model.read(model.write())
    else:
        assert len(_dex.AnalysisContext.from_dex_buffers([payload]).classes) == 12


def _damage_unused_debug_frame(data: bytearray, damage: str) -> None:
    def leb(position: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                return value, position

    for code, _ in _mapped_code_items(data):
        registers = struct.unpack_from("<H", data, code)[0]
        units = struct.unpack_from("<I", data, code + 12)[0]
        position = struct.unpack_from("<I", data, code + 8)[0]
        if position == 0:
            continue
        _, position = leb(position)
        count, position = leb(position)
        for _ in range(count):
            _, position = leb(position)
        while True:
            begin = position
            opcode = data[position]
            position += 1
            if opcode == 0:
                break
            if (
                damage == "debug-position"
                and units < 16
                and (opcode >= 10 or opcode in (7, 8))
            ):
                data[begin] = 255
                return
            arguments = (
                3
                if opcode == 3
                else 4
                if opcode == 4
                else 1
                if opcode in (1, 2, 5, 6, 9)
                else 0
            )
            for argument in range(arguments):
                begin = position
                _, position = leb(position)
                if (
                    damage == "debug-register"
                    and opcode in (3, 4, 5, 6)
                    and argument == 0
                    and position == begin + 1
                    and registers < 128
                ):
                    data[begin] = registers
                    return
    raise AssertionError("fixture needs the associated debug-frame event")


@pytest.mark.parametrize("boundary", ["model", "analysis"])
@pytest.mark.parametrize("damage", ["debug-register", "debug-position"])
def testRead_whenUnusedMappedDebugNamesFrameOrPositionOutsideBody_refuses(
    damage: str, boundary: str
) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    _damage_unused_debug_frame(data, damage)
    count, offset, _ = _map(data)[6]
    for index in range(count):
        for field in (20, 24, 28):
            struct.pack_into("<I", data, offset + 32 * index + field, 0)
    payload = _resign(data)
    if boundary == "model":
        with pytest.raises(ValueError, match=r"(?i)(debug|register|position)"):
            _dex.Model.read(payload)
    else:
        with pytest.raises(ValueError, match=r"(?i)(debug|register|position)"):
            _dex.AnalysisContext.from_dex_buffers([payload])


def _type_index(data: bytearray, descriptor: bytes) -> int:
    sections = _map(data)
    count, types, _ = sections[2]
    strings = sections[1][1]
    for index in range(count):
        string_index = struct.unpack_from("<I", data, types + 4 * index)[0]
        position = struct.unpack_from("<I", data, strings + 4 * string_index)[0]
        while data[position] & 128:
            position += 1
        position += 1
        end = data.index(0, position)
        if data[position:end] == descriptor:
            return index
    raise AssertionError("fixture needs the requested type")


@pytest.mark.parametrize("boundary", ["model", "analysis"])
@pytest.mark.parametrize(("opcode", "descriptor"), [(0x22, b"I"), (0x1C, b"V")])
def testRead_whenUnusedInstructionRequiresDifferentTypeKind_refuses(
    opcode: int, descriptor: bytes, boundary: str
) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    sections = _map(data)
    type_index = _type_index(data, descriptor)
    struct.pack_into("<HH", data, sections[0x2001][1] + 16, opcode, type_index)
    count, offset, _ = sections[6]
    for index in range(count):
        for field in (20, 24, 28):
            struct.pack_into("<I", data, offset + 32 * index + field, 0)
    payload = _resign(data)
    if boundary == "model":
        with pytest.raises(ValueError, match=r"(?i)(type|class|void)"):
            _dex.Model.read(payload)
    else:
        with pytest.raises(ValueError, match=r"(?i)(type|class|void)"):
            _dex.AnalysisContext.from_dex_buffers([payload])


@pytest.mark.parametrize("boundary", ["model", "analysis"])
def testRead_whenDebugMapCountCannotFitSection_refusesBeforeReservation(
    boundary: str,
) -> None:
    data = bytearray(_SAMPLE.read_bytes())
    _, _, record = _map(data)[0x2003]
    struct.pack_into("<I", data, record + 4, 100_000_000)
    payload = _resign(data)
    with _dex.Request() as request:
        if boundary == "model":
            with pytest.raises(ValueError, match="debug item count"):
                _dex.Model.read(payload)
        else:
            with pytest.raises(ValueError, match="debug item count"):
                _dex.AnalysisContext.from_dex_buffers([payload])
        assert request.storage < 64 * 1024 * 1024

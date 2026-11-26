"""Tests for the at-rest guard: write_guard encrypts the marker into a runtime binary."""

import io
import pathlib
import struct
import tempfile

import lief

from rasp_packer.ios import guard

_DATA = pathlib.Path(__file__).resolve().parent.parent / "data" / "runtime_config"
_BINARY = (_DATA / "RaspRuntime").read_bytes()

_MARKER = b"RASPOK!!"
_GUARD_SIZE = 32
_NONCE = bytes(
    [
        0x00,
        0x00,
        0x00,
        0x00,
        0x61,
        0x74,
        0x72,
        0x73,
        0x74,
        0x67,
        0x75,
        0x61,
        0x72,
        0x64,
        0x30,
        0x31,
    ]
)


def _build_fixture_with_guard_section() -> bytes:
    """Build a Mach-O fixture that has a __DATA,__rasp_guard section filled with zeros."""
    fat = lief.MachO.parse(io.BytesIO(_BINARY))
    assert fat is not None
    macho = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert macho is not None
    section = lief.MachO.Section.create("__rasp_guard", [0] * 64)
    assert section is not None
    seg = macho.get_segment("__DATA")
    assert seg is not None
    macho.add_section(seg, section)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        tmp = f.name
    macho.write(tmp)
    return pathlib.Path(tmp).read_bytes()


def _decrypt_guard_blob(binary: bytes) -> bytes:
    """Re-derive the key from the binary and decrypt the guard blob, as the runtime would."""
    fat = lief.MachO.parse(io.BytesIO(binary))
    assert fat is not None
    for macho in fat:
        gs = macho.get_section("__DATA", "__rasp_guard")
        ts = macho.get_section("__TEXT", "__text")
        if gs is None or ts is None:
            continue
        blob_off = macho.fat_offset + gs.offset
        text_off = macho.fat_offset + ts.offset
        blob = bytearray(binary[blob_off : blob_off + _GUARD_SIZE])
        text = binary[text_off : text_off + ts.size]
        code_hash = _hash_region(text)
        seed = _reconstruct_seed()
        key = _hash_region(seed + code_hash)
        _chacha20_xor(blob, key, _NONCE)
        return bytes(blob)
    raise AssertionError("no __DATA,__rasp_guard section found")


def _hash_region(data: bytes) -> bytes:
    """FNV-1a 4-lane hash, identical to the runtime and packer implementations."""
    fnv_offset = 0xCBF29CE484222325
    fnv_prime = 0x100000001B3
    mask64 = (1 << 64) - 1
    lanes_count = 4
    lanes = [
        (fnv_offset ^ ((lane * fnv_prime) & mask64)) & mask64
        for lane in range(lanes_count)
    ]
    for index, byte in enumerate(data):
        lane = index % lanes_count
        lanes[lane] = ((lanes[lane] ^ byte) * fnv_prime) & mask64
    for lane in range(lanes_count):
        lanes[lane] ^= len(data) & mask64
        lanes[lane] = (lanes[lane] * fnv_prime) & mask64
        lanes[lane] ^= lanes[(lane + 1) % lanes_count] >> 29
        lanes[lane] &= mask64
    return b"".join(struct.pack("<Q", lane) for lane in lanes)


def _reconstruct_seed() -> bytes:
    """The default development scatter, identical to the runtime and packer."""
    seed = bytearray(32)
    for i in range(32):
        target = ((i * 37) + 11) & 0xFF
        half = (0x5A + i) & 0xFF
        seed[i] ^= half
        seed[i] ^= target ^ half
    return bytes(seed)


def _rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_xor(data: bytearray, key: bytes, nonce16: bytes) -> None:
    """ChaCha20 in place, for test-side decryption."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    offset = 0
    while offset < len(data):
        working = list(state)
        for _ in range(10):
            _quarter_round(working, 0, 4, 8, 12)
            _quarter_round(working, 1, 5, 9, 13)
            _quarter_round(working, 2, 6, 10, 14)
            _quarter_round(working, 3, 7, 11, 15)
            _quarter_round(working, 0, 5, 10, 15)
            _quarter_round(working, 1, 6, 11, 12)
            _quarter_round(working, 2, 7, 8, 13)
            _quarter_round(working, 3, 4, 9, 14)
        out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        keystream = b"".join(struct.pack("<I", word) for word in out)
        take = min(64, len(data) - offset)
        for i in range(take):
            data[offset + i] ^= keystream[i]
        offset += take
        state[12] = (state[12] + 1) & 0xFFFFFFFF


def testWriteGuard_whenBinaryHasNoGuardSection_returnsBinaryUnchanged() -> None:
    result = guard.write_guard(_BINARY)

    assert result == _BINARY


def testWriteGuard_whenBinaryHasGuardSection_writesNonZeroBlob() -> None:
    fixture = _build_fixture_with_guard_section()

    guarded = guard.write_guard(fixture)

    fat = lief.MachO.parse(io.BytesIO(guarded))
    assert fat is not None
    for macho in fat:
        gs = macho.get_section("__DATA", "__rasp_guard")
        if gs is not None:
            blob_off = macho.fat_offset + gs.offset
            blob = guarded[blob_off : blob_off + _GUARD_SIZE]
            assert blob != bytes(_GUARD_SIZE)
            return
    raise AssertionError("no __DATA,__rasp_guard section in output")


def testWriteGuard_whenBinaryHasGuardSection_blobDecryptsToMarker() -> None:
    fixture = _build_fixture_with_guard_section()

    guarded = guard.write_guard(fixture)
    plaintext = _decrypt_guard_blob(guarded)

    assert plaintext[:8] == _MARKER
    assert plaintext[8:] == bytes(_GUARD_SIZE - len(_MARKER))


def testWriteGuard_whenCodeIsPatched_blobDoesNotDecryptToMarker() -> None:
    fixture = _build_fixture_with_guard_section()
    guarded = guard.write_guard(fixture)

    fat = lief.MachO.parse(io.BytesIO(guarded))
    assert fat is not None
    tampered = bytearray(guarded)
    for macho in fat:
        ts = macho.get_section("__TEXT", "__text")
        if ts is not None:
            text_off = macho.fat_offset + ts.offset
            tampered[text_off] ^= 0x01
            break

    plaintext = _decrypt_guard_blob(bytes(tampered))

    assert plaintext[:8] != _MARKER


def testWriteGuard_whenBinaryHasGuardSection_doesNotChangeSize() -> None:
    fixture = _build_fixture_with_guard_section()

    guarded = guard.write_guard(fixture)

    assert len(guarded) == len(fixture)

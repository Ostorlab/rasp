"""The at-rest guard blob in the iOS runtime binary, `RaspRuntime` in `RaspRuntime.framework`.

The runtime carries an encrypted guard blob in a `__DATA,__rasp_guard` section. At load the runtime derives a key from
a hash of its own code and the scattered seed, decrypts the blob, and checks it against a known marker; an intact
runtime decrypts it, a patched one does not. This module is the packer side: it computes the same key from the shipped
binary and writes the ciphertext of the marker into the section, so a packed build's blob decrypts and an unpacked one
(all zeros) does not.

The key derivation here mirrors the runtime's (ios/src/selfdecrypt/{atrest,seed,guard}.cpp) byte for byte; the two must
stay in step.
"""

import io
import struct

import lief

from rasp_packer import errors

MACHO_SEGMENT = "__DATA"
MACHO_SECTION = "__rasp_guard"

_GUARD_SIZE = 32
_KEY_BYTES = 32
_SEED_BYTES = 32
_CODE_WINDOW = 256
# "RASPOK!!" followed by zero padding to the blob size.
_MARKER = b"RASPOK!!"
# The fixed 16-byte counter and nonce the runtime uses for the guard blob.
_NONCE = bytes([0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73, 0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31])

_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_LANES = _KEY_BYTES // 8
_MASK64 = (1 << 64) - 1


def write_guard(binary: bytes) -> bytes:
    """Encrypts the guard blob into every slice of the runtime binary.

    Args:
        binary: The content of the `RaspRuntime` binary.

    Returns:
        The binary with the ciphertext of the marker written into the `__DATA,__rasp_guard` section of each slice. Its
        size does not change.

    Raises:
        InvalidRuntimeError: The binary is not a Mach-O file, or a slice has no `__DATA,__rasp_guard` section, or the
            section is smaller than the guard blob.
    """
    data = bytearray(binary)
    for guard_offset, section_size, text in _slices(binary):
        if section_size < _GUARD_SIZE:
            raise errors.InvalidRuntimeError(
                f"the {MACHO_SEGMENT},{MACHO_SECTION} section is {section_size} bytes, smaller than the guard"
            )
        key = _derive_key(_hash_region(text), _reconstruct_seed())
        blob = bytearray(_GUARD_SIZE)
        blob[: len(_MARKER)] = _MARKER
        _chacha20_xor(blob, key, _NONCE)
        data[guard_offset : guard_offset + _GUARD_SIZE] = blob
    return bytes(data)


def _slices(binary: bytes) -> list[tuple[int, int, bytes]]:
    """For each slice: the guard section's file offset and size, and the __TEXT,__text bytes the key is bound to.

    The runtime hashes its own __TEXT,__text section at load; the packer hashes the same bytes from the file. The two
    match because ASLR slides where __text loads, not what it holds.
    """
    fat = lief.MachO.parse(io.BytesIO(binary))
    if fat is None:
        raise errors.InvalidRuntimeError("the runtime binary is not a Mach-O file")
    found: list[tuple[int, int, bytes]] = []
    for macho in fat:
        section = macho.get_section(MACHO_SEGMENT, MACHO_SECTION)
        if section is None:
            raise errors.InvalidRuntimeError(
                f"the runtime binary has no {MACHO_SEGMENT},{MACHO_SECTION} section"
            )
        text_section = macho.get_section("__TEXT", "__text")
        if text_section is None:
            raise errors.InvalidRuntimeError("the runtime binary has no __TEXT,__text section")
        start = macho.fat_offset + text_section.offset
        text = binary[start : start + text_section.size]
        if len(text) < text_section.size:
            raise errors.InvalidRuntimeError("the __TEXT,__text section runs past the end of the binary")
        found.append((macho.fat_offset + section.offset, section.size, text))
    return found


def _reconstruct_seed() -> bytes:
    """The scattered seed, rebuilt exactly as the runtime's reconstruct_seed does (default development scatter)."""
    seed = bytearray(_SEED_BYTES)
    for i in range(_SEED_BYTES):
        target = ((i * 37) + 11) & 0xFF
        half = (0x5A + i) & 0xFF
        seed[i] ^= half
        seed[i] ^= target ^ half
    return bytes(seed)


def _hash_region(data: bytes) -> bytes:
    """The runtime's hash_region: four FNV-1a lanes, an avalanche pass, little-endian output."""
    lanes = [(_FNV_OFFSET ^ ((lane * _FNV_PRIME) & _MASK64)) & _MASK64 for lane in range(_LANES)]
    for index, byte in enumerate(data):
        lane = index % _LANES
        lanes[lane] = ((lanes[lane] ^ byte) * _FNV_PRIME) & _MASK64
    for lane in range(_LANES):
        lanes[lane] ^= len(data) & _MASK64
        lanes[lane] = (lanes[lane] * _FNV_PRIME) & _MASK64
        lanes[lane] ^= lanes[(lane + 1) % _LANES] >> 29
        lanes[lane] &= _MASK64
    return b"".join(struct.pack("<Q", lane) for lane in lanes)


def _derive_key(code_hash: bytes, seed: bytes) -> bytes:
    """The runtime's derive_key: hash_region(seed || code_hash)."""
    return _hash_region(seed + code_hash)


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


def _chacha20_block(state: list[int]) -> bytes:
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
    return b"".join(struct.pack("<I", word) for word in out)


def _chacha20_xor(data: bytearray, key: bytes, nonce16: bytes) -> None:
    """ChaCha20 in place, byte layout identical to the runtime's chacha20_xor."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    offset = 0
    while offset < len(data):
        keystream = _chacha20_block(state)
        take = min(64, len(data) - offset)
        for i in range(take):
            data[offset + i] ^= keystream[i]
        offset += take
        state[12] = (state[12] + 1) & 0xFFFFFFFF

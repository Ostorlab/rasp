"""Packs the app's original dex files into one encrypted payload.

The payload is a container of the original dex files, encrypted as a single
frame (see cipher). The native runtime decrypts it, and the stub loads each dex
with InMemoryDexClassLoader.

Container layout, before encryption:

    count     4 bytes     number of dex files, big-endian
    for each dex, in load order:
        name_length  4 bytes   length of the name in bytes, big-endian
        name         *         entry name, UTF-8 (for example "classes.dex")
        data_length  4 bytes   length of the dex, big-endian
        data         *         the dex bytes
"""

import collections.abc
import dataclasses
import struct

from rasp_packer.android import cipher


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Dex:
    """One dex file from the app.

    Attributes:
        name: The entry name in the APK (for example "classes.dex").
        data: The dex bytes.
    """

    name: str
    data: bytes


def build(key: bytes, dexes: collections.abc.Sequence[Dex]) -> bytes:
    """Builds the encrypted payload from the app's dex files.

    Args:
        key: The master key to encrypt with.
        dexes: The original dex files, in load order.

    Returns:
        The encrypted payload frame.
    """
    container = bytearray(struct.pack(">I", len(dexes)))
    for dex in dexes:
        name = dex.name.encode("utf-8")
        container += struct.pack(">I", len(name))
        container += name
        container += struct.pack(">I", len(dex.data))
        container += dex.data
    return cipher.encrypt(key, bytes(container))


def parse(key: bytes, payload: bytes) -> list[Dex]:
    """Decrypts a payload and returns its dex files.

    The native runtime does this in C; this is the reference, used by the tests.

    Args:
        key: The master key the payload was encrypted with.
        payload: A payload produced by build.

    Returns:
        The dex files, in load order.
    """
    container = cipher.decrypt(key, payload)
    dexes: list[Dex] = []
    offset = 0
    (count,) = struct.unpack_from(">I", container, offset)
    offset += 4
    for _ in range(count):
        (name_length,) = struct.unpack_from(">I", container, offset)
        offset += 4
        name = container[offset : offset + name_length].decode("utf-8")
        offset += name_length
        (data_length,) = struct.unpack_from(">I", container, offset)
        offset += 4
        dexes.append(
            Dex(name=name, data=bytes(container[offset : offset + data_length]))
        )
        offset += data_length
    return dexes

"""Minimal DER reader: enough to walk the Android Key Attestation extension."""

from __future__ import annotations

from dataclasses import dataclass

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

INTEGER = 0x02
OCTET_STRING = 0x04
ENUMERATED = 0x0A
BOOLEAN = 0x01
SEQUENCE = 0x10
SET = 0x11


class DerError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    cls: int
    constructed: bool
    tag: int
    value: bytes

    def children(self) -> list[Node]:
        if not self.constructed:
            raise DerError(f"tag {self.tag} is primitive")
        return parse_all(self.value)

    def as_int(self) -> int:
        if not self.value:
            raise DerError("empty integer")
        return int.from_bytes(self.value, "big", signed=True)

    def as_bool(self) -> bool:
        if len(self.value) != 1:
            raise DerError("bad boolean")
        return self.value != b"\x00"


def _read(data: bytes, pos: int) -> tuple[Node, int]:
    if pos >= len(data):
        raise DerError("truncated")
    first = data[pos]
    pos += 1
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    if tag == 0x1F:  # high-tag-number form, e.g. [709] attestationApplicationId
        tag = 0
        while True:
            if pos >= len(data):
                raise DerError("truncated tag")
            byte = data[pos]
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    if pos >= len(data):
        raise DerError("truncated length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise DerError("value past end")
    return Node(cls, constructed, tag, data[pos:end]), end


def parse(data: bytes) -> Node:
    node, end = _read(data, 0)
    if end != len(data):
        raise DerError("trailing bytes")
    return node


def parse_all(data: bytes) -> list[Node]:
    nodes, pos = [], 0
    while pos < len(data):
        node, pos = _read(data, pos)
        nodes.append(node)
    return nodes

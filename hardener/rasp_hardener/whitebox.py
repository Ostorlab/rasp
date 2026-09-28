"""White-box AES-128 table generation with optional seeded affine state encodings.

Turns a 16-byte AES key into lookup tables that a table-driven evaluator (native ``wbaes.c``) uses to encrypt
AES-128 blocks **without the key appearing as a contiguous literal** in the binary. This is the structural
foundation of white-box AES:

  round r (1..9):  x = ShiftRows(state)
                   col c out(32-bit) = XOR_{i=0..3}  TypeII[r][4c+i][ x[4c+i] ]
  round 10:        x = ShiftRows(state);  state[p] = TypeIILast[p][ x[p] ]

Each ``TypeII`` entry folds, for one byte position, the previous round's AddRoundKey (as ShiftRows(k)), the
SubBytes S-box, and one column of MixColumns (the "Tyi" tables). The initial AddRoundKey(k0) is folded into
round 1; the final AddRoundKey(k10) into the last table.

An optional 32-byte encoding seed absorbs invertible affine byte encodings across
nine state boundaries. These preserve the evaluator ABI and AES behavior. They are
not full nonlinear encoded-XOR networks or demonstrated DCA/DFA countermeasures;
embedded keys remain extractable by a determined analyst. Without an encoding seed,
the original plain reference tables are generated.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from rasp_hardener import aes
from rasp_hardener import encodings

# AES MixColumns matrix (used to build the Tyi tables).
MIXCOL = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def pack32(b: tuple[int, int, int, int]) -> int:
    """Pack 4 bytes (row0..row3) into a 32-bit int, row0 most significant. Must match wbaes.c."""
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def unpack32(v: int) -> list[int]:
    return [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]


def _tyi(row: int, t: int) -> int:
    """Tyi table for a byte `t` sitting in MixColumns input `row`: its 32-bit contribution to the column."""
    return pack32(tuple(aes.gf_mul(MIXCOL[j][row], t) for j in range(4)))


@dataclass(frozen=True)
class WhiteBoxTables:
    """The generated tables. ``type2[r-1][p][x]`` for r in 1..9; ``last[p][x]`` for round 10."""

    type2: list[list[list[int]]]  # [9][16][256] of uint32
    last: list[list[int]]         # [16][256] of uint8

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Evaluate AES-128 using only the tables. Mirrors wbaes.c byte-for-byte."""
        if len(plaintext) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(plaintext)
        for r in range(9):
            x = aes.shift_rows(state)
            new_state = [0] * 16
            for c in range(4):
                acc = 0
                for i in range(4):
                    p = c * 4 + i
                    acc ^= self.type2[r][p][x[p]]
                new_state[c * 4 : c * 4 + 4] = unpack32(acc)
            state = new_state
        x = aes.shift_rows(state)
        state = [self.last[p][x[p]] for p in range(16)]
        return bytes(state)


    def encrypt_block_checked(self, other: WhiteBoxTables, plaintext: bytes) -> bytes:
        """Reject divergent results from independently encoded same-key tables.

        This detects the measured single-table faults, not common-mode faults or DCA.
        Callers must opt in; existing CTR/CMAC APIs retain their original evaluator.
        """
        first = self.encrypt_block(plaintext)
        second = other.encrypt_block(plaintext)
        if hmac.compare_digest(first, second) is False:
            raise ValueError("redundant AES evaluation mismatch")
        return first


def generate(key: bytes, encoding_seed: bytes | None = None) -> WhiteBoxTables:
    """Generate AES tables; a 32-byte encoding seed adds nine affine state boundaries."""
    round_keys = aes.key_expansion(key)
    # sk[r] = ShiftRows(k[r]) so that AddRoundKey-before-ShiftRows folds into SubBytes-after-ShiftRows.
    sk = [aes.shift_rows(rk) for rk in round_keys]

    type2: list[list[list[int]]] = []
    for r in range(1, 10):
        round_tables: list[list[int]] = []
        for p in range(16):
            row = p % 4
            key_byte = sk[r - 1][p]
            table = [_tyi(row, aes.SBOX[x ^ key_byte]) for x in range(256)]
            round_tables.append(table)
        type2.append(round_tables)

    last: list[list[int]] = []
    for p in range(16):
        key_byte = sk[9][p]
        final_key = round_keys[10][p]
        last.append([aes.SBOX[x ^ key_byte] ^ final_key for x in range(256)])

    if encoding_seed is not None:
        if len(encoding_seed) != 32:
            raise ValueError("encoding seed must be 32 bytes")
        boundaries = [[encodings.byte_encoding(encoding_seed, boundary, position) for position in range(16)] for boundary in range(9)]
        shifted_positions = aes.shift_rows(list(range(16)))
        for round_index in range(9):
            for position in range(16):
                original = type2[round_index][position]
                inverse = boundaries[round_index - 1][shifted_positions[position]][1] if round_index > 0 else list(range(256))
                column_start = position // 4 * 4
                transformed = []
                for encoded_input in range(256):
                    contribution = unpack32(original[inverse[encoded_input]])
                    output = []
                    for row in range(4):
                        linear, _, offset = boundaries[round_index][column_start + row]
                        # XOR is linear: combine four encoded contributions into E(sum).
                        # Exactly one contribution carries the affine offset.
                        output.append(linear[contribution[row]] ^ (offset if position % 4 == 0 else 0))
                    transformed.append(pack32(tuple(output)))
                type2[round_index][position] = transformed
        for position in range(16):
            original = last[position]
            inverse = boundaries[8][shifted_positions[position]][1]
            last[position] = [original[inverse[value]] for value in range(256)]
    return WhiteBoxTables(type2=type2, last=last)


# --- CTR mode, AES-CMAC, and SecureStore reference (mirrors wbaes.c / securestore.c) -------------------------

NONCE_LEN = 12
TAG_LEN = 16
_CMAC_RB = b"\x00" * 15 + b"\x87"  # GF(2^128) reduction constant for the CMAC subkeys (RFC 4493)


def ctr(tables: WhiteBoxTables, nonce: bytes, data: bytes) -> bytes:
    """AES-128-CTR over the white-box block function; keystream = E(nonce || counter_be32) from counter 0."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    out = bytearray()
    counter = 0
    for off in range(0, max(len(data), 0), 16):
        keystream = tables.encrypt_block(bytes(nonce) + counter.to_bytes(4, "big"))
        chunk = data[off : off + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter += 1
    return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _shift_left_1(block: bytes) -> bytes:
    return ((int.from_bytes(block, "big") << 1) & ((1 << 128) - 1)).to_bytes(16, "big")


def _cmac_subkeys(tables: WhiteBoxTables) -> tuple[bytes, bytes]:
    """The two CMAC subkeys K1, K2 derived from E(0^128) per RFC 4493."""
    k0 = tables.encrypt_block(bytes(16))
    k1 = _shift_left_1(k0)
    if k0[0] & 0x80:
        k1 = _xor(k1, _CMAC_RB)
    k2 = _shift_left_1(k1)
    if k1[0] & 0x80:
        k2 = _xor(k2, _CMAC_RB)
    return k1, k2


def cmac(tables: WhiteBoxTables, message: bytes) -> bytes:
    """AES-CMAC (RFC 4493) over `message` using the white-box block E_k. Returns the 16-byte tag."""
    k1, k2 = _cmac_subkeys(tables)
    complete = len(message) > 0 and len(message) % 16 == 0
    blocks = max((len(message) + 15) // 16, 1)
    if complete:
        last = _xor(message[(blocks - 1) * 16 :], k1)
    else:
        rem = message[(blocks - 1) * 16 :]
        padded = rem + b"\x80" + b"\x00" * (15 - len(rem))
        last = _xor(padded, k2)
    x = bytes(16)
    for i in range(blocks - 1):
        x = tables.encrypt_block(_xor(x, message[i * 16 : (i + 1) * 16]))
    return tables.encrypt_block(_xor(x, last))


def secure_store_seal(tables: WhiteBoxTables, nonce: bytes, plaintext: bytes) -> bytes:
    """Authenticated seal: ``nonce(12) || ciphertext || tag(16)``, encrypt-then-MAC (CTR + AES-CMAC).

    The tag authenticates ``nonce || ciphertext``, so any change to the nonce or ciphertext is detected on
    open. Single-key CTR+CMAC composition, in the spirit of CCM (the white-box carries one embedded key).
    """
    ciphertext = ctr(tables, nonce, plaintext)
    tag = cmac(tables, bytes(nonce) + ciphertext)
    return bytes(nonce) + ciphertext + tag


def secure_store_open(tables: WhiteBoxTables, sealed: bytes) -> bytes:
    """Verify the tag (constant-time), then decrypt. Raises ``ValueError`` on any tampering."""
    if len(sealed) < NONCE_LEN + TAG_LEN:
        raise ValueError("sealed blob too short")
    nonce = sealed[:NONCE_LEN]
    tag = sealed[-TAG_LEN:]
    ciphertext = sealed[NONCE_LEN:-TAG_LEN]
    if not hmac.compare_digest(cmac(tables, nonce + ciphertext), tag):
        raise ValueError("integrity check failed")
    return ctr(tables, nonce, ciphertext)


# --- C header emission --------------------------------------------------------------------------------------

_AUTOGEN = "/* Generated by rasp-hardener. Do not edit; regenerate from the white-box key. */"


def render_tables_h(tables: WhiteBoxTables, name: str = "RASP_WBAES") -> str:
    """Render the tables as a C header: ``<name>_TYPE2[9][16][256]`` and ``<name>_LAST[16][256]``."""
    lines = [
        _AUTOGEN,
        f"#ifndef {name}_TABLES_H",
        f"#define {name}_TABLES_H",
        "",
        "#include <stdint.h>",
        "",
        f"static const uint32_t {name}_TYPE2[9][16][256] = {{",
    ]
    for r in range(9):
        lines.append("  {")
        for p in range(16):
            row = ", ".join(f"0x{v:08x}" for v in tables.type2[r][p])
            lines.append(f"    {{ {row} }},")
        lines.append("  },")
    lines += ["};", "", f"static const uint8_t {name}_LAST[16][256] = {{"]
    for p in range(16):
        row = ", ".join(f"0x{v:02x}" for v in tables.last[p])
        lines.append(f"  {{ {row} }},")
    lines += ["};", "", "#endif", ""]
    return "\n".join(lines)

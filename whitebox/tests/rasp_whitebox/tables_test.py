"""Compile and exercise generated AES tables against independent AES."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess

import pytest
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

from rasp_whitebox import aes
from rasp_whitebox import tables


@pytest.mark.parametrize(
    ("key_hex", "plaintext_hex", "ciphertext_hex", "seed_byte"),
    [
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            0,
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
            1,
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
            2,
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            3,
        ),
    ],
)
def testEncryptBlock_whenGeneratedAndCompiled_matchesIndependentAes(
    tmp_path: pathlib.Path,
    key_hex: str,
    plaintext_hex: str,
    ciphertext_hex: str,
    seed_byte: int,
) -> None:
    key = bytes.fromhex(key_hex)
    table_data = tables.generate(key, bytes([seed_byte]) * 32)
    (tmp_path / "aes.h").write_text(tables.emit_header(table_data))
    source = tmp_path / "harness.cpp"
    source.write_text(
        '#include "aes.h"\n'
        "#include <cstdio>\n"
        "int main() {\n"
        "  std::array<std::uint8_t, 16> block{};\n"
        "  while (std::fread(block.data(), 1, 16, stdin) == 16) {\n"
        "    wb::encrypt_block(block.data(), block.data());\n"
        "    if (std::fwrite(block.data(), 1, 16, stdout) != 16) return 1;\n"
        "  }\n"
        "  return std::ferror(stdin) == 0 ? 0 : 1;\n"
        "}\n"
    )
    binary = tmp_path / "aes-harness"
    subprocess.run(
        [
            "g++",
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
    )
    blocks = bytes.fromhex(plaintext_hex) + hashlib.shake_256(key).digest(16 * 64)
    encryptor = ciphers.Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    expected = encryptor.update(blocks) + encryptor.finalize()
    result = subprocess.run(
        [str(binary)], input=blocks, capture_output=True, check=True
    )
    assert result.stdout[:16] == bytes.fromhex(ciphertext_hex)
    assert result.stdout == expected
    compiled = binary.read_bytes()
    if key != bytes(16):
        assert key not in compiled
        for round_key in aes.expand_key(key):
            assert round_key not in table_data


def testGenerate_whenSameKeyAndSeed_isReproducible() -> None:
    first = tables.generate(bytes(range(16)), bytes(range(32)))
    second = tables.generate(bytes(range(16)), bytes(range(32)))
    assert first == second
    assert len(first) == 372736


def testGenerate_whenSeedChanges_changesTableEncoding() -> None:
    first = tables.generate(bytes(16), bytes(32))
    second = tables.generate(bytes(16), b"x" * 32)
    assert first != second


@pytest.mark.parametrize(
    ("key_length", "seed_length"), [(15, 32), (17, 32), (16, 31), (16, 33)]
)
def testGenerate_whenInvalidInputLength_rejectsInput(
    key_length: int, seed_length: int
) -> None:
    with pytest.raises(ValueError, match="bytes"):
        tables.generate(bytes(key_length), bytes(seed_length))


@pytest.mark.parametrize("length", [0, 372735, 372737])
def testEmitHeader_whenInvalidTableLength_rejectsInput(length: int) -> None:
    with pytest.raises(ValueError, match="table"):
        tables.emit_header(bytes(length))

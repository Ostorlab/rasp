"""Compile and execute the generated standalone binary."""

import pathlib
import subprocess

import pytest
from cryptography.hazmat.primitives.ciphers import aead

from rasp_whitebox import build
from rasp_whitebox import codec


@pytest.fixture(scope="module")
def executable(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    folder = tmp_path_factory.mktemp("native")
    target = folder / "whitebox"
    build.build_binary(key=bytes(range(16)), output=target, seed=bytes(32))
    return target


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4097])
def testBinary_whenEncrypting_matchesLibrary(
    executable: pathlib.Path, tmp_path: pathlib.Path, size: int
) -> None:
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    source = tmp_path / "plain"
    source.write_bytes(data)
    sealed = tmp_path / "sealed"
    subprocess.run([str(executable), "encrypt", str(source), str(sealed)], check=True)
    record = sealed.read_bytes()
    assert (
        aead.AESGCM(bytes(range(16))).decrypt(record[4:16], record[16:], record[:16])
        == data
    )
    recovered = tmp_path / "recovered"
    subprocess.run(
        [str(executable), "decrypt", str(sealed), str(recovered)], check=True
    )
    assert recovered.read_bytes() == data


@pytest.mark.parametrize("size", [0, 1, 16, 31, 1024])
def testBinary_whenGivenReferenceCiphertext_recoversPlaintext(
    executable: pathlib.Path, tmp_path: pathlib.Path, size: int
) -> None:
    source = tmp_path / "sealed"
    data = b"x" * size
    source.write_bytes(codec.encrypt(bytes(range(16)), data))
    output = tmp_path / "recovered"
    subprocess.run([str(executable), "decrypt", str(source), str(output)], check=True)
    assert output.read_bytes() == data


@pytest.mark.parametrize("offset", [0, 4, 16, -1])
def testBinary_whenAuthenticationFails_createsNoOutput(
    executable: pathlib.Path, tmp_path: pathlib.Path, offset: int
) -> None:
    record = bytearray(codec.encrypt(bytes(range(16)), b"secret"))
    record[offset] ^= 1
    source = tmp_path / "sealed"
    source.write_bytes(record)
    output = tmp_path / "recovered"
    result = subprocess.run(
        [str(executable), "decrypt", str(source), str(output)], capture_output=True
    )
    assert result.returncode != 0
    assert output.exists() is False


def testBinary_whenOutputExists_preservesFile(
    executable: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    source = tmp_path / "plain"
    source.write_bytes(b"hello")
    output = tmp_path / "existing"
    output.write_bytes(b"keep")
    result = subprocess.run(
        [str(executable), "encrypt", str(source), str(output)], capture_output=True
    )
    assert result.returncode != 0
    assert output.read_bytes() == b"keep"


def testBuild_whenOutputExists_preservesFile(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "existing"
    output.write_bytes(b"keep")
    with pytest.raises(build.Error, match="exists"):
        build.build_binary(key=bytes(16), output=output, seed=bytes(32))
    assert output.read_bytes() == b"keep"

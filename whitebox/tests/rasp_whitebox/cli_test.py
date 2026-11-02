"""Exercise the installed command-line interface as a user would."""

import pathlib
import subprocess
import sys


def testCli_whenRoundTrip_recoversBinaryInput(tmp_path: pathlib.Path) -> None:
    key = tmp_path / "key"
    plain = tmp_path / "plain"
    sealed = tmp_path / "sealed"
    recovered = tmp_path / "recovered"
    plain.write_bytes(b"text\x00\xff" * 17)
    subprocess.run(
        [sys.executable, "-m", "rasp_whitebox", "keygen", "--output", str(key)],
        check=True,
    )
    assert len(key.read_bytes()) == 16
    for operation, source, target in [
        ("encrypt", plain, sealed),
        ("decrypt", sealed, recovered),
    ]:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "rasp_whitebox",
                operation,
                "--key-file",
                str(key),
                "--input",
                str(source),
                "--output",
                str(target),
            ],
            check=True,
        )
    assert recovered.read_bytes() == plain.read_bytes()
    assert key.stat().st_mode & 0o077 == 0


def testCli_whenKeyOutputExists_preservesFile(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "keep"
    output.write_bytes(b"keep")
    result = subprocess.run(
        [sys.executable, "-m", "rasp_whitebox", "keygen", "--output", str(output)],
        capture_output=True,
    )
    assert result.returncode != 0
    assert b"exists" in result.stderr
    assert output.read_bytes() == b"keep"


def testCli_whenInvalidKey_createsNoOutput(tmp_path: pathlib.Path) -> None:
    key = tmp_path / "key"
    key.write_bytes(b"short")
    plain = tmp_path / "plain"
    plain.write_bytes(b"hello")
    output = tmp_path / "sealed"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "rasp_whitebox",
            "encrypt",
            "--key-file",
            str(key),
            "--input",
            str(plain),
            "--output",
            str(output),
        ],
        capture_output=True,
    )
    assert result.returncode != 0
    assert b"16 raw bytes" in result.stderr
    assert output.exists() is False

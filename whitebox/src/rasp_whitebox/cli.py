"""File-oriented commands for the standalone research implementation."""

import argparse
import os
import pathlib
import secrets
import sys

from rasp_whitebox import build
from rasp_whitebox import codec


def _read(path: pathlib.Path, maximum: int) -> bytes:
    """Read a bounded input without loading an arbitrarily large file."""
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise codec.Error(f"input exceeds size limit: {path}")
    return value


def _write(path: pathlib.Path, value: bytes) -> None:
    """Create a private new file; never overwrite an existing path."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    """Run a keyed reference operation or compile a key-specific binary."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create a new 16-byte key file")
    keygen.add_argument("--output", required=True, type=pathlib.Path)
    for name in ("encrypt", "decrypt", "build"):
        command = commands.add_parser(name)
        command.add_argument("--key-file", required=True, type=pathlib.Path)
        command.add_argument("--output", required=True, type=pathlib.Path)
        if name != "build":
            command.add_argument("--input", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            _write(args.output, secrets.token_bytes(16))
            return 0
        key = _read(args.key_file, 16)
        if len(key) != 16:
            raise codec.Error("key must contain exactly 16 raw bytes")
        if args.command == "build":
            build.build_binary(key=key, output=args.output)
            return 0
        if args.command == "encrypt":
            result = codec.encrypt(key, _read(args.input, codec.MAX_PLAINTEXT))
        else:
            result = codec.decrypt(
                key, _read(args.input, codec.MAX_PLAINTEXT + codec.OVERHEAD)
            )
        _write(args.output, result)
        return 0
    except (OSError, codec.Error, build.Error) as error:
        print(f"rasp-whitebox: {error}", file=sys.stderr)
        return 1

"""Independent DEX layout/digest checks and required SDK dexdump for generated real features."""

import argparse
import hashlib
import pathlib
import struct
import subprocess
import zlib


def validate(path: pathlib.Path, dexdump: pathlib.Path) -> None:
    data = path.read_bytes()
    if data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError(f"bad DEX magic: {path}")
    if struct.unpack_from("<I", data, 32)[0] != len(data):
        raise ValueError(f"bad DEX file size: {path}")
    if data[12:32] != hashlib.sha1(data[32:]).digest() or struct.unpack_from(
        "<I", data, 8
    )[0] != zlib.adler32(data[12:]):
        raise ValueError(f"bad independent DEX digest: {path}")
    position = struct.unpack_from("<I", data, 52)[0]
    count = struct.unpack_from("<I", data, position)[0]
    types: set[int] = set()
    previous = -1
    for kind, unused, size, offset in struct.iter_unpack(
        "<HHII", data[position + 4 : position + 4 + 12 * count]
    ):
        if (
            kind in types
            or unused != 0
            or size == 0
            or offset <= previous
            or offset >= len(data)
        ):
            raise ValueError(f"bad independently inspected map: {path}")
        types.add(kind)
        previous = offset
    subprocess.run([str(dexdump), "-c", str(path)], check=True, capture_output=True)
    subprocess.run([str(dexdump), "-d", str(path)], check=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("--dexdump", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.dexdump.is_file() is False:
        raise ValueError("required independent dexdump is unavailable")
    paths = sorted(arguments.directory.glob("*.dex"))
    versions = {path.read_bytes()[4:7] for path in paths}
    if versions != {b"035", b"037", b"038", b"039", b"040"}:
        raise ValueError(
            "genuine feature fixtures for all five declared versions are required"
        )
    for path in paths:
        validate(path, arguments.dexdump)
    print(
        f"independent layout/digest/dexdump checks passed for {len(paths)} DEX fixtures"
    )


if __name__ == "__main__":
    main()

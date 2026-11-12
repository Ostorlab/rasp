"""Native build/CI entry point using the packer's production catalogue validator."""

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))

from rasp_packer import capabilities


def main() -> None:
    """Emit or verify the sidecar adjacent to a pristine native library."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("emit", "verify"))
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("platform", choices=("android", "ios"))
    parser.add_argument("abi")
    parser.add_argument("minimum_os")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    sidecar = args.binary.with_name(args.binary.name + capabilities.SIDECAR_SUFFIX)
    expected = capabilities.emit(binary, args.platform, args.abi, args.minimum_os)
    if args.action == "emit":
        sidecar.write_bytes(expected)
    else:
        data = sidecar.read_bytes()
        capabilities.bind(binary, data, args.platform, args.abi)
        if data != expected:
            raise ValueError("non-deterministic capability sidecar")


if __name__ == "__main__":
    main()

"""Emit/verify support only for native targets that actually link the policy facade."""

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))
from rasp_packer import local_policy


def main() -> None:
    """Bind the descriptor to pristine linked bytes before packer config insertion."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("emit", "verify"))
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("platform", choices=("android", "ios"))
    parser.add_argument("abi")
    parser.add_argument("minimum_os")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    expected = local_policy.emit_support(
        binary, args.platform, args.abi, args.minimum_os
    )
    filename = args.binary.with_name(args.binary.name + local_policy.SUPPORT_SUFFIX)
    if args.action == "emit":
        filename.write_bytes(expected)
    else:
        actual = local_policy.read_support(args.binary)
        local_policy.bind(binary, actual, args.platform, args.abi, required=True)
        if actual != expected:
            raise ValueError("noncanonical local policy support descriptor")


if __name__ == "__main__":
    main()

"""Verify staged native bytes using the production packer consumer before/after config mutation.

Run with lief==1.0.0 installed. This does not load or execute the native binary.
"""

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))
from rasp_packer import capabilities
from rasp_packer import runtime_config
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.ios import runtime_binary


def main() -> None:
    """Exercise binding plus actual ELF/Mach-O config parsing on a staged release artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("platform", choices=("android", "ios"))
    parser.add_argument("abi")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    sidecar = capabilities.read_sidecar(args.binary)
    binding = capabilities.bind(binary, sidecar, args.platform, args.abi)
    if binding is None:
        raise ValueError("staged native release is missing its capability manifest")
    config = runtime_config.RuntimeConfig(
        build_id="release-consumer-test", checks=("identity",)
    )
    if args.platform == "android":
        if sidecar is None:
            raise AssertionError("binding requires sidecar")
        artifacts = resources.Artifacts(
            stub_dex=b"", libraries={args.abi: binary}, manifests={args.abi: sidecar}
        )
        assert resources.bindings(artifacts, [args.abi]) == (binding,)
        written = runtime_library.write_config(binary, config)
        assert runtime_library.read_config(written) == config.to_json()
    else:
        written = runtime_binary.write_config(binary, config)
        assert runtime_binary.read_config(written) == [config.to_json()]
    assert len(written) == len(binary)
    print(
        f"validated staged {args.platform}/{args.abi}: {binding.catalogue_id} {binding.artifact_sha256}"
    )


if __name__ == "__main__":
    main()

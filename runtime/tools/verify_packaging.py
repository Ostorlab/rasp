"""Verify staged native bytes using the production packer consumer before/after config mutation.

Run with lief==1.0.0 installed. This does not load or execute the native binary.
"""

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))
from rasp_packer import capabilities
from rasp_packer import local_policy
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
    policy_sidecar = local_policy.read_support(args.binary)
    policy_binding = local_policy.bind(
        binary, policy_sidecar, args.platform, args.abi, required=True
    )
    assert policy_binding is not None
    assert policy_sidecar is not None
    config = runtime_config.RuntimeConfig(
        build_id="release-consumer-test", checks=("identity",)
    )
    if args.platform == "android":
        if sidecar is None:
            raise AssertionError("binding requires sidecar")
        artifacts = resources.Artifacts(
            stub_dex=b"",
            libraries={args.abi: binary},
            manifests={args.abi: sidecar},
            policy_manifests={args.abi: policy_sidecar},
        )
        assert resources.bindings(artifacts, [args.abi]) == (binding,)
        assert resources.policy_bindings(artifacts, [args.abi], required=True) == (
            policy_binding,
        )
        written = runtime_library.write_config(binary, config)
        assert runtime_library.read_config(written) == config.to_json()
    else:
        written = runtime_binary.write_config(binary, config)
        assert runtime_binary.read_config(written) == [config.to_json()]
    assert len(written) == len(binary)
    policy_file = (
        pathlib.Path(__file__).resolve().parents[2]
        / "docs/fixtures"
        / f"local-policy-{args.platform}-v1.json"
    )
    policy = local_policy.parse(policy_file.read_bytes())
    explicit = runtime_config.RuntimeConfig(
        build_id="release-consumer-test",
        checks=("debugger", "identity"),
        local_policy=policy,
    )
    if args.platform == "android":
        runtime_library.verify_policy_exports(binary)
        explicit_bytes = runtime_library.write_config(binary, explicit)
        assert json.loads(runtime_library.read_config(explicit_bytes))[
            "local_policy"
        ] == json.loads(policy.canonical_json)
    else:
        runtime_binary.verify_policy_exports(binary)
        explicit_bytes = runtime_binary.write_config(binary, explicit)
        assert all(
            value == explicit.to_json()
            for value in runtime_binary.read_config(explicit_bytes)
        )
    print(
        f"validated staged {args.platform}/{args.abi}: {binding.catalogue_id} {binding.artifact_sha256}"
    )


if __name__ == "__main__":
    main()

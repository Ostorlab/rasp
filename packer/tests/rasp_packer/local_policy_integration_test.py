"""Public API/CLI against installed exact SDK/NDK policy artifacts; no gate mock or device claim."""

import dataclasses
import json
import os
import pathlib
import subprocess
import sys
import zipfile

import pytest

from rasp_packer import cli
from rasp_packer import errors
from rasp_packer import local_policy
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import resources
from rasp_packer.android import runtime_library

pytestmark = pytest.mark.skipif(
    os.environ.get("RASP_POLICY_HOST_APK") is None,
    reason="requires actual installed policy artifacts and SDK source host",
)


def _policy() -> local_policy.Policy:
    document = {
        "schema_version": 1,
        "engine_version": 1,
        "policy_id": "demo",
        "policy_version": 4294967295,
        "mode": "gate",
        "scope": "host_calls_only",
        "platform": "android",
        "catalogue_id": local_policy.selector_inventory()["catalogue_id"],
        "report_schema_version": 1,
        "report_reason_version": 1,
        "native_metadata_version": 1,
        "operations": [
            {
                "name": "append_demo_receipt",
                "max_evidence_age_ms": 75000,
                "max_cycle_duration_ms": 5000,
                "rules": [
                    {
                        "rule_id": "native.android.dbg.tracer_pid.proc_status",
                        "rule_version": 1,
                    }
                ],
            }
        ],
    }
    return local_policy.parse(json.dumps(document).encode())


@pytest.mark.parametrize("artifact_format", ["apk", "aab"])
@pytest.mark.parametrize("explicit", [False, True])
def testPolicy_whenActualInstalledArtifactsPacked_roundTripsPublicApiAndCli(
    tmp_path: pathlib.Path, artifact_format: str, explicit: bool
) -> None:
    source = pathlib.Path(
        os.environ[
            "RASP_POLICY_HOST_APK"
            if artifact_format == "apk"
            else "RASP_POLICY_HOST_AAB"
        ]
    )
    artifacts = resources.load()
    policy = _policy() if explicit is True else None
    output = tmp_path / ("protected." + artifact_format)
    result = packer.pack(
        app=source,
        platform=platforms.Platform.ANDROID,
        output=output,
        build_id="test",
        checks=["debugger"],
        local_policy=policy,
    )
    assert result.local_policy_bindings is not None
    assert result.policy_mode == ("gate" if explicit is True else "report_only")
    if policy is not None:
        assert result.policy_sha256 == policy.sha256
    config = runtime_config.RuntimeConfig(
        build_id="test", checks=result.effective_checks, local_policy=policy
    )
    prefix = "base/" if artifact_format == "aab" else ""
    with zipfile.ZipFile(output) as archive:
        for abi, pristine in artifacts.libraries.items():
            injected = archive.read(prefix + "lib/" + abi + "/librasp.so")
            assert injected == runtime_library.write_config(pristine, config)
            assert runtime_library.read_config(injected) == config.to_json()
    arguments = [
        "pack",
        str(source),
        "--platform",
        "android",
        "--build-id",
        "test",
        "--checks",
        "debugger",
        "--output",
        str(tmp_path / ("cli." + artifact_format)),
    ]
    if policy is not None:
        filename = tmp_path / "policy.json"
        filename.write_bytes(policy.canonical_json)
        arguments += ["--local-policy", str(filename)]
    assert cli.main(arguments) == cli.EXIT_OK
    visible = subprocess.run(
        [
            sys.executable,
            "-c",
            "from rasp_packer import local_policy; print(local_policy.selector_digest('android'))",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert visible.stdout.strip() == local_policy.selector_digest("android")


def testPolicy_whenActualArtifactSetHasMissingOrChangedSupport_rejectsBeforeOutput() -> (
    None
):
    artifacts = resources.load()
    abi = next(iter(artifacts.libraries))
    missing = dict(artifacts.policy_manifests)
    del missing[abi]
    with pytest.raises(errors.InvalidRuntimeError):
        resources.policy_bindings(
            dataclasses.replace(artifacts, policy_manifests=missing),
            artifacts.libraries,
            required=True,
        )
    libraries = dict(artifacts.libraries)
    libraries[abi] += b"changed"
    with pytest.raises(errors.InvalidRuntimeError):
        resources.policy_bindings(
            dataclasses.replace(artifacts, libraries=libraries),
            libraries,
            required=True,
        )

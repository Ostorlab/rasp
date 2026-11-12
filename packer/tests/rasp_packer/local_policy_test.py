"""Strict embedded policy, canonical identity and pristine support-binding tests."""

import copy
import json
import os
import pathlib
import subprocess

import lief
import pytest

from rasp_packer import capabilities
from rasp_packer import errors
from rasp_packer import local_policy
from rasp_packer import runtime_config
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest


def policy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "engine_version": 1,
        "policy_id": "demo",
        "policy_version": 1,
        "mode": "gate",
        "scope": "host_calls_only",
        "platform": "android",
        "catalogue_id": capabilities.catalogue_id(),
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


def testPolicy_whenValid_normalizesAndPins() -> None:
    policy = local_policy.parse(json.dumps(policy_document()).encode())
    assert policy.mode == "gate"
    assert policy.operations[0].rules[0].group == "debugger"
    assert local_policy.parse(policy.canonical_json) == policy
    assert len(policy.sha256) == 64
    assert (
        local_policy.validate_for(policy, "android", ("debugger", "identity"), "build")
        == policy
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mode", "kill"),
        ("schema_version", 2),
        ("engine_version", True),
        ("policy_version", 0),
        ("policy_version", 4294967296),
        ("catalogue_id", "0" * 64),
        ("platform", "other"),
        ("scope", "all_operations"),
        ("operations", []),
        ("policy_id", "bad\x00name"),
    ],
)
def testPolicy_whenInvalid_rejects(field: str, value: object) -> None:
    document = policy_document()
    document[field] = value
    with pytest.raises(errors.InvalidLocalPolicyError):
        local_policy.parse(json.dumps(document).encode())


@pytest.mark.parametrize(
    "data",
    [
        b"null",
        b"{}",
        b"[]",
        b"\xff",
        b"{",
        b'{"schema_version":1,"schema_version":1}',
        b" " * 2049,
        b"[" * 9 + b"0" + b"]" * 9,
    ],
)
def testPolicy_whenMalformedOrOversized_rejects(data: bytes) -> None:
    with pytest.raises(errors.InvalidLocalPolicyError):
        local_policy.parse(data)


@pytest.mark.parametrize(
    "rule",
    [
        "local.android.capture.screenshot.observer_state.activity_screen_capture",
        "native.android.id.package.package_manager",
        "native.ios.dbg.traced.sysctl",
    ],
)
def testPolicy_whenRuleIsUninterpretedOrForeign_rejects(rule: str) -> None:
    document = policy_document()
    document["operations"] = [
        {
            "name": "append_demo_receipt",
            "max_evidence_age_ms": 75000,
            "max_cycle_duration_ms": 5000,
            "rules": [{"rule_id": rule, "rule_version": 1}],
        }
    ]
    with pytest.raises(errors.InvalidLocalPolicyError):
        local_policy.parse(json.dumps(document).encode())


def testPolicy_whenGroupDisabled_refusesRatherThanEnabling() -> None:
    policy = local_policy.parse(json.dumps(policy_document()).encode())
    with pytest.raises(errors.InvalidLocalPolicyError, match="enabled"):
        local_policy.validate_for(policy, "android", ("identity",), "build")


def testPolicy_whenDuplicateOperationOrRule_rejects() -> None:
    document = policy_document()
    operations = document["operations"]
    assert isinstance(operations, list)
    operations.append(copy.deepcopy(operations[0]))
    with pytest.raises(errors.InvalidLocalPolicyError):
        local_policy.parse(json.dumps(document).encode())


def testPolicy_whenFloatOrExponentVersion_rejectsLexically() -> None:
    data = json.dumps(policy_document()).encode()
    for replacement in (b'"policy_version": 1.0', b'"policy_version": 1e0'):
        with pytest.raises(errors.InvalidLocalPolicyError):
            local_policy.parse(data.replace(b'"policy_version": 1', replacement))


def testSupport_whenLegacyOrCorrupted_refusesExplicitPolicy() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="policy"):
        local_policy.bind(b"runtime", None, "android", "arm64-v8a", required=True)
    descriptor = local_policy.emit_support(b"runtime", "android", "arm64-v8a", "31")
    assert (
        local_policy.bind(b"runtime", descriptor, "android", "arm64-v8a", required=True)
        is not None
    )
    with pytest.raises(errors.InvalidRuntimeError):
        local_policy.bind(b"changed", descriptor, "android", "arm64-v8a", required=True)
    assert (
        local_policy.bind(b"runtime", None, "android", "arm64-v8a", required=False)
        is None
    )


def testPolicyFile_whenOversized_readsBoundedAndRejects(tmp_path: pathlib.Path) -> None:
    filename = tmp_path / "policy.json"
    filename.write_bytes(b" " * 2049)
    with pytest.raises(errors.InvalidLocalPolicyError):
        local_policy.load(filename)


@pytest.mark.parametrize("build_id", ["test", 'bühl "7"'])
def testPolicy_whenPassedToActualNativeParser_hasIdenticalCanonicalHashes(
    tmp_path: pathlib.Path, build_id: str
) -> None:
    probe = os.environ.get("RASP_LOCAL_POLICY_PROBE")
    if probe is None:
        pytest.skip("actual native parser probe not supplied")
    policy = local_policy.parse(json.dumps(policy_document()).encode())
    config = runtime_config.RuntimeConfig(
        build_id=build_id, checks=("debugger",), local_policy=policy
    )
    filename = tmp_path / "config.json"
    filename.write_bytes(config.to_json())
    result = subprocess.run(
        [probe, str(filename), "android"], check=True, capture_output=True, timeout=10
    )
    output = json.loads(result.stdout)
    assert output["status"] == 0
    assert output["config_state"] == 2
    assert output["policy_sha256"] == policy.sha256
    assert output["effective_config_sha256"] == local_policy.effective_hash(
        build_id, config.checks, policy
    )


@pytest.mark.parametrize(
    "corruption", ["valid", "unterminated", "nonzero_padding", "malformed"]
)
def testEmbeddedConfig_whenRealNativeSectionIsPatched_preservesExplicitErrors(
    tmp_path: pathlib.Path, corruption: str
) -> None:
    probe = os.environ.get("RASP_LOCAL_POLICY_PROBE")
    if probe is None:
        pytest.skip("actual native embedded-config probe not supplied")
    binary = pathlib.Path(probe).read_bytes()
    policy = local_policy.parse(json.dumps(policy_document()).encode())
    config = runtime_config.RuntimeConfig(
        build_id="test", checks=("debugger",), local_policy=policy
    )
    written = bytearray(runtime_library.write_config(binary, config))
    parsed = lief.ELF.parse(bytes(written))
    assert parsed is not None
    section = parsed.get_section(runtime_library.ELF_SECTION)
    assert section is not None
    assert section.size == 4096
    if corruption == "unterminated":
        written[section.offset : section.offset + section.size] = b"x" * section.size
    elif corruption == "nonzero_padding":
        written[section.offset + section.size - 1] = 120
    elif corruption == "malformed":
        written[section.offset] = 91
    executable = tmp_path / "native-policy-probe"
    executable.write_bytes(written)
    executable.chmod(0o700)
    result = subprocess.run(
        [str(executable), "--embedded", "android"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    output = json.loads(result.stdout)
    if corruption == "valid":
        assert output["status"] == 0
        assert output["config_state"] == 2
        assert output["policy_sha256"] == policy.sha256
    else:
        assert output["status"] != 0
        assert output["config_state"] == 3


def testSupport_whenConfigOnlyElfHasMatchingDescriptors_stillRejectsMissingFacade() -> (
    None
):
    binary = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
    artifacts = resources.Artifacts(
        stub_dex=b"unused",
        libraries={"arm64-v8a": binary},
        manifests={
            "arm64-v8a": capabilities.emit(binary, "android", "arm64-v8a", "31")
        },
        policy_manifests={
            "arm64-v8a": local_policy.emit_support(binary, "android", "arm64-v8a", "31")
        },
    )
    with pytest.raises(errors.InvalidRuntimeError, match="exports"):
        resources.policy_bindings(artifacts, ("arm64-v8a",), required=True)

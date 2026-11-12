"""Release catalogue and exact artifact binding contracts."""

import copy
import hashlib
import json
import pathlib
import re

import pytest

from rasp_packer import capabilities
from rasp_packer import checks
from rasp_packer import errors
from rasp_packer import platforms


def testCatalogue_whenCurrent_hasRequiredIdentityAndTypedSources() -> None:
    catalogue = capabilities.catalogue()
    for platform in ("android", "ios"):
        groups = catalogue["platforms"][platform]["groups"]
        assert [group["name"] for group in groups if group["required"]] == ["identity"]
        assert all(len(group["observations"]) > 0 for group in groups)
    assert catalogue["plugins"] == "unmodelled"


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "structure",
        "duplicate",
        "duplicate_output",
        "kind",
        "cardinality",
        "condition",
    ],
)
def testParseCatalogue_whenInvalid_rejects(mutation: str) -> None:
    data = copy.deepcopy(capabilities.catalogue())
    groups = data["platforms"]["ios"]["groups"]
    if mutation == "version":
        data["schema_version"] = 999
    elif mutation == "structure":
        data["unexpected"] = True
    elif mutation == "duplicate":
        groups.append(groups[0])
    elif mutation == "duplicate_output":
        groups[0]["observations"].append(groups[0]["observations"][0])
    elif mutation == "condition":
        groups[0]["observations"][0]["supported_on"] = "unknown_platform_api"
    elif mutation == "kind":
        groups[0]["observations"][0]["value_kind"] = "float"
    else:
        groups[0]["observations"][0]["cardinality"] = "unlimited"
    with pytest.raises(errors.InvalidRuntimeError):
        capabilities.parse_catalogue(json.dumps(data).encode())


@pytest.mark.parametrize(
    "data",
    [b'{"schema_version":1,"schema_version":1}', b"{", b"[]", b"\xff", b" " * 131073],
)
def testParseCatalogue_whenMalformedOrOversized_rejects(data: bytes) -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        capabilities.parse_catalogue(data)


def testBind_whenExactArtifact_isDeterministic() -> None:
    binary = b"exact native build"
    sidecar = capabilities.emit(binary, "android", "arm64-v8a", "31")
    assert sidecar == capabilities.emit(binary, "android", "arm64-v8a", "31")
    binding = capabilities.bind(binary, sidecar, "android", "arm64-v8a")
    assert binding is not None
    assert binding.catalogue_id == capabilities.catalogue_id()
    assert binding.abi == "arm64-v8a"
    assert capabilities.bind(binary, None, "android", "arm64-v8a") is None


@pytest.mark.parametrize(
    "mutation",
    [
        "binary",
        "digest",
        "catalogue",
        "identity",
        "version",
        "platform",
        "abi",
        "floor",
        "unknown",
        "duplicate",
    ],
)
def testBind_whenUnmatched_rejects(mutation: str) -> None:
    binary = b"one build"
    data = json.loads(capabilities.emit(binary, "android", "arm64-v8a", "31"))
    if mutation == "binary":
        binary = b"another build with same runtime version"
    elif mutation == "digest":
        data["artifact_sha256"] = "0" * 64
    elif mutation == "catalogue":
        data["catalogue"]["revision"] += 1
    elif mutation == "identity":
        data["catalogue_id"] = "0" * 64
    elif mutation == "version":
        data["schema_version"] = 2
    elif mutation == "platform":
        data["platform"] = "ios"
    elif mutation == "abi":
        data["abi"] = "x86"
    elif mutation == "floor":
        data["minimum_os"] = "1"
    elif mutation == "unknown":
        data["new_field"] = True
    sidecar = json.dumps(data).encode()
    if mutation == "duplicate":
        sidecar = sidecar.replace(
            b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'
        )
    with pytest.raises(errors.InvalidRuntimeError):
        capabilities.bind(binary, sidecar, "android", "arm64-v8a")


@pytest.mark.parametrize(("field", "value"), [("abis", [{}]), ("groups", None)])
def testParseCatalogue_whenWrongNestedType_rejects(field: str, value: object) -> None:
    data = capabilities.catalogue()
    data["platforms"]["ios"][field] = value
    with pytest.raises(errors.InvalidRuntimeError):
        capabilities.parse_catalogue(json.dumps(data).encode())


def testBind_whenForeignCatalogueHasConsistentIdentity_rejects() -> None:
    data = json.loads(capabilities.emit(b"native", "ios", "arm64", "12.0"))
    data["catalogue"]["revision"] = 2
    data["catalogue_id"] = hashlib.sha256(
        capabilities.canonical(data["catalogue"])
    ).hexdigest()
    with pytest.raises(
        errors.InvalidRuntimeError, match="unknown capability catalogue"
    ):
        capabilities.bind(b"native", capabilities.canonical(data), "ios", "arm64")


def testCatalogue_whenSourceInventoryCompared_coversEveryBuiltinSignal() -> None:
    runtime = pathlib.Path(__file__).resolve().parents[3] / "runtime"
    for platform, document in capabilities.catalogue()["platforms"].items():
        for group in document["groups"]:
            source = (
                runtime / platform / "src" / "checks" / f"{group['name']}.cpp"
            ).read_text()
            signals = set(
                re.findall(
                    r'constexpr std::string_view k\w*Signal = "([^"]+)";', source
                )
            )
            assert signals == {row["signal"] for row in group["observations"]}


def testContractFixtures_whenSelectionResolved_matchEffectiveGroups() -> None:
    fixture = (
        pathlib.Path(__file__).resolve().parents[3]
        / "docs"
        / "fixtures"
        / "check-capabilities-v1.json"
    )
    for case in json.loads(fixture.read_bytes())["cases"]:
        result = checks.resolve_checks(
            platforms.Platform(case["platform"]), case["requested"]
        )
        assert list(result.checks) == case["effective_checks"]
        assert list(result.skipped) == case["skipped"]


def testReadSidecar_whenOversized_rejectsBeforeParsing(tmp_path: pathlib.Path) -> None:
    binary = tmp_path / "librasp.so"
    binary.with_name(binary.name + capabilities.SIDECAR_SUFFIX).write_bytes(
        b" " * (capabilities.MAX_MANIFEST_BYTES + 1)
    )
    with pytest.raises(errors.InvalidRuntimeError, match="size limit"):
        capabilities.read_sidecar(binary)


def testCatalogue_whenIosUserCasAlwaysUnsupported_declaresNoValueKind() -> None:
    groups = capabilities.catalogue()["platforms"]["ios"]["groups"]
    row = next(
        row
        for group in groups
        for row in group["observations"]
        if row["signal"] == "mitm.user_cas"
    )
    assert row["value_kind"] == "none"
    assert row["value_cardinality"] == "none"
    assert row["statuses"] == ["unsupported"]

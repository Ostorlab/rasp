"""Release catalogue and exact artifact binding contracts."""

import copy
import hashlib
import json
import pathlib
import re
import runpy
import sys

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
    data["catalogue"]["revision"] += 1
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
            service_group = platform == "android" and group["name"] in (
                "accessibility",
                "input_method",
                "notification_access",
            )
            filename = "service_exposure" if service_group is True else group["name"]
            source = (
                runtime / platform / "src" / "checks" / f"{filename}.cpp"
            ).read_text()
            if service_group is True:
                source = source.split(
                    f"std::vector<Observation> {group['name']}() {{", 1
                )[1].split("\n}\n", 1)[0]
            pattern = (
                r'constexpr std::string_view k(?:Signal|Enabled|Current) = "([^"]+)";'
                if service_group is True
                else r'constexpr std::string_view k\w*Signal = "([^"]+)";'
            )
            signals = set(re.findall(pattern, source))
            assert signals == {row["signal"] for row in group["observations"]}


def testContractFixtures_whenSelectionResolved_matchEffectiveGroups() -> None:
    fixture = (
        pathlib.Path(__file__).resolve().parents[3]
        / "docs"
        / "fixtures"
        / "check-capabilities-v1.json"
    )
    document = json.loads(fixture.read_bytes())
    assert document["catalogue"]["catalogue_id"] == capabilities.catalogue_id()
    assert document["catalogue"]["revision"] == capabilities.catalogue()["revision"]
    assert document["catalogue"]["observation_counts"] == {
        name: sum(len(group["observations"]) for group in platform["groups"])
        for name, platform in capabilities.catalogue()["platforms"].items()
    }
    for case in document["cases"]:
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


def testBind_whenPreviousCatalogueRevisionHasMatchingBytes_rejects() -> None:
    data = json.loads(capabilities.emit(b"native", "ios", "arm64", "12.0"))
    data["catalogue"]["revision"] -= 1
    data["catalogue_id"] = hashlib.sha256(
        capabilities.canonical(data["catalogue"])
    ).hexdigest()
    with pytest.raises(
        errors.InvalidRuntimeError, match="unknown capability catalogue"
    ):
        capabilities.bind(b"native", capabilities.canonical(data), "ios", "arm64")


@pytest.mark.parametrize(
    ("platform", "group", "signal", "source", "kind"),
    [
        ("android", "debugger", "dbg.tracer_pid", "proc_status_syscall", "integer"),
        ("android", "hooks", "hook.maps_hits", "proc_maps_syscall", "string_list"),
        ("android", "hooks", "hook.threads", "proc_task", "string_list"),
        ("android", "hooks", "hook.inline", "prologue", "string_list"),
        ("android", "root", "root.fs_paths", "access", "string_list"),
        ("android", "root", "root.fs_paths", "stat", "string_list"),
        ("android", "root", "root.fs_paths", "faccessat_syscall", "string_list"),
        ("android", "root", "root.mounts", "proc_mounts_syscall", "string_list"),
        ("android", "root", "root.rw_mounts", "proc_mounts_syscall", "string_list"),
        ("ios", "debugger", "dbg.traced", "sysctl_syscall", "boolean"),
        ("ios", "debugger", "dbg.parent", "sysctl_syscall", "integer"),
    ],
)
def testCatalogue_whenReviewedSourceRegistered_preservesTypedErrors(
    platform: str, group: str, signal: str, source: str, kind: str
) -> None:
    groups = capabilities.catalogue()["platforms"][platform]["groups"]
    observations = next(
        entry["observations"] for entry in groups if entry["name"] == group
    )
    row = next(
        entry
        for entry in observations
        if entry["signal"] == signal and entry["source"] == source
    )
    assert row["value_kind"] == kind
    assert set(row["statuses"]) == {"ok", "error", "unsupported"}
    assert row["cardinality"] == "one"


@pytest.mark.parametrize(
    "statuses", [["timeout"], ["ok", "unsupported", "error", "timeout"]]
)
def testParseCatalogue_whenTimeoutDeclared_roundTripsWithoutChangingProductionCatalogue(
    statuses: list[str],
) -> None:
    current_id = capabilities.catalogue_id()
    document = capabilities.catalogue()
    row = document["platforms"]["android"]["groups"][0]["observations"][0]
    row["statuses"] = statuses
    encoded = capabilities.canonical(document)
    parsed = capabilities.parse_catalogue(encoded)
    assert (
        parsed["platforms"]["android"]["groups"][0]["observations"][0]["statuses"]
        == statuses
    )
    assert capabilities.canonical(parsed) == encoded
    assert capabilities.catalogue_id() == current_id
    assert (
        current_id == "eaac77e3bdbf7f21af2abfb79a7868ccf516e5c3f758d25c90127550e3e7db7c"
    )
    assert all(
        "timeout" not in output["statuses"]
        for platform in capabilities.catalogue()["platforms"].values()
        for group in platform["groups"]
        for output in group["observations"]
    )


def testCapabilityHeader_whenTimeoutParsed_generatesActualNativeStatusBit(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = capabilities.catalogue()
    document["platforms"]["android"]["groups"][0]["observations"][0]["statuses"] = [
        "timeout"
    ]
    parsed = capabilities.parse_catalogue(capabilities.canonical(document))
    monkeypatch.setattr(capabilities, "catalogue", lambda: parsed)
    header = tmp_path / "expectations.h"
    monkeypatch.setattr(sys, "argv", ["capability_header.py", str(header), "android"])
    tool = (
        pathlib.Path(__file__).resolve().parents[3]
        / "runtime"
        / "tools"
        / "capability_header.py"
    )
    runpy.run_path(str(tool), run_name="__main__")
    row = next(
        line
        for line in header.read_text().splitlines()
        if 'signal = "root.fs_paths", .source = "access"' in line
    )
    assert ".statuses = 8}" in row
    assert ".statuses = 7}" in header.read_text()


@pytest.mark.parametrize("statuses", [["timeout", "timeout"], ["timedout"], [True]])
def testParseCatalogue_whenTimeoutVocabularyMalformed_rejects(
    statuses: list[object],
) -> None:
    document = capabilities.catalogue()
    document["platforms"]["android"]["groups"][0]["observations"][0]["statuses"] = (
        statuses
    )
    with pytest.raises(errors.InvalidRuntimeError):
        capabilities.parse_catalogue(capabilities.canonical(document))


def testCatalogue_whenInlineSourceRegistered_preservesBoundedUnknownContract() -> None:
    platforms_document = capabilities.catalogue()["platforms"]
    android_hooks = next(
        group["observations"]
        for group in platforms_document["android"]["groups"]
        if group["name"] == "hooks"
    )
    identities = {(row["signal"], row["source"]): row for row in android_hooks}
    assert ("hook.inline", "prologue") in identities
    row = identities[("hook.inline", "prologue")]
    assert row["value_kind"] == "string_list"
    assert row["cardinality"] == "one"
    assert row["value_cardinality"] == "variable"
    assert set(row["statuses"]) == {"ok", "error", "unsupported"}
    assert row["supported_on"] == "android"
    assert "at most 32" in row["behavior"]
    assert "empty only after all 32 comparisons succeed" in row["behavior"]
    assert "no partial list" in row["behavior"]
    assert all(
        entry["signal"] != "hook.inline"
        for group in platforms_document["ios"]["groups"]
        for entry in group["observations"]
    )


def testCatalogue_whenAndroidServiceMetadataRegistered_preservesVersionedContext() -> (
    None
):
    document = capabilities.catalogue()
    android = document["platforms"]["android"]
    groups = {group["name"]: group for group in android["groups"]}
    assert document["schema_version"] == 1
    assert document["revision"] == 4
    assert sum(len(group["observations"]) for group in android["groups"]) == 32
    assert (
        sum(
            len(group["observations"])
            for group in document["platforms"]["ios"]["groups"]
        )
        == 26
    )
    contracts = (
        (
            "accessibility",
            "a11y.enabled_services",
            "accessibility_manager",
            "string_list",
        ),
        (
            "input_method",
            "ime.enabled_components",
            "input_method_manager",
            "string_list",
        ),
        ("input_method", "ime.current_component", "input_method_manager", "string"),
        (
            "notification_access",
            "notification.enabled_listeners",
            "settings_secure",
            "string_list",
        ),
    )
    for group, signal, source, kind in contracts:
        assert groups[group]["required"] is False
        row = next(
            row for row in groups[group]["observations"] if row["signal"] == signal
        )
        assert row["source"] == source
        assert row["value_kind"] == kind
        assert row["cardinality"] == "one"
        assert row["value_cardinality"] == (
            "scalar" if kind == "string" else "variable"
        )
        assert set(row["statuses"]) == {"ok", "error", "unsupported"}
        assert row["supported_on"] == "android"
        assert "Context" in row["behavior"]
        assert all(
            entry["name"] != group for entry in document["platforms"]["ios"]["groups"]
        )
    current = groups["input_method"]["observations"][1]
    assert "API31-33" in current["behavior"]
    assert "API34+" in current["behavior"]
    assert "null" in current["behavior"]
    assert "selected" in current["behavior"]


def testServiceContractFixtures_whenComparedWithCatalogue_preserveTypesAndUnknownValues() -> (
    None
):
    fixture = (
        pathlib.Path(__file__).resolve().parents[3]
        / "docs/fixtures/android-service-observations-v1.json"
    )
    document = json.loads(fixture.read_bytes())
    identities = {
        (row["signal"], row["source"]): row
        for group in capabilities.catalogue()["platforms"]["android"]["groups"]
        for row in group["observations"]
    }
    for case in document["cases"]:
        for observation in case["observations"]:
            row = identities[(observation["signal"], observation["source"])]
            assert observation["status"] in row["statuses"]
            if observation["status"] == "ok":
                value = observation["value"]
                if row["value_kind"] == "string_list":
                    assert isinstance(value, list)
                    assert value == sorted(set(value))
                    assert all(isinstance(component, str) for component in value)
                else:
                    assert row["value_kind"] == "string"
                    assert isinstance(value, str)
            else:
                assert "value" not in observation


def testParseCatalogue_whenAndroidTruthIsUnavailable_acceptsUnsupportedWithNoValue() -> (
    None
):
    document = capabilities.catalogue()
    row = document["platforms"]["android"]["groups"][0]["observations"][0]
    row.update(
        value_kind="none",
        value_cardinality="none",
        statuses=["unsupported"],
        supported_on="never",
    )
    assert capabilities.parse_catalogue(capabilities.canonical(document)) == document

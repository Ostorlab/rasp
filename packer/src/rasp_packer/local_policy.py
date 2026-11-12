"""Bounded opt-in host-operation policy; configuration/support hashes are not attestation."""

from __future__ import annotations

import collections.abc
import dataclasses
import hashlib
import importlib.resources
import json
import pathlib
import re
from typing import Any

from rasp_packer import capabilities
from rasp_packer import errors

MAX_POLICY_BYTES = 2048
SUPPORT_SUFFIX = ".local-policy.json"
DEFAULT_POLICY = b'{"engine_version":1,"mode":"report_only","schema_version":1}'
_VERSIONS = {
    "schema_version",
    "engine_version",
    "report_schema_version",
    "report_reason_version",
    "native_metadata_version",
}
_POLICY_KEYS = _VERSIONS | {
    "policy_id",
    "policy_version",
    "mode",
    "scope",
    "platform",
    "catalogue_id",
    "operations",
}


def canonical(value: object) -> bytes:
    """Canonical UTF-8 JSON for this contract, preserving Unicode build identifiers."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise errors.InvalidLocalPolicyError("duplicate policy member")
        result[key] = value
    return result


def _number(token: str) -> int:
    if re.fullmatch(r"[0-9]{1,10}", token) is None:
        raise errors.InvalidLocalPolicyError(
            "policy integers must be unsigned decimal uint32"
        )
    return int(token)


def _float(token: str) -> None:
    raise errors.InvalidLocalPolicyError(
        "fractional/exponent policy numbers are unsupported"
    )


def _decode(data: bytes, limit: int) -> Any:
    if len(data) > limit:
        raise errors.InvalidLocalPolicyError("policy input exceeds byte limit")
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted is True:
            if escaped is True:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                raise errors.InvalidLocalPolicyError(
                    "policy nesting exceeds eight containers"
                )
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_number,
            parse_float=_float,
            parse_constant=_float,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise errors.InvalidLocalPolicyError("invalid policy JSON") from error


def _keys(value: Any, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise errors.InvalidLocalPolicyError("unknown or missing policy members")


def _name(value: Any, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1," + str(maximum) + "}", value) is None
    ):
        raise errors.InvalidLocalPolicyError("invalid policy identifier")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise errors.InvalidLocalPolicyError("policy integer outside supported range")
    return value


def selector_inventory() -> dict[str, Any]:
    """Read the single reviewed rule/version/group inventory from installed resources."""
    data = (
        importlib.resources.files("rasp_packer")
        .joinpath("local_policy_selectors_v1.json")
        .read_bytes()
    )
    document: dict[str, Any] = json.loads(data)
    if (
        document["schema_version"] != 1
        or document["catalogue_id"] != capabilities.catalogue_id()
    ):
        raise errors.InvalidLocalPolicyError("unsupported policy selector catalogue")
    return document


def selector_digest(platform: str) -> str:
    """Bind the exact platform selector inventory independently of catalogue revisions."""
    document = selector_inventory()
    return hashlib.sha256(
        canonical(
            {
                "schema_version": 1,
                "platform": platform,
                "rules": [
                    entry
                    for entry in document["rules"]
                    if entry["platform"] == platform
                ],
            }
        )
    ).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Rule:
    """One exact supported absence/indicator predicate; no raw observation expression."""

    rule_id: str
    rule_version: int
    group: str


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Operation:
    """Host-adapted operation with conservative historical evidence bounds."""

    name: str
    max_evidence_age_ms: int
    max_cycle_duration_ms: int
    rules: tuple[Rule, ...]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """Owned immutable validated policy, including its canonical source bytes."""

    policy_id: str
    policy_version: int
    platform: str
    mode: str
    operations: tuple[Operation, ...]
    canonical_json: bytes

    @property
    def sha256(self) -> str:
        """Configuration equality only, never authenticity or authorization."""
        return hashlib.sha256(self.canonical_json).hexdigest()


def parse(data: bytes) -> Policy:
    """Validate bounded schema 1 and every mandatory semantic pin without fallback."""
    document = _decode(data, MAX_POLICY_BYTES)
    _keys(document, _POLICY_KEYS)
    for field in _VERSIONS:
        _integer(document[field], 1, 1)
    platform = document["platform"]
    if (
        platform not in ("android", "ios")
        or document["catalogue_id"] != capabilities.catalogue_id()
    ):
        raise errors.InvalidLocalPolicyError("unsupported policy platform/catalogue")
    if document["scope"] != "host_calls_only" or document["mode"] not in (
        "gate",
        "report_only",
    ):
        raise errors.InvalidLocalPolicyError("unsupported policy action/scope")
    policy_id = _name(document["policy_id"], 64)
    policy_version = _integer(document["policy_version"], 1, 4294967295)
    operations = document["operations"]
    if (
        not isinstance(operations, list)
        or len(operations) > 4
        or (document["mode"] == "gate" and len(operations) == 0)
    ):
        raise errors.InvalidLocalPolicyError("invalid policy operation count")
    inventory = {
        entry["rule_id"]: entry
        for entry in selector_inventory()["rules"]
        if entry["platform"] == platform
    }
    owned: list[Operation] = []
    names: set[str] = set()
    total_rules = 0
    for operation in operations:
        _keys(
            operation, {"name", "max_evidence_age_ms", "max_cycle_duration_ms", "rules"}
        )
        name = _name(operation["name"], 32)
        if name in names:
            raise errors.InvalidLocalPolicyError("duplicate policy operation")
        names.add(name)
        age = _integer(operation["max_evidence_age_ms"], 1000, 120000)
        duration = _integer(operation["max_cycle_duration_ms"], 1, min(age, 10000))
        selected = operation["rules"]
        if not isinstance(selected, list) or not 1 <= len(selected) <= 8:
            raise errors.InvalidLocalPolicyError("invalid policy rule count")
        rules: list[Rule] = []
        rule_names: set[str] = set()
        for selection in selected:
            _keys(selection, {"rule_id", "rule_version"})
            rule_id = _name(selection["rule_id"], 128)
            version = _integer(selection["rule_version"], 1, 4294967295)
            entry = inventory.get(rule_id)
            if (
                entry is None
                or entry["rule_version"] != version
                or rule_id in rule_names
            ):
                raise errors.InvalidLocalPolicyError(
                    "unsupported/duplicate policy rule or version"
                )
            rule_names.add(rule_id)
            rules.append(
                Rule(rule_id=rule_id, rule_version=version, group=entry["group"])
            )
        rules.sort(key=lambda rule: rule.rule_id)
        total_rules += len(rules)
        operation["rules"] = [
            {"rule_id": rule.rule_id, "rule_version": rule.rule_version}
            for rule in rules
        ]
        owned.append(
            Operation(
                name=name,
                max_evidence_age_ms=age,
                max_cycle_duration_ms=duration,
                rules=tuple(rules),
            )
        )
    if total_rules > 8:
        raise errors.InvalidLocalPolicyError("policy exceeds eight total selectors")
    document["operations"] = sorted(operations, key=lambda operation: operation["name"])
    encoded = canonical(document)
    if len(encoded) > MAX_POLICY_BYTES:
        raise errors.InvalidLocalPolicyError("canonical policy exceeds byte limit")
    return Policy(
        policy_id=policy_id,
        policy_version=policy_version,
        platform=platform,
        mode=document["mode"],
        operations=tuple(sorted(owned, key=lambda operation: operation.name)),
        canonical_json=encoded,
    )


def load(filename: pathlib.Path) -> Policy:
    """Read at most limit+1 bytes, preserving existing CLI error-before-output behavior."""
    try:
        with filename.open("rb") as stream:
            return parse(stream.read(MAX_POLICY_BYTES + 1))
    except OSError as error:
        raise errors.InvalidLocalPolicyError("cannot read local policy file") from error


def validate_for(
    policy: Policy, platform: str, checks: collections.abc.Sequence[str], build_id: str
) -> Policy:
    """Revalidate public typed arguments and actual enabled prerequisites; never auto-enable."""
    parsed = parse(policy.canonical_json)
    if parsed != policy or parsed.platform != platform:
        raise errors.InvalidLocalPolicyError(
            "policy does not match target platform/content"
        )
    if (
        len(build_id.encode("utf-8")) > 256
        or len(build_id) == 0
        or re.search(r"[\x00-\x1f\x7f]", build_id) is not None
    ):
        raise errors.InvalidLocalPolicyError("policy build identifier outside bounds")
    if len(checks) > 64 or len(set(checks)) != len(checks):
        raise errors.InvalidLocalPolicyError("policy checks must be unique and bounded")
    supported_groups = {
        entry["name"]
        for entry in capabilities.catalogue()["platforms"][platform]["groups"]
    }
    for group in checks:
        _name(group, 96)
        if group not in supported_groups:
            raise errors.InvalidLocalPolicyError(
                "policy config contains an unsupported check group"
            )
    for operation in parsed.operations:
        for rule in operation.rules:
            if rule.group not in checks:
                raise errors.InvalidLocalPolicyError(
                    "policy rule group must be enabled in effective checks"
                )
    return parsed


def effective_hash(
    build_id: str, checks: collections.abc.Sequence[str], policy: Policy | None
) -> str:
    """Hash effective selection/config without install identity or an authenticity claim."""
    return hashlib.sha256(
        canonical(
            {
                "build_id": build_id,
                "checks": sorted(checks),
                "local_policy": json.loads(
                    DEFAULT_POLICY if policy is None else policy.canonical_json
                ),
            }
        )
    ).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Binding:
    """Verified build-support metadata for exact pristine native bytes, not execution."""

    platform: str
    abi: str
    artifact_sha256: str
    selector_table_sha256: str


def emit_support(binary: bytes, platform: str, abi: str, minimum_os: str) -> bytes:
    """Emit only from targets which actually build/link the policy facade."""
    expected = capabilities.catalogue()["platforms"].get(platform)
    if (
        expected is None
        or abi not in expected["abis"]
        or minimum_os != expected["minimum_os"]
    ):
        raise errors.InvalidRuntimeError("unsupported policy-support target")
    return canonical(
        {
            "schema_version": 1,
            "platform": platform,
            "abi": abi,
            "minimum_os": minimum_os,
            "artifact_sha256": hashlib.sha256(binary).hexdigest(),
            "catalogue_id": capabilities.catalogue_id(),
            "policy_schema_version": 1,
            "engine_version": 1,
            "facade_abi_version": 1,
            "gate_reason_version": 1,
            "report_schema_version": 1,
            "report_reason_version": 1,
            "native_metadata_version": 1,
            "selector_table_sha256": selector_digest(platform),
        }
    )


def bind(
    binary: bytes, sidecar: bytes | None, platform: str, abi: str, *, required: bool
) -> Binding | None:
    """Refuse legacy/foreign/mixed runtimes for explicit policy; never silently ignore it."""
    if sidecar is None:
        if required is True:
            raise errors.InvalidRuntimeError(
                "runtime has no local policy support descriptor"
            )
        return None
    try:
        document = _decode(sidecar, 4096)
        expected = json.loads(
            emit_support(
                binary, platform, abi, "31" if platform == "android" else "12.0"
            )
        )
        _keys(document, set(expected))
        for field, value in expected.items():
            if type(document[field]) is not type(value) or document[field] != value:
                raise errors.InvalidRuntimeError(
                    "runtime local policy support binding mismatch"
                )
    except errors.InvalidLocalPolicyError as error:
        raise errors.InvalidRuntimeError(
            "invalid runtime local policy support descriptor"
        ) from error
    return Binding(
        platform=platform,
        abi=abi,
        artifact_sha256=expected["artifact_sha256"],
        selector_table_sha256=expected["selector_table_sha256"],
    )


def read_support(binary_path: pathlib.Path) -> bytes | None:
    """Read a bounded adjacent descriptor before any config mutation."""
    filename = binary_path.with_name(binary_path.name + SUPPORT_SUFFIX)
    try:
        with filename.open("rb") as stream:
            data = stream.read(4097)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise errors.InvalidRuntimeError(
            "cannot read local policy support descriptor"
        ) from error
    if len(data) > 4096:
        raise errors.InvalidRuntimeError(
            "local policy support descriptor exceeds limit"
        )
    return data

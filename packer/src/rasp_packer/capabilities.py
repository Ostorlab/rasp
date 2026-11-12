"""Versioned built-in capabilities bound to exact pristine native artifacts.

A binding describes possible outputs, never execution evidence or device attestation.
This module uses only the standard library so the native build can use the same validator.
"""

import dataclasses
import hashlib
import importlib.resources
import json
import pathlib
import re
from typing import Any

from rasp_packer import errors

# Positions match the native Status enum; additions do not change catalogue entries.
STATUS_NAMES = ("ok", "unsupported", "error", "timeout")

MAX_MANIFEST_BYTES = 131072
SIDECAR_SUFFIX = ".capabilities.json"


def canonical(data: object) -> bytes:
    """Deterministic UTF-8 encoding used for identities and sidecars."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise errors.InvalidRuntimeError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def _load(data: bytes) -> Any:
    if len(data) > MAX_MANIFEST_BYTES:
        raise errors.InvalidRuntimeError("capability manifest exceeds size limit")
    try:
        return json.loads(data, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise errors.InvalidRuntimeError("invalid capability JSON") from error


def _keys(data: Any, keys: set[str]) -> None:
    if not isinstance(data, dict) or set(data) != keys:
        raise errors.InvalidRuntimeError("unknown capability manifest structure")


def _text(value: Any) -> None:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", value) is None
    ):
        raise errors.InvalidRuntimeError("invalid capability name")


def parse_catalogue(data: bytes) -> dict[str, Any]:
    """Validate bounded schema v1, rejecting unknown fields, kinds and duplicate identities."""
    document: dict[str, Any] = _load(data)
    _keys(document, {"schema_version", "revision", "plugins", "platforms"})
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise errors.InvalidRuntimeError("unsupported capability catalogue version")
    if (
        type(document["revision"]) is not int
        or not 1 <= document["revision"] <= 2147483647
    ):
        raise errors.InvalidRuntimeError("invalid capability revision")
    if document["plugins"] != "unmodelled":
        raise errors.InvalidRuntimeError("plugin signals must be explicitly unmodelled")
    _keys(document["platforms"], {"android", "ios"})
    for name, platform in document["platforms"].items():
        _keys(platform, {"abis", "minimum_os", "groups"})
        expected_abis = (
            {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
            if name == "android"
            else {"arm64"}
        )
        if (
            not isinstance(platform["abis"], list)
            or len(platform["abis"]) != len(expected_abis)
            or any(not isinstance(abi, str) for abi in platform["abis"])
            or set(platform["abis"]) != expected_abis
        ):
            raise errors.InvalidRuntimeError("unsupported capability architectures")
        if platform["minimum_os"] != ("31" if name == "android" else "12.0"):
            raise errors.InvalidRuntimeError("unsupported capability OS floor")
        groups = platform["groups"]
        if not isinstance(groups, list) or not 1 <= len(groups) <= 64:
            raise errors.InvalidRuntimeError("invalid capability groups")
        names: set[str] = set()
        identities: set[tuple[str, str]] = set()
        for group in groups:
            _keys(group, {"name", "required", "observations"})
            _text(group["name"])
            if group["name"] in names or type(group["required"]) is not bool:
                raise errors.InvalidRuntimeError(
                    "duplicate or invalid capability group"
                )
            names.add(group["name"])
            observations = group["observations"]
            if not isinstance(observations, list) or not 1 <= len(observations) <= 256:
                raise errors.InvalidRuntimeError("invalid capability observations")
            for observation in observations:
                _keys(
                    observation,
                    {
                        "signal",
                        "source",
                        "value_kind",
                        "cardinality",
                        "value_cardinality",
                        "statuses",
                        "supported_on",
                        "behavior",
                    },
                )
                _text(observation["signal"])
                _text(observation["source"])
                identity = (observation["signal"], observation["source"])
                if identity in identities:
                    raise errors.InvalidRuntimeError(
                        "duplicate capability signal/source"
                    )
                identities.add(identity)
                if (
                    observation["value_kind"]
                    not in ("none", "boolean", "integer", "string", "string_list")
                    or observation["cardinality"] != "one"
                ):
                    raise errors.InvalidRuntimeError(
                        "unknown value kind or observation cardinality"
                    )
                if observation["value_cardinality"] != (
                    {"none": "none", "string_list": "variable"}.get(
                        observation["value_kind"], "scalar"
                    )
                ):
                    raise errors.InvalidRuntimeError("invalid value cardinality")
                statuses = observation["statuses"]
                if (
                    not isinstance(statuses, list)
                    or len(statuses) == 0
                    or any(status not in STATUS_NAMES for status in statuses)
                    or len(set(statuses)) != len(statuses)
                ):
                    raise errors.InvalidRuntimeError(
                        "unknown or duplicate capability status"
                    )
                if observation["supported_on"] not in (
                    ("android", "never")
                    if name == "android"
                    else ("ios_device", "apple", "never")
                ):
                    raise errors.InvalidRuntimeError(
                        "unknown capability support condition"
                    )
                if (observation["value_kind"] == "none") != (
                    observation["supported_on"] == "never"
                ) or (
                    observation["supported_on"] == "never"
                    and statuses != ["unsupported"]
                ):
                    raise errors.InvalidRuntimeError(
                        "unsupported-only capability must declare no value"
                    )
                if (
                    not isinstance(observation["behavior"], str)
                    or not 1 <= len(observation["behavior"]) <= 2048
                ):
                    raise errors.InvalidRuntimeError("invalid capability behavior")
        if [group["name"] for group in groups if group["required"]] != ["identity"]:
            raise errors.InvalidRuntimeError("identity must be the required group")
    return document


def catalogue() -> dict[str, Any]:
    """Read the single source of truth through installed package resources."""
    return parse_catalogue(
        importlib.resources.files("rasp_packer")
        .joinpath("checks_manifest.json")
        .read_bytes()
    )


def catalogue_id() -> str:
    """SHA-256 of the canonical validated catalogue, independent of JSON whitespace."""
    return hashlib.sha256(canonical(catalogue())).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Binding:
    """A validated pristine artifact identity; config mutation happens after validation."""

    catalogue_id: str
    artifact_sha256: str
    platform: str
    abi: str
    minimum_os: str


def emit(binary: bytes, platform: str, abi: str, minimum_os: str) -> bytes:
    """Native build producer: emit a deterministic sidecar for the actual linked artifact."""
    document = catalogue()
    if (
        platform not in document["platforms"]
        or abi not in document["platforms"][platform]["abis"]
        or minimum_os != document["platforms"][platform]["minimum_os"]
    ):
        raise errors.InvalidRuntimeError("unsupported native build capability target")
    return canonical(
        {
            "schema_version": 1,
            "catalogue": document,
            "catalogue_id": catalogue_id(),
            "artifact_sha256": hashlib.sha256(binary).hexdigest(),
            "platform": platform,
            "abi": abi,
            "minimum_os": minimum_os,
        }
    )


def bind(
    binary: bytes, sidecar: bytes | None, platform: str, abi: str
) -> Binding | None:
    """Consumer: missing legacy manifest means unknown; malformed/unmatched manifests fail closed."""
    if sidecar is None:
        return None
    document = _load(sidecar)
    _keys(
        document,
        {
            "schema_version",
            "catalogue",
            "catalogue_id",
            "artifact_sha256",
            "platform",
            "abi",
            "minimum_os",
        },
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise errors.InvalidRuntimeError("unsupported artifact capability version")
    parsed = parse_catalogue(canonical(document["catalogue"]))
    manifest_id = hashlib.sha256(canonical(parsed)).hexdigest()
    if document["catalogue_id"] != manifest_id or manifest_id != catalogue_id():
        raise errors.InvalidRuntimeError("unknown capability catalogue identity")
    if (
        document["platform"] != platform
        or document["abi"] != abi
        or platform not in parsed["platforms"]
        or abi not in parsed["platforms"][platform]["abis"]
    ):
        raise errors.InvalidRuntimeError("capability platform/ABI mismatch")
    if document["minimum_os"] != parsed["platforms"][platform]["minimum_os"]:
        raise errors.InvalidRuntimeError("capability OS floor mismatch")
    digest = hashlib.sha256(binary).hexdigest()
    if document["artifact_sha256"] != digest:
        raise errors.InvalidRuntimeError("runtime artifact capability digest mismatch")
    return Binding(
        catalogue_id=manifest_id,
        artifact_sha256=digest,
        platform=platform,
        abi=abi,
        minimum_os=document["minimum_os"],
    )


def read_sidecar(binary_path: pathlib.Path) -> bytes | None:
    """Read a bounded adjacent sidecar; absent legacy metadata stays unknown."""
    path = binary_path.with_name(binary_path.name + SIDECAR_SUFFIX)
    if path.exists() is False:
        return None
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise errors.InvalidRuntimeError(
            "cannot read runtime capability manifest"
        ) from error
    if len(data) > MAX_MANIFEST_BYTES:
        raise errors.InvalidRuntimeError("capability manifest exceeds size limit")
    return data

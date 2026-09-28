"""Select reviewed sink-disable rules from exact versioned SCA components."""

from __future__ import annotations

import dataclasses
import re
import typing

SINKS = frozenset({"sql", "file", "process", "network", "deserialization"})
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclasses.dataclass(frozen=True)
class Selection:
    denied_sinks: frozenset[str]
    vulnerability_ids: tuple[str, ...]


def select(sbom: dict[str, typing.Any], rules: list[dict[str, str]]) -> Selection:
    components = sbom.get("components")
    if (
        not isinstance(components, list)
        or len(components) > 100000
        or len(rules) > 10000
    ):
        raise ValueError("invalid or excessive SCA components/rules")
    installed: set[str] = set()
    for component in components:
        if not isinstance(component, dict) or not isinstance(
            component.get("purl"), str
        ):
            raise TypeError("each component needs a PURL")
        installed.add(component["purl"])
    sinks: set[str] = set()
    vulnerabilities: set[str] = set()
    for rule in rules:
        purl = rule.get("purl", "")
        vulnerability = rule.get("vulnerabilityId", "")
        sink = rule.get("sink", "")
        if (
            not purl.startswith("pkg:")
            or "@" not in purl
            or len(purl.rsplit("@", 1)[1].split("?", 1)[0]) == 0
        ):
            raise ValueError("patch PURL must specify an exact version")
        if sink not in SINKS or _CVE.fullmatch(vulnerability) is None:
            raise ValueError("patch requires a supported sink and CVE identifier")
        if purl in installed:
            sinks.add(sink)
            vulnerabilities.add(vulnerability)
    return Selection(frozenset(sinks), tuple(sorted(vulnerabilities)))

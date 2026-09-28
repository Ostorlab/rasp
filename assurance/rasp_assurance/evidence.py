"""Export redacted observed signals with reviewed OWASP control references.

Presence of a signal is evidence of detection, not proof of complete coverage or
MASVS compliance. Absence of a signal never turns into a passing assessment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import typing

from rasp_assurance import crashmaps

# References reviewed against mas.owasp.org on 2026-09-28. Old 0045..0051
# tests are deprecated; retain current tests/knowledge articles explicitly.
CONTROLS: dict[str, tuple[str, str, str]] = {
    "root": ("MASVS-RESILIENCE-1", "MASWE-0051", "MASTG-KNOW-0027"),
    "jailbreak": ("MASVS-RESILIENCE-1", "MASWE-0051", "MASTG-KNOW-0084"),
    "emulator": ("MASVS-RESILIENCE-4", "MASWE-0053", "MASTG-TEST-0351"),
    "debugger": ("MASVS-RESILIENCE-4", "MASWE-0064", "MASTG-TEST-0353"),
    "hooking": ("MASVS-RESILIENCE-4", "MASWE-0065", "MASTG-KNOW-0030"),
    "tamper": ("MASVS-RESILIENCE-2", "MASWE-0058", "MASTG-KNOW-0032"),
    "netMitm": ("MASVS-NETWORK-2", "MASWE-0028", "MASTG-KNOW-0015"),
    "screenCapture": ("MASVS-PLATFORM-3", "MASWE-0038", ""),
    "screenRecording": ("MASVS-PLATFORM-3", "MASWE-0038", ""),
    "overlay": ("MASVS-PLATFORM-3", "MASWE-0039", "MASTG-KNOW-0022"),
    "accessibilityAbuse": ("MASVS-PLATFORM-3", "MASWE-0040", ""),
}


def export(
    report: dict[str, typing.Any], artifact_sha256: str, platform: str
) -> dict[str, typing.Any]:
    if not isinstance(report, dict):
        raise TypeError("report must be an object")
    if (
        platform not in {"android", "ios"}
        or re.fullmatch(r"[0-9a-fA-F]{64}", artifact_sha256) is None
    ):
        raise ValueError("platform and SHA-256 required")
    signals = report.get("signals")
    if not isinstance(signals, list) or len(signals) > 4096:
        raise ValueError("bounded signal list required")
    observed: list[dict[str, typing.Any]] = []
    for signal in signals:
        if (
            not isinstance(signal, dict)
            or not isinstance(signal.get("threat"), str)
            or not isinstance(signal.get("detector"), str)
        ):
            raise TypeError("invalid signal")
        threat, detector = signal["threat"], signal["detector"]
        if len(threat) > 100 or len(detector) > 200:
            raise ValueError("signal identifiers exceed bounds")
        references = CONTROLS.get(threat)
        # Android test IDs are not evidence that the corresponding iOS control ran.
        masvs, maswe, mastg = references if references is not None else ("", "", "")
        if platform == "ios" and threat != "jailbreak":
            mastg = ""
        observed.append(
            {
                "threat": threat,
                "detector": detector,
                "observation": "signal_reported",
                "masvs": masvs or None,
                "maswe": maswe or None,
                "mastg": mastg or None,
            }
        )
    return {
        "schema": "rasp-evidence-1",
        "platform": platform,
        "artifactSha256": artifact_sha256,
        "referenceDate": "2026-09-28",
        "assessment": "not_assessed",
        "sourceAuthenticity": "not_verified_by_exporter",
        "signals": observed,
        "referenceIndex": "https://mas.owasp.org/MASTG/tests/",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--platform", choices=("android", "ios"), required=True)
    args = parser.parse_args()
    try:
        report = json.loads(crashmaps.read_bounded(args.report, 1024 * 1024))
        digest = hashlib.sha256()
        with args.artifact.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        print(json.dumps(export(report, digest.hexdigest(), args.platform), indent=2))
    except (ValueError, OSError, TypeError):
        print(json.dumps({"error": "invalid_evidence_input"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

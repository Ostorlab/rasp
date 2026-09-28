"""Server-side risk scoring and token policy for the trust service.

The device reports; the server decides. This module turns the sealed report's signals, the install's
attestation summary and the platform (Play Integrity) verdict into one authoritative risk level, sets the
token's lifetime from that risk, and says whether a token should be refused outright.

Risk is deliberately coarse (the resource server maps it to allow / step-up / deny per endpoint):

- critical: the app or its runtime is compromised (tamper, hooking, a debugger), or hardware attestation
  hard-failed. A payment must not proceed.
- high: malware is watching or driving the screen (accessibility abuse, overlay, recording, mirroring).
- medium: a risky but not conclusively compromised environment (root, emulator, a call in progress, a
  remote-access app, a screenshot, a degraded/absent platform attestation, a detector that could not run).
- low: some low-confidence signal is present.
- none: clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CRITICAL_THREATS = {"tamper", "hooking", "debugger"}
HIGH_THREATS = {"accessibilityAbuse", "overlay", "screenRecording", "screenMirroring"}
MEDIUM_THREATS = {"root", "emulator", "activeCall", "remoteAccessApp", "screenCapture", "netMitm", "detectorFailure"}

RISK_ORDER = ["none", "low", "medium", "high", "critical"]

# Token lifetime (seconds) by risk. A riskier context gets a shorter token, so a changed device state is
# re-evaluated sooner. The design allows 60-300 s.
TOKEN_TTL_BY_RISK = {"none": 300, "low": 300, "medium": 120, "high": 60, "critical": 60}


def _max_risk(*levels: str) -> str:
    return max(levels, key=RISK_ORDER.index) if levels else "none"


@dataclass
class TokenPolicy:
    """Tunable policy for the trust service."""

    require_hardware: bool = True
    require_user_auth: bool = True
    # Risk levels for which the trust service refuses to issue a token at all. Empty = always issue a token
    # carrying the risk, and let the resource server deny per endpoint.
    deny_token_on: frozenset[str] = frozenset()
    # Lowest risk allowed when the platform attestation (Play Integrity / App Attest) is unavailable: the
    # device cannot earn a clean pass on the RASP report alone, so the risk floor is raised to this. Other
    # signals may still push it higher. This is the design's degraded mode ("capped at medium").
    degraded_attestation_floor: str = "medium"
    # The validated App Attest lifecycle proves app/key origin, not OS integrity.
    # Keep its policy separate from Android device-integrity verdicts.
    app_attest_risk_floor: str = "medium"


@dataclass
class RiskAssessment:
    risk: str
    reasons: list[str] = field(default_factory=list)
    threat_summary: list[str] = field(default_factory=list)


def assess_risk(
    *,
    report_threats: set[str],
    attestation_security_level: str,
    device_locked: bool | None,
    verified_boot_state: str | None,
    platform_verdict: str | None,
    platform_available: bool,
    policy: TokenPolicy,
) -> RiskAssessment:
    """Combines the sealed report, the hardware attestation summary and the platform verdict into a risk."""
    reasons: list[str] = []
    risk = "none"

    critical = sorted(report_threats & CRITICAL_THREATS)
    high = sorted(report_threats & HIGH_THREATS)
    medium = sorted(report_threats & MEDIUM_THREATS)
    other = sorted(report_threats - CRITICAL_THREATS - HIGH_THREATS - MEDIUM_THREATS)
    if critical:
        risk = _max_risk(risk, "critical")
        reasons += [f"threat:{t}" for t in critical]
    if high:
        risk = _max_risk(risk, "high")
        reasons += [f"threat:{t}" for t in high]
    if medium:
        risk = _max_risk(risk, "medium")
        reasons += [f"threat:{t}" for t in medium]
    if other:
        risk = _max_risk(risk, "low")
        reasons += [f"threat:{t}" for t in other]

    # Hardware attestation state. A software key or an unlocked/unverified device is a strong signal on its
    # own; on a payment the resource server will treat critical as deny.
    if attestation_security_level == "software":
        risk = _max_risk(risk, "high")
        reasons.append("attestation:software_key")
    if device_locked is False or (verified_boot_state not in (None, "verified")):
        risk = _max_risk(risk, "high")
        reasons.append(f"attestation:boot_{verified_boot_state}_locked_{device_locked}")

    # Platform attestation (Play Integrity / App Attest).
    if not platform_available:
        risk = _max_risk(risk, policy.degraded_attestation_floor)
        reasons.append("degraded:no_platform_attestation")
    elif platform_verdict == "APP_ATTEST":
        risk = _max_risk(risk, policy.app_attest_risk_floor)
        reasons.append("platform:APP_ATTEST")
    elif platform_verdict is not None and platform_verdict not in ("STRONG", "DEVICE"):
        risk = _max_risk(risk, "high")
        reasons.append(f"platform:{platform_verdict}")

    return RiskAssessment(risk=risk, reasons=reasons, threat_summary=sorted(report_threats))


def token_ttl(risk: str) -> int:
    return TOKEN_TTL_BY_RISK.get(risk, 60)

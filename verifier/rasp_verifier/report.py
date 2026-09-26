"""Verification of the sealed RASP report produced by the native core.

The native core serializes its signals into a canonical JSON string and MACs the exact bytes with a
per-build key (HMAC-SHA256). The trust service looks up that build key in the build registry, recomputes
the MAC over the exact bytes it received (never re-serializing, so device and server agree byte for byte),
and then reads the signals. A forged report, a report from an unregistered build, or a report MAC'd with a
different key is refused. The report is bound to the challenge nonce and carries a device timestamp, so a
captured report cannot be replayed into a later token request.

The native serialization is `flutter_rasp/android/src/main/cpp/report.c` (`rasp_seal_report`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

REPORT_VERSION = "rasp-report-1"
MAX_REPORT_AGE_SECONDS = 60


class ReportError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class ReportSignal:
    threat: str
    detector: str
    confidence: int
    evidence: str


@dataclass
class SealedReport:
    build_id: str
    nonce: str
    timestamp_ms: int
    signals: list[ReportSignal] = field(default_factory=list)

    @property
    def threats(self) -> set[str]:
        return {s.threat for s in self.signals}


def verify_sealed_report(
    envelope: dict,
    *,
    build_key: bytes,
    expected_nonce: str,
    now: float | None = None,
    max_age_seconds: float = MAX_REPORT_AGE_SECONDS,
) -> SealedReport:
    """Verifies the MAC over the exact report bytes, then the version, nonce and freshness.

    `build_key` comes from the build registry, keyed by the `buildId` inside the report. `expected_nonce`
    is the challenge the trust service issued for this token request.
    """
    report_text = envelope.get("report")
    mac_hex = envelope.get("mac")
    if not isinstance(report_text, str) or not isinstance(mac_hex, str):
        raise ReportError("bad_envelope", "report and mac are required strings")

    expected_mac = hmac.new(build_key, report_text.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac_hex.lower()):
        raise ReportError("bad_mac", "report MAC does not match the build key")

    try:
        report = json.loads(report_text)
    except ValueError as e:
        raise ReportError("bad_report", str(e)) from e
    if report.get("v") != REPORT_VERSION:
        raise ReportError("bad_report", f"unsupported version {report.get('v')}")
    if report.get("nonce") != expected_nonce:
        raise ReportError("nonce_mismatch")

    try:
        timestamp_ms = int(report["ts"])
        build_id = str(report["buildId"])
        raw_signals = report["signals"]
    except (KeyError, ValueError, TypeError) as e:
        raise ReportError("bad_report", str(e)) from e

    now = time.time() if now is None else now
    if abs(now - timestamp_ms / 1000) > max_age_seconds:
        raise ReportError("stale", f"report ts is {timestamp_ms}")

    signals = []
    for item in raw_signals:
        try:
            signals.append(
                ReportSignal(
                    threat=str(item["threat"]),
                    detector=str(item["detector"]),
                    confidence=int(item["confidence"]),
                    evidence=str(item.get("evidence", "")),
                )
            )
        except (KeyError, ValueError, TypeError) as e:
            raise ReportError("bad_report", str(e)) from e
    return SealedReport(build_id=build_id, nonce=expected_nonce, timestamp_ms=timestamp_ms, signals=signals)

"""Verification of transactions signed by the bound device key (format `rasp-tx-1`), and the risk decision."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FORMAT_VERSION = "rasp-tx-1"
MAX_CLOCK_SKEW_SECONDS = 300

# Threats that make a payment unsafe whatever the amount: the device or the app is compromised, or malware is
# watching or driving the screen.
DENY_THREATS = {
    "tamper", "hooking", "debugger", "accessibilityAbuse", "overlay", "screenRecording", "screenMirroring",
}
# Threats that call for extra confirmation (out-of-band OTP, a cooling-off delay, a call-back).
STEP_UP_THREATS = {"root", "emulator", "activeCall", "remoteAccessApp", "screenCapture"}


class TransactionError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class SignedTransaction:
    nonce: str
    timestamp_ms: int
    app: str
    risk: str
    threats: list[str]
    fields: dict[str, str]


@dataclass
class Decision:
    action: str  # "allow" | "step_up" | "deny"
    reasons: list[str] = field(default_factory=list)


def _unescape(value: str) -> str:
    return value.replace("%0A", "\n").replace("%0D", "\r").replace("%25", "%")


def parse_signed_data(signed_data: str) -> SignedTransaction:
    lines = signed_data.split("\n")
    header = {}
    fields = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep:
            raise TransactionError("bad_format", f"line without '=': {line[:40]}")
        if key.startswith("f."):
            fields[key[2:]] = _unescape(value)
        elif key in header:
            raise TransactionError("bad_format", f"duplicate {key}")
        else:
            header[key] = value
    if header.get("v") != FORMAT_VERSION:
        raise TransactionError("bad_format", f"unsupported version {header.get('v')}")
    try:
        return SignedTransaction(
            nonce=_unescape(header["nonce"]),
            timestamp_ms=int(header["ts"]),
            app=_unescape(header["app"]),
            risk=header["risk"],
            threats=[t for t in header["threats"].split(",") if t],
            fields=fields,
        )
    except (KeyError, ValueError) as e:
        raise TransactionError("bad_format", str(e)) from e


def verify_transaction(
    signed_data: str,
    signature_b64: str,
    public_key_der: bytes,
    *,
    expected_nonce: str,
    package_name: str,
    now: float | None = None,
) -> SignedTransaction:
    """Checks the signature with the device's bound key, then the nonce, the app and the timestamp."""
    public_key = serialization.load_der_public_key(public_key_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TransactionError("bad_key", "bound key is not an EC key")
    try:
        public_key.verify(base64.b64decode(signature_b64), signed_data.encode(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as e:
        raise TransactionError("bad_signature") from e

    tx = parse_signed_data(signed_data)
    if tx.nonce != expected_nonce:
        raise TransactionError("nonce_mismatch")
    if tx.app != package_name:
        raise TransactionError("wrong_app", tx.app)
    now = time.time() if now is None else now
    if abs(now - tx.timestamp_ms / 1000) > MAX_CLOCK_SKEW_SECONDS:
        raise TransactionError("stale", f"device time is {tx.timestamp_ms}")
    return tx


def decide(tx: SignedTransaction) -> Decision:
    """Risk decision for a verified transaction, based on the RASP verdict it carries."""
    deny = sorted(set(tx.threats) & DENY_THREATS)
    if deny:
        return Decision("deny", [f"threat:{t}" for t in deny])
    if tx.risk == "high":
        return Decision("deny", ["risk:high"])
    step_up = sorted(set(tx.threats) & STEP_UP_THREATS)
    if step_up or tx.risk == "medium":
        return Decision("step_up", [f"threat:{t}" for t in step_up] or ["risk:medium"])
    return Decision("allow")

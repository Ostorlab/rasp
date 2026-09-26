"""Reference bank backend for the Demo Bank sample (in-memory, for demos and tests; not production code).

    python -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank --cert-sha256 <digest> \
        [--allow-software-attestation] [--port 8787]

Endpoints (JSON):
    POST /v1/challenge  {"purpose": "bind"|"transfer", "deviceId"?}  -> {"nonce"}
    POST /v1/devices    {"challenge", "publicKey", "certificateChain"} -> {"deviceId", "securityLevel", ...}
    POST /v1/transfers  {"deviceId", "signedData", "signature"}       -> {"decision", "reasons"}  (403 on deny)
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .attestation import AttestationError, verify_key_attestation
from .transaction import TransactionError, decide, verify_transaction

CHALLENGE_TTL_SECONDS = 120


@dataclass
class BankState:
    package_name: str
    signing_cert_sha256: list[str]
    require_hardware: bool = True
    trusted_roots: list | None = None  # None = Google's published roots
    challenges: dict[str, tuple[str, str | None, float]] = field(default_factory=dict)  # nonce -> (purpose, device, t)
    devices: dict[str, bytes] = field(default_factory=dict)  # deviceId -> public key DER
    lock: threading.Lock = field(default_factory=threading.Lock)

    def issue(self, purpose: str, device_id: str | None) -> str:
        nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        with self.lock:
            self.challenges[nonce] = (purpose, device_id, time.time())
        return nonce

    def consume(self, nonce: str, purpose: str, device_id: str | None) -> bool:
        """Single use: a nonce is removed as soon as it is presented, valid or not."""
        with self.lock:
            entry = self.challenges.pop(nonce, None)
        if entry is None:
            return False
        issued_purpose, issued_device, issued_at = entry
        return (
            issued_purpose == purpose
            and issued_device == device_id
            and time.time() - issued_at <= CHALLENGE_TTL_SECONDS
        )

    def challenge(self, body: dict) -> tuple[int, dict]:
        purpose = body.get("purpose")
        if purpose not in ("bind", "transfer"):
            return HTTPStatus.BAD_REQUEST, {"error": "purpose must be bind or transfer"}
        device_id = body.get("deviceId")
        if purpose == "transfer" and device_id not in self.devices:
            return HTTPStatus.NOT_FOUND, {"error": "unknown device"}
        return HTTPStatus.OK, {"nonce": self.issue(purpose, device_id), "expiresIn": CHALLENGE_TTL_SECONDS}

    def bind(self, body: dict) -> tuple[int, dict]:
        challenge = body.get("challenge", "")
        if not self.consume(challenge, "bind", None):
            return HTTPStatus.BAD_REQUEST, {"error": "unknown, used or expired challenge"}
        try:
            result = verify_key_attestation(
                body.get("certificateChain", []),
                base64.b64decode(challenge),
                self.package_name,
                self.signing_cert_sha256,
                require_hardware=self.require_hardware,
                trusted_roots=self.trusted_roots,
            )
        except AttestationError as e:
            return HTTPStatus.FORBIDDEN, {"error": "attestation_failed", "reason": e.reason, "detail": str(e)}
        # The key the app will sign with must be the attested one.
        if base64.b64decode(body.get("publicKey", "")) != result.public_key_der:
            return HTTPStatus.FORBIDDEN, {"error": "attestation_failed", "reason": "key_mismatch"}
        device_id = secrets.token_hex(16)
        with self.lock:
            self.devices[device_id] = result.public_key_der
        return HTTPStatus.CREATED, {
            "deviceId": device_id,
            "securityLevel": result.security_level,
            "trustedRoot": result.trusted_root,
            "verifiedBootState": result.verified_boot_state,
            "warnings": result.warnings,
        }

    def transfer(self, body: dict) -> tuple[int, dict]:
        device_id = body.get("deviceId")
        public_key = self.devices.get(device_id)
        if public_key is None:
            return HTTPStatus.NOT_FOUND, {"error": "unknown device"}
        signed_data = body.get("signedData", "")
        try:
            nonce = next(line[6:] for line in signed_data.split("\n") if line.startswith("nonce="))
        except StopIteration:
            return HTTPStatus.BAD_REQUEST, {"error": "no nonce"}
        if not self.consume(nonce, "transfer", device_id):
            return HTTPStatus.BAD_REQUEST, {"error": "unknown, used or expired nonce"}
        try:
            tx = verify_transaction(
                signed_data, body.get("signature", ""), public_key,
                expected_nonce=nonce, package_name=self.package_name,
            )
        except TransactionError as e:
            return HTTPStatus.FORBIDDEN, {"error": "verification_failed", "reason": e.reason}
        decision = decide(tx)
        status = HTTPStatus.FORBIDDEN if decision.action == "deny" else HTTPStatus.OK
        return status, {"decision": decision.action, "reasons": decision.reasons, "fields": tx.fields}


def make_handler(state: BankState):
    routes = {"/v1/challenge": state.challenge, "/v1/devices": state.bind, "/v1/transfers": state.transfer}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (http.server naming)
            route = routes.get(self.path)
            if route is None:
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(min(length, 256 * 1024)) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
            except ValueError:
                return self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
            status, payload = route(body)
            self._send(status, payload)

        def _send(self, status: int, payload: dict):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            print(f"[bank] {self.address_string()} {fmt % args}", flush=True)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--package", required=True)
    parser.add_argument("--cert-sha256", action="append", required=True, help="app signing certificate digest")
    parser.add_argument(
        "--allow-software-attestation", action="store_true",
        help="accept software-backed keys and non-Google roots (emulators). Never in production.",
    )
    args = parser.parse_args()
    state = BankState(args.package, args.cert_sha256, require_hardware=not args.allow_software_attestation)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(f"[bank] listening on {args.host}:{args.port} (hardware attestation required: {state.require_hardware})")
    server.serve_forever()


if __name__ == "__main__":
    main()

"""Reference bank backend for the Demo Bank sample (in-memory, for demos and tests; not production code).

    python -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank --cert-sha256 <digest> [--port 8787]
        [--allow-software-attestation] [--allow-no-user-auth] [--no-revocation-check]

Endpoints (JSON):
    POST /v1/sessions   {"customerId", "pin"}                                  -> {"sessionToken"}
    POST /v1/challenge  {"sessionToken", "purpose": "bind"|"transfer", "deviceId"?} -> {"nonce"}
    POST /v1/devices    {"sessionToken", "challenge", "publicKey", "certificateChain"} -> {"deviceId", ...}
    POST /v1/transfers  {"sessionToken", "deviceId", "signedData", "signature"}  -> {"decision", "reasons"} (403 on deny)

Binding needs a logged-in customer and replaces the customer's previous device.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .attestation import AttestationError, verify_key_attestation
from .revocation import RevocationList
from .transaction import TransactionError, decide, verify_transaction

CHALLENGE_TTL_SECONDS = 120
SESSION_TTL_SECONDS = 15 * 60
MAX_PIN_FAILURES = 5


@dataclass
class Device:
    customer_id: str
    public_key_der: bytes


@dataclass
class BankState:
    package_name: str
    signing_cert_sha256: list[str]
    customers: dict[str, str] = field(default_factory=lambda: {"demo": "1234"})  # customerId -> PIN (demo only)
    require_hardware: bool = True
    require_user_auth: bool = True
    revocations: RevocationList | None = None  # None = revocation check disabled (tests, offline demos)
    trusted_roots: list | None = None  # None = Google's published roots
    sessions: dict[str, tuple[str, float]] = field(default_factory=dict)  # token -> (customer, expiry)
    pin_failures: dict[str, int] = field(default_factory=dict)
    challenges: dict[str, tuple[str, str, str | None, float]] = field(default_factory=dict)
    devices: dict[str, Device] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    # --- sessions -------------------------------------------------------------------------------------------------

    def login(self, body: dict) -> tuple[int, dict]:
        customer_id, pin = str(body.get("customerId", "")), str(body.get("pin", ""))
        with self.lock:
            if self.pin_failures.get(customer_id, 0) >= MAX_PIN_FAILURES:
                return HTTPStatus.TOO_MANY_REQUESTS, {"error": "locked, contact the bank"}
            expected = self.customers.get(customer_id)
            if expected is None or not hmac.compare_digest(expected, pin):
                self.pin_failures[customer_id] = self.pin_failures.get(customer_id, 0) + 1
                return HTTPStatus.UNAUTHORIZED, {"error": "wrong customer or PIN"}
            self.pin_failures.pop(customer_id, None)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = (customer_id, time.time() + SESSION_TTL_SECONDS)
        return HTTPStatus.CREATED, {"sessionToken": token, "expiresIn": SESSION_TTL_SECONDS}

    def _customer(self, body: dict) -> str | None:
        with self.lock:
            entry = self.sessions.get(str(body.get("sessionToken", "")))
        if entry is None or entry[1] < time.time():
            return None
        return entry[0]

    # --- challenges -----------------------------------------------------------------------------------------------

    def _issue(self, purpose: str, customer_id: str, device_id: str | None) -> str:
        nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        with self.lock:
            self.challenges[nonce] = (purpose, customer_id, device_id, time.time())
        return nonce

    def _consume(self, nonce: str, purpose: str, customer_id: str, device_id: str | None) -> bool:
        """Single use: a nonce is removed as soon as it is presented, valid or not."""
        with self.lock:
            entry = self.challenges.pop(nonce, None)
        if entry is None:
            return False
        issued_purpose, issued_customer, issued_device, issued_at = entry
        return (
            (issued_purpose, issued_customer, issued_device) == (purpose, customer_id, device_id)
            and time.time() - issued_at <= CHALLENGE_TTL_SECONDS
        )

    def challenge(self, body: dict) -> tuple[int, dict]:
        customer_id = self._customer(body)
        if customer_id is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "log in first"}
        purpose = body.get("purpose")
        if purpose not in ("bind", "transfer"):
            return HTTPStatus.BAD_REQUEST, {"error": "purpose must be bind or transfer"}
        device_id = body.get("deviceId") if purpose == "transfer" else None
        if purpose == "transfer" and not self._owns(customer_id, device_id):
            return HTTPStatus.NOT_FOUND, {"error": "unknown device"}
        nonce = self._issue(purpose, customer_id, device_id)
        return HTTPStatus.OK, {"nonce": nonce, "expiresIn": CHALLENGE_TTL_SECONDS}

    def _owns(self, customer_id: str, device_id: object) -> bool:
        with self.lock:
            device = self.devices.get(device_id) if isinstance(device_id, str) else None
        return device is not None and device.customer_id == customer_id

    # --- binding and transfers ------------------------------------------------------------------------------------

    def bind(self, body: dict) -> tuple[int, dict]:
        customer_id = self._customer(body)
        if customer_id is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "log in first"}
        challenge = body.get("challenge", "")
        if not self._consume(challenge, "bind", customer_id, None):
            return HTTPStatus.BAD_REQUEST, {"error": "unknown, used or expired challenge"}
        revocations = None
        if self.revocations is not None:
            revocations = self.revocations.current()
            if revocations is None:  # fail closed: without a fresh list, revoked keys would be accepted
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "revocation list unavailable, try again later"}
        try:
            result = verify_key_attestation(
                body.get("certificateChain", []),
                base64.b64decode(challenge),
                self.package_name,
                self.signing_cert_sha256,
                require_hardware=self.require_hardware,
                require_user_auth=self.require_user_auth,
                trusted_roots=self.trusted_roots,
                revocations=revocations,
            )
        except AttestationError as e:
            return HTTPStatus.FORBIDDEN, {"error": "attestation_failed", "reason": e.reason, "detail": str(e)}
        # The key the app will sign with must be the attested one.
        if base64.b64decode(body.get("publicKey", "")) != result.public_key_der:
            return HTTPStatus.FORBIDDEN, {"error": "attestation_failed", "reason": "key_mismatch"}
        device_id = secrets.token_hex(16)
        with self.lock:
            # One active device per customer: binding a new phone revokes the old one.
            revoked = [d for d, dev in self.devices.items() if dev.customer_id == customer_id]
            for old in revoked:
                del self.devices[old]
            self.devices[device_id] = Device(customer_id, result.public_key_der)
        return HTTPStatus.CREATED, {
            "deviceId": device_id,
            "revokedDevices": len(revoked),
            "securityLevel": result.security_level,
            "trustedRoot": result.trusted_root,
            "userAuthRequired": result.user_auth_required,
            "verifiedBootState": result.verified_boot_state,
            "warnings": result.warnings,
        }

    def transfer(self, body: dict) -> tuple[int, dict]:
        customer_id = self._customer(body)
        if customer_id is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "log in first"}
        device_id = body.get("deviceId")
        if not self._owns(customer_id, device_id):
            return HTTPStatus.NOT_FOUND, {"error": "unknown device"}
        with self.lock:
            public_key = self.devices[device_id].public_key_der
        signed_data = body.get("signedData", "")
        nonce = next((line[6:] for line in signed_data.split("\n") if line.startswith("nonce=")), None)
        if nonce is None or not self._consume(nonce, "transfer", customer_id, device_id):
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
    routes = {
        "/v1/sessions": state.login,
        "/v1/challenge": state.challenge,
        "/v1/devices": state.bind,
        "/v1/transfers": state.transfer,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (http.server naming)
            route = routes.get(self.path)
            if route is None:
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 256 * 1024:
                    return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                body = json.loads(self.rfile.read(length) or b"{}")
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--package", required=True)
    parser.add_argument("--cert-sha256", action="append", required=True, help="app signing certificate digest")
    parser.add_argument(
        "--allow-software-attestation", action="store_true",
        help="accept software-backed keys and non-Google roots (emulators). Never in production.",
    )
    parser.add_argument("--allow-no-user-auth", action="store_true",
                        help="accept keys usable without biometric or device credential. Never in production.")
    parser.add_argument("--no-revocation-check", action="store_true",
                        help="skip Google's revocation list (offline demos). Never in production.")
    args = parser.parse_args()

    revocations = None
    if not args.no_revocation_check:
        revocations = RevocationList()
        if not revocations.refresh():
            print("[bank] revocation list not loaded yet; binding is refused until it is", flush=True)
        revocations.start_background_refresh()
    state = BankState(
        args.package, args.cert_sha256,
        require_hardware=not args.allow_software_attestation,
        require_user_auth=not args.allow_no_user_auth,
        revocations=revocations,
    )
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(f"[bank] listening on {args.host}:{args.port} (hardware attestation: {state.require_hardware}, "
          f"user auth: {state.require_user_auth}, revocation check: {revocations is not None})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

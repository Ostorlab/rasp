"""Reference backend for the Demo Bank sample: the trust service and a bank resource server in one process.

The two are logically separate (the design deploys them apart), but the reference serves both so the sample
hits a single URL, and the bank verifies tokens against the trust service's JWKS in-process.

    python -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank --cert-sha256 <digest>
        --build-id <id> --build-key-hex <hex>  [--port 8787]
        [--allow-software-attestation] [--allow-no-user-auth] [--no-revocation-check] [--stub-play-integrity]

Trust service routes (JSON):
    POST /v1/challenge  {"installId","purpose":"bind"|"token"}                 -> {"nonce"}
    POST /v1/bind       {"installId","nonce","publicKey","certificateChain","playIntegrityToken"?} -> {...}
    POST /v1/token      {"installId","nonce","proof","sealedReport","playIntegrityToken"?} -> {"token",...}
    GET  /.well-known/jwks.json                                                -> JWKS

Bank resource routes (JSON):
    POST /v1/sessions   {"customerId","pin"}                                   -> {"sessionToken"}
    POST /v1/transfers  {"sessionToken","payee","amountCents","currency"} + X-Integrity-* headers
                                                                              -> {"decision","reasons"} (403 on deny)

Every bank route that needs device trust also needs the X-Integrity-* headers (see `resource`).
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import pathlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509

from rasp_verifier import jose
from rasp_verifier import app_attest
from rasp_verifier import durable_registry
from rasp_verifier import play_integrity
from rasp_verifier import postgres
from rasp_verifier import storage

from .jose import SigningKey
from .platform import DisabledPlatformAttestation, StubPlatformAttestation
from .policy import TokenPolicy
from .registry import Build, BuildRegistry, InstallRegistry
from .resource import ResourceError, decide, verify_request
from .revocation import RevocationList
from .trust import TrustError, TrustService

SESSION_TTL_SECONDS = 15 * 60
MAX_PIN_FAILURES = 5


@dataclass
class RequestContext:
    method: str
    path: str
    headers: dict
    body: bytes
    json: dict


@dataclass
class BankState:
    """The bank resource server: it verifies trust-service tokens and decides on transfers."""

    package_name: str
    jwks_provider: object  # callable -> {"keys":[...]}
    customers: dict[str, str] = field(default_factory=lambda: {"demo": "1234"})
    sessions: dict[str, tuple[str, float]] = field(default_factory=dict)
    pin_failures: dict[str, int] = field(default_factory=dict)
    session_install: dict[str, str] = field(default_factory=dict)  # session -> install id (sub)
    install_counter: dict[str, int] = field(default_factory=dict)  # session key thumbprint (cnf.jkt) -> last counter
    lock: threading.Lock = field(default_factory=threading.Lock)
    replay_store: storage.Store | None = None

    def login(self, ctx: RequestContext) -> tuple[int, dict]:
        body = ctx.json
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

    def transfer(self, ctx: RequestContext) -> tuple[int, dict]:
        customer_id = self._customer(ctx.json)
        if customer_id is None:
            return HTTPStatus.UNAUTHORIZED, {"error": "log in first"}
        headers = ctx.headers
        session = str(ctx.json.get("sessionToken", ""))
        try:
            verified = verify_request(
                token=headers.get("x-integrity-token", ""),
                install_key_der_b64=headers.get("x-integrity-key", ""),
                signature_b64=headers.get("x-integrity-sig", ""),
                ts_ms=int(headers.get("x-integrity-ts", "0")),
                counter=int(headers.get("x-integrity-counter", "0")),
                method=ctx.method,
                path=ctx.path,
                body=ctx.body,
                jwks_keys=self.jwks_provider()["keys"],
                replay_store=self.replay_store,
            )
        except (ResourceError, jose.JoseError) as error:
            return HTTPStatus.UNAUTHORIZED, {"error": "integrity_failed", "reason": error.reason}
        except ValueError:
            return HTTPStatus.UNAUTHORIZED, {"error": "integrity_failed", "reason": "bad_headers"}

        if verified.claims.get("app") != self.package_name:
            return HTTPStatus.FORBIDDEN, {"error": "integrity_failed", "reason": "wrong_app"}
        # Replay protection is scoped to the session key (cnf.jkt): each token has its own session key, so a
        # new token legitimately restarts the counter, but a proof cannot be replayed within one token's life.
        jkt = (verified.claims.get("cnf") or {}).get("jkt", "")
        with self.lock:
            bound = self.session_install.get(session)
            if bound is None:
                self.session_install[session] = verified.install_id
            elif bound != verified.install_id:
                return HTTPStatus.FORBIDDEN, {"error": "integrity_failed", "reason": "install_mismatch"}
            last = self.install_counter.get(jkt)
            if last is not None and verified.counter <= last:
                return HTTPStatus.UNAUTHORIZED, {"error": "integrity_failed", "reason": "replayed_proof"}
            self.install_counter[jkt] = verified.counter

        # A transfer is sensitive: high risk (malware watching, unlocked/compromised device) is denied,
        # medium (root, emulator, a call, a screenshot) needs step-up.
        decision = decide(verified.risk, verified.threats, deny_at="high", step_up_at="medium")
        status = HTTPStatus.FORBIDDEN if decision.action == "deny" else HTTPStatus.OK
        fields = {
            "payee": ctx.json.get("payee"),
            "amountCents": ctx.json.get("amountCents"),
            "currency": ctx.json.get("currency", "USD"),
        }
        return status, {"decision": decision.action, "reasons": decision.reasons, "fields": fields}


def make_handler(trust: TrustService, bank: BankState):
    def trust_challenge(ctx: RequestContext):
        return HTTPStatus.OK, trust.challenge(str(ctx.json.get("installId", "")), str(ctx.json.get("purpose", "")))

    def trust_bind(ctx: RequestContext):
        return HTTPStatus.CREATED, trust.bind(ctx.json)

    def trust_token(ctx: RequestContext):
        return HTTPStatus.OK, trust.token(ctx.json)

    post_routes = {
        "/v1/challenge": trust_challenge,
        "/v1/bind": trust_bind,
        "/v1/token": trust_token,
        "/v1/ios/bind": lambda ctx: (HTTPStatus.CREATED, trust.bind_ios(ctx.json)),
        "/v1/ios/token": lambda ctx: (HTTPStatus.OK, trust.token_ios(ctx.json)),
        "/v1/sessions": bank.login,
        "/v1/transfers": bank.transfer,
    }
    get_routes = {
        "/.well-known/jwks.json": lambda ctx: (HTTPStatus.OK, trust.jwks()),
        "/v1/jwks": lambda ctx: (HTTPStatus.OK, trust.jwks()),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            route = get_routes.get(self.path)
            if route is None:
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            self._run(route, b"", {})

        def do_POST(self):  # noqa: N802
            route = post_routes.get(self.path)
            if route is None:
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
                    raise ValueError("ambiguous request framing")
                if lengths[0].isascii() is False or lengths[0].isdecimal() is False:
                    raise ValueError("invalid content length")
                length = int(lengths[0])
                if length > 256 * 1024:
                    return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                raw = self.rfile.read(length) or b"{}"
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise ValueError("body must be an object")
            except ValueError:
                return self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
            self._run(route, raw, parsed)

        def _run(self, route, raw: bytes, parsed: dict):
            ctx = RequestContext(
                method=self.command,
                path=self.path,
                headers={k.lower(): v for k, v in self.headers.items()},
                body=raw,
                json=parsed,
            )
            try:
                status, payload = route(ctx)
            except TrustError as e:
                status, payload = e.status, {"error": e.reason, "detail": e.detail}
            self._send(status, payload)

        def _send(self, status: int, payload: dict):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            print(f"[server] {self.address_string()} {fmt % args}", flush=True)

    return Handler


def build_services(args, revocations=None):
    scope = storage.Scope(args.tenant_id, args.package)
    dsn = os.environ.get(args.postgres_dsn_env)
    state = storage.MemoryStore(scope) if dsn is None else postgres.PostgresStore(dsn, scope)
    builds = durable_registry.BuildRegistry(state)
    builds.register(Build(args.build_id, bytes.fromhex(args.build_key_hex), args.package, args.cert_sha256))
    installs = durable_registry.InstallRegistry(state)
    platform = StubPlatformAttestation() if args.stub_play_integrity else DisabledPlatformAttestation()
    if args.google_play_integrity is True:
        platform = play_integrity.GooglePlayIntegrityAttestation(signing_cert_sha256=args.cert_sha256)
    apple = None
    if args.apple_app_id is not None:
        if args.apple_root_pem is None:
            raise ValueError("--apple-root-pem is required for App Attest")
        apple = app_attest.AppAttestVerifier(app_id=args.apple_app_id,
            trusted_roots=x509.load_pem_x509_certificates(pathlib.Path(args.apple_root_pem).read_bytes()),
            development=args.apple_development)
    signing_key = SigningKey.generate() if args.signing_key_pem is None else SigningKey.from_pem(pathlib.Path(args.signing_key_pem).read_bytes())
    policy = TokenPolicy(
        require_hardware=not args.allow_software_attestation,
        require_user_auth=not args.allow_no_user_auth,
    )
    trust = TrustService(
        signing_key=signing_key,
        state=state,
        apple_verifier=apple,
        package_name=args.package,
        signing_cert_sha256=args.cert_sha256,
        builds=builds,
        installs=installs,
        platform_attestation=platform,
        policy=policy,
        revocations=revocations,
    )
    bank = BankState(package_name=args.package, jwks_provider=trust.jwks, replay_store=state)
    return trust, bank


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--package", required=True)
    parser.add_argument("--cert-sha256", action="append", required=True, help="app signing certificate digest")
    parser.add_argument("--build-id", required=True, help="the genuine build's id (matches the app's build_config.h)")
    parser.add_argument("--build-key-hex", required=True, help="the build's report-MAC key, hex (matches build_config.h)")
    parser.add_argument("--allow-software-attestation", action="store_true",
                        help="accept software-backed keys and non-Google roots (emulators). Never in production.")
    parser.add_argument("--allow-no-user-auth", action="store_true",
                        help="accept keys usable without biometric or device credential. Never in production.")
    parser.add_argument("--no-revocation-check", action="store_true",
                        help="skip Google's revocation list (offline demos). Never in production.")
    parser.add_argument("--stub-play-integrity", action="store_true",
                        help="accept the self-describing stub platform token (demos/tests). Never in production.")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--postgres-dsn-env", default="RASP_POSTGRES_DSN", help="environment variable holding database DSN")
    parser.add_argument("--signing-key-pem", help="persistent P-256 signing key; omit only for demos")
    parser.add_argument("--google-play-integrity", action="store_true", help="use Google OAuth decode API with application default credentials")
    parser.add_argument("--apple-app-id", help="Apple App ID prefix plus bundle ID")
    parser.add_argument("--apple-root-pem", help="trusted Apple App Attest root PEM file")
    parser.add_argument("--apple-development", action="store_true", help="accept development App Attest AAGUID only")
    args = parser.parse_args()
    if args.google_play_integrity is True and args.stub_play_integrity is True:
        parser.error("Google verification and demo stub are mutually exclusive")

    revocations = None
    if not args.no_revocation_check:
        revocations = RevocationList()
        if not revocations.refresh():
            print("[server] revocation list not loaded yet; binding is refused until it is", flush=True)
        revocations.start_background_refresh()
    trust, bank = build_services(args, revocations=revocations)
    try:
        server = ThreadingHTTPServer((args.host, args.port), make_handler(trust, bank))
        try:
            print(f"[server] listening on {args.host}:{args.port} (hardware: {trust.policy.require_hardware}, "
                  f"user auth: {trust.policy.require_user_auth}, revocation: {revocations is not None}, "
                  f"platform attestation: {trust.platform.available})", flush=True)
            server.serve_forever()
        finally:
            server.server_close()
    finally:
        if isinstance(trust.state, postgres.PostgresStore):
            trust.state.close()


if __name__ == "__main__":
    main()

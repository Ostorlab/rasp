"""Reusable evidence authorizer and small, bounded reference HTTP adapter."""

from __future__ import annotations

import collections.abc
import dataclasses
import hashlib
import http.server
import json
import pathlib
import re
import secrets
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ed25519

from rasp_elf import protocol

CHALLENGE_TTL = 30.0


@dataclasses.dataclass(frozen=True)
class Evidence:
    build: str
    nonce: str
    pid: int
    exe: str
    runtime: str
    threats: tuple[str, ...]
    operation: str
    request: str


class Authorizer:
    """Verify first, then invoke the customer's policy. Keys are software-only."""

    def __init__(
        self,
        decision_key: ed25519.Ed25519PrivateKey,
        publisher_public: str,
        policy: collections.abc.Callable[[Evidence], str] | None = None,
        clock: collections.abc.Callable[[], float] = time.monotonic,
        max_challenges: int = 4096,
        audit_path: pathlib.Path | None = None,
    ) -> None:
        if max_challenges < 1 or max_challenges > 4096:
            raise ValueError("max_challenges must be between 1 and 4096")
        self.decision_key = decision_key
        self.publisher_public = publisher_public
        self.policy = policy
        self.clock = clock
        self.max_challenges = max_challenges
        self.audit_path = audit_path
        self._builds: dict[str, dict[str, str]] = {}
        self._challenges: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._audit_lock = threading.Lock()

    def register(self, manifest: bytes) -> None:
        values = protocol.validate_manifest(manifest, self.publisher_public)
        if values["endpoint"] == "" or values["server_public"] != protocol.public_hex(self.decision_key):
            raise ValueError("manifest backend key does not match this server")
        with self._lock:
            if values["build"] in self._builds and self._builds[values["build"]] != values:
                raise ValueError("build already registered with different metadata")
            self._builds[values["build"]] = values

    def challenge(self, build: str) -> str:
        now = self.clock()
        with self._lock:
            if build not in self._builds:
                raise ValueError("unknown build")
            self._challenges = {
                nonce: entry for nonce, entry in self._challenges.items() if now - entry[1] < CHALLENGE_TTL
            }
            if len(self._challenges) >= self.max_challenges:
                raise ValueError("challenge capacity exhausted")
            nonce = secrets.token_hex(32)
            self._challenges[nonce] = (build, now)
        return nonce

    def authorize(
        self,
        message: bytes,
        *,
        expected_request: bytes | None = None,
        expected_operation: str | None = None,
    ) -> bytes:
        """Consume evidence once; middleware can bind it to its actual request bytes."""
        fields, signed, _ = protocol.parse_message(message, protocol.EVIDENCE_FIELDS)
        with self._lock:
            challenge = self._challenges.pop(fields["nonce"], None)
            manifest = self._builds.get(fields["build"])
        if (
            challenge is None
            or manifest is None
            or challenge[0] != fields["build"]
            or self.clock() - challenge[1] >= CHALLENGE_TTL
        ):
            raise ValueError("unknown, expired, used or mismatched challenge")
        protocol.verify_message(message, manifest["client_public"], protocol.EVIDENCE_FIELDS)
        if fields["v"] != "rasp-elf-evidence-1" or fields["operation"] not in protocol.OPERATIONS:
            raise ValueError("invalid evidence version or operation")
        for name in ("build", "nonce", "exe", "runtime", "request"):
            if protocol.is_hex(fields[name]) is False:
                raise ValueError(f"invalid evidence {name}")
        if re.fullmatch(r"[1-9][0-9]{0,9}", fields["pid"]) is None:
            raise ValueError("invalid evidence pid")
        threats = () if fields["threats"] == "none" else tuple(fields["threats"].split(","))
        if any(threat not in protocol.THREATS for threat in threats) or len(set(threats)) != len(threats):
            raise ValueError("invalid threat names")
        evidence = Evidence(
            build=fields["build"],
            nonce=fields["nonce"],
            pid=int(fields["pid"]),
            exe=fields["exe"],
            runtime=fields["runtime"],
            threats=threats,
            operation=fields["operation"],
            request=fields["request"],
        )
        action = "allow"
        request_mismatch = (
            expected_request is not None and evidence.request != hashlib.sha256(expected_request).hexdigest()
        )
        operation_mismatch = expected_operation is not None and evidence.operation != expected_operation
        if (
            len(threats) != 0
            or evidence.exe != manifest["exe"]
            or evidence.runtime != manifest["runtime"]
            or request_mismatch is True
            or operation_mismatch is True
        ):
            action = "deny"
        elif self.policy is not None:
            try:
                candidate = self.policy(evidence)
                action = candidate if candidate in protocol.ACTIONS else "deny"
            except Exception:  # noqa: BLE001 - arbitrary customer policy failures must deny.
                action = "deny"
        self._audit(evidence, action)
        return protocol.sign_message(
            {
                "v": "rasp-elf-decision-1",
                "build": evidence.build,
                "nonce": evidence.nonce,
                "evidence": hashlib.sha256(signed).hexdigest(),
                "action": action,
                "expires": str(int(time.time()) + 30),
            },
            self.decision_key,
        )

    def _audit(self, evidence: Evidence, action: str) -> None:
        if self.audit_path is None:
            return
        event = dataclasses.asdict(evidence) | {"action": action, "timestamp": int(time.time())}
        with self._audit_lock, self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")


class ReferenceServer(http.server.ThreadingHTTPServer):
    """Loopback demo adapter; production should use its own bounded HTTP stack."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], authorizer: Authorizer) -> None:
        self.authorizer = authorizer
        super().__init__(address, Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    server: ReferenceServer

    def setup(self) -> None:
        self.request.settimeout(2.0)
        super().setup()

    def do_POST(self) -> None:
        try:
            raw_length = self.headers.get("Content-Length", "")
            if self.headers.get("Transfer-Encoding") is not None or re.fullmatch(r"[0-9]{1,5}", raw_length) is None:
                raise ValueError("Content-Length required; chunking unsupported")
            length = int(raw_length)
            if length < 1 or length > protocol.MAX_MESSAGE_BYTES:
                raise ValueError("invalid body length")
            message = self.rfile.read(length)
            if len(message) != length:
                raise ValueError("truncated body")
            if self.path == "/v1/challenge":
                if re.fullmatch(rb"build=[0-9a-f]{64}\n", message) is None:
                    raise ValueError("invalid challenge request")
                nonce = self.server.authorizer.challenge(message[6:-1].decode("ascii"))
                self._send(200, f"nonce={nonce}\n".encode("ascii"))
            elif self.path == "/v1/authorize":
                self._send(200, self.server.authorizer.authorize(message))
            else:
                self._send(404, b"error=unknown endpoint\n")
        except (ValueError, UnicodeError) as error:
            self._send(400, f"error={error}\n".encode("ascii", errors="replace"))
        except OSError:
            self.close_connection = True
        except Exception:  # noqa: BLE001 - never turn adapter failures into an allow response.
            self._send(503, b"error=authorization unavailable\n")

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return

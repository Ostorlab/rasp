"""Exercise the go-live checker over real HTTP, including broken enforcement."""

from __future__ import annotations

import base64
import contextlib
import http.server
import io
import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from rasp_verifier import enforcement
from rasp_verifier import jose

from tests import test_server


class EnforcementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = "protected"
        self.seen = False
        self.requests: list[dict[str, str]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                headers = {name.lower(): value for name, value in self.headers.items()}
                owner.requests.append(headers)
                token = headers.get("x-integrity-token", "")
                if owner.mode == "unavailable":
                    status = 503
                elif owner.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "/redirected")
                    self.end_headers()
                    return
                elif owner.mode == "open":
                    status = 200
                elif token == owner.valid_token and owner.seen is False:
                    owner.seen = True
                    status = 200
                elif token == owner.valid_token and owner.mode == "replayable":
                    status = 200
                else:
                    status = 401
                self.send_response(status)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.shutdown)
        self.valid_token = _token(int(time.time()) + 600)
        self.expired_token = _token(int(time.time()) - 600)
        self.request = enforcement.ProbeRequest(
            url=f"http://127.0.0.1:{self.server.server_port}/transfer",
            method="POST",
            body=b'{"amount":1}',
            headers={
                "Authorization": "Bearer test-account",
                "X-Integrity-Token": self.valid_token,
                "X-Integrity-Key": "test-key",
                "X-Integrity-Sig": "test-signature",
                "X-Integrity-Ts": "1",
                "X-Integrity-Counter": "1",
            },
        )
        self.expired_headers = {
            **self.request.headers,
            "X-Integrity-Token": self.expired_token,
        }

    def testCheck_whenEnforcementWorks_returnsAllPassing(self) -> None:
        results = enforcement.check(
            self.request, self.expired_headers, allow_loopback_http=True
        )
        self.assertEqual(
            [result.name for result in results],
            [
                "missing_token",
                "invalid_token",
                "expired_token",
                "valid_request",
                "replayed_request",
            ],
        )
        self.assertTrue(all(result.passed is True for result in results))
        self.assertNotIn("x-integrity-token", self.requests[0])
        self.assertEqual(self.requests[0]["authorization"], "Bearer test-account")

    def testCheck_whenEnvironmentProxyConfigured_sendsCredentialsOnlyToTarget(
        self,
    ) -> None:
        with (
            mock.patch(
                "urllib.request.getproxies", return_value={"http": "http://127.0.0.1:1"}
            ),
            mock.patch("urllib.request.proxy_bypass", return_value=False),
        ):
            results = enforcement.check(
                self.request, self.expired_headers, allow_loopback_http=True
            )
        self.assertTrue(all(result.passed is True for result in results))
        self.assertEqual(len(self.requests), 5)

    def testCheck_whenEndpointIgnoresIntegrity_rejects(self) -> None:
        self.mode = "open"
        results = enforcement.check(
            self.request, self.expired_headers, allow_loopback_http=True
        )
        self.assertFalse(all(result.passed is True for result in results))

    def testCheck_whenProofCanReplay_rejects(self) -> None:
        self.mode = "replayable"
        results = enforcement.check(
            self.request, self.expired_headers, allow_loopback_http=True
        )
        self.assertFalse(results[-1].passed)

    def testCheck_whenServerUnavailable_neverTreatsErrorAsEnforcement(self) -> None:
        self.mode = "unavailable"
        results = enforcement.check(
            self.request, self.expired_headers, allow_loopback_http=True
        )
        self.assertTrue(all(result.passed is False for result in results))

    def testCheck_whenRedirected_doesNotForwardCredentials(self) -> None:
        self.mode = "redirect"
        results = enforcement.check(
            self.request, self.expired_headers, allow_loopback_http=True
        )
        self.assertEqual(len(self.requests), 5)
        self.assertTrue(all(result.passed is False for result in results))

    def testCheck_whenExpiredFixtureIsFresh_failsBeforeSending(self) -> None:
        with self.assertRaises(ValueError):
            enforcement.check(
                self.request, self.request.headers, allow_loopback_http=True
            )
        self.assertEqual(self.requests, [])

    def testCheck_whenHttpNotExplicitlyAllowed_failsBeforeSending(self) -> None:
        with self.assertRaises(ValueError):
            enforcement.check(self.request, self.expired_headers)
        self.assertEqual(self.requests, [])

    def testCheck_whenAccountCredentialsDiffer_failsBeforeSending(self) -> None:
        headers = {**self.expired_headers, "Authorization": "Bearer wrong-account"}
        with self.assertRaises(ValueError):
            enforcement.check(self.request, headers, allow_loopback_http=True)
        self.assertEqual(self.requests, [])

    def testCheck_whenDuplicateCaseHeaders_rejectsAmbiguousRequest(self) -> None:
        request = enforcement.ProbeRequest(
            self.request.url,
            self.request.method,
            self.request.body,
            {**self.request.headers, "x-integrity-token": "other"},
        )
        with self.assertRaises(ValueError):
            enforcement.check(request, self.expired_headers, allow_loopback_http=True)
        self.assertEqual(self.requests, [])

    def testCheck_whenConnectionRefused_reportsFailure(self) -> None:
        request = enforcement.ProbeRequest(
            "http://127.0.0.1:0/", "POST", self.request.body, self.request.headers
        )
        results = enforcement.check(
            request, self.expired_headers, allow_loopback_http=True
        )
        self.assertTrue(
            all(result.status == 0 and result.passed is False for result in results)
        )

    def testCheck_whenInvalidParameters_rejectsBeforeNetwork(self) -> None:
        for url in [
            "http://example.com",
            "http://localhost",
            "ftp://127.0.0.1",
            "https://user@example.com",
            "https://example.com/#f",
            "https://",
        ]:
            request = enforcement.ProbeRequest(url, "POST", b"", self.request.headers)
            with self.subTest(url=url), self.assertRaises(ValueError):
                enforcement.check(
                    request, self.expired_headers, allow_loopback_http=True
                )
        for timeout in [0, -1, float("nan"), float("inf"), 61]:
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                enforcement.check(
                    self.request,
                    self.expired_headers,
                    timeout=timeout,
                    allow_loopback_http=True,
                )

    def testMain_whenFixtureValid_returnsSuccessWithoutLeakingCredentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "url": self.request.url,
                        "method": "POST",
                        "bodyBase64": base64.b64encode(self.request.body).decode(),
                        "headers": self.request.headers,
                        "expiredHeaders": self.expired_headers,
                    }
                )
            )
            output = io.StringIO()
            with (
                mock.patch(
                    "sys.argv", ["enforcement", str(fixture), "--allow-loopback-http"]
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(enforcement.main(), 0)
            self.assertNotIn(self.valid_token, output.getvalue())
            self.assertTrue(json.loads(output.getvalue())["passed"])

    def testMain_whenFixtureMalformed_returnsConfigurationError(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "fixture.json"
            fixture.write_text('{"secret":"never print me"}')
            output = io.StringIO()
            with (
                mock.patch("sys.argv", ["enforcement", str(fixture)]),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(enforcement.main(), 2)
            self.assertNotIn("never print me", output.getvalue())


def _token(expiry: int) -> str:
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode())
        .decode()
        .rstrip("=")
    )
    return f"eyJhbGciOiJFUzI1NiJ9.{payload}.fixture-signature"


class ReferenceEnforcementTest(unittest.TestCase):
    def testCheck_withAttestedReferenceBankFlow_verifiesAllRefusals(self) -> None:
        bank = test_server.ServerTest()
        bank.setUp()
        self.addCleanup(bank.tearDown)
        session = bank.login()
        chain, _ = bank.bind()
        token, session_key = bank.get_token(chain)
        body, headers = bank.build_transfer(session, session_key, token)
        claims = jose.decode_jwt(token, bank.trust.jwks()["keys"])
        claims["iat"] = int(time.time()) - 1200
        claims["exp"] = int(time.time()) - 600
        expired_token = bank.trust.signing_key.sign_jwt(claims)
        expired = {**headers, "X-Integrity-Token": expired_token}
        request = enforcement.ProbeRequest(
            bank.base + "/v1/transfers", "POST", body, headers
        )

        results = enforcement.check(request, expired, allow_loopback_http=True)

        self.assertEqual(
            [result.status for result in results], [401, 401, 401, 200, 401]
        )
        self.assertTrue(all(result.passed for result in results))

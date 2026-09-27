"""HTTP tests for the reference server: the trust service and bank resource server together."""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization

from rasp_verifier import jose
from rasp_verifier.platform import StubPlatformAttestation
from rasp_verifier.policy import TokenPolicy
from rasp_verifier.registry import Build, BuildRegistry, InstallRegistry
from rasp_verifier.resource import canonical_request
from rasp_verifier.revocation import RevocationList
from rasp_verifier.server import MAX_PIN_FAILURES, BankState, make_handler
from rasp_verifier.trust import TrustService, token_proof_message
from tests.helpers import (
    BUILD_ID,
    BUILD_KEY,
    APP_CERT_SHA256,
    PACKAGE,
    Chain,
    raw_es256,
    seal_report,
    session_keypair,
    stub_play_integrity,
)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.trust = TrustService(
            signing_key=jose.SigningKey.generate(),
            package_name=PACKAGE,
            signing_cert_sha256=[APP_CERT_SHA256],
            builds=BuildRegistry([Build(BUILD_ID, BUILD_KEY, PACKAGE, [APP_CERT_SHA256])]),
            installs=InstallRegistry(),
            platform_attestation=StubPlatformAttestation(),
            policy=TokenPolicy(),
            revocations=None,
        )
        self.bank = BankState(PACKAGE, self.trust.jwks, customers={"alice": "1111", "bob": "2222"})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.trust, self.bank))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, path, body, headers=None):
        raw = json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, raw,
                                         {"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read()), raw
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read()), raw

    # --- flow helpers ---------------------------------------------------------------------------------------

    def login(self, customer="alice", pin="1111"):
        status, body, _ = self.post("/v1/sessions", {"customerId": customer, "pin": pin})
        self.assertEqual(201, status, body)
        return body["sessionToken"]

    def bind(self, install_id="install-1", *, user_auth=True, expect=201, **chain_kwargs):
        _, challenge, _ = self.post("/v1/challenge", {"installId": install_id, "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=user_auth, **chain_kwargs)
        self.trust.trusted_roots = [chain.root]
        status, body, _ = self.post("/v1/bind", {
            "installId": install_id,
            "nonce": challenge["nonce"],
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
            "playIntegrityToken": stub_play_integrity(challenge["nonce"]),
        })
        self.assertEqual(expect, status, body)
        return chain, body

    def get_token(self, chain, install_id="install-1", signals=(), verdict="STRONG"):
        """Returns (token, session_private_key). The session key signs per-request proofs silently."""
        _, challenge, _ = self.post("/v1/challenge", {"installId": install_id, "purpose": "token"})
        nonce = challenge["nonce"]
        sealed = seal_report(nonce, signals)
        session_key, session_b64 = session_keypair()
        session_jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = raw_es256(chain.device_key, token_proof_message(nonce, sealed["mac"], session_jkt))
        status, body, _ = self.post("/v1/token", {
            "installId": install_id, "nonce": nonce, "proof": proof, "sessionPublicKey": session_b64,
            "sealedReport": sealed, "playIntegrityToken": stub_play_integrity(nonce, verdict=verdict),
        })
        self.assertEqual(200, status, body)
        return body["token"], session_key

    def build_transfer(self, session, session_key, token, *, counter=1, amount_cents=5000, session_override=None):
        """Returns the (raw body, headers) for a transfer request, so a test can send or replay it."""
        body = {"sessionToken": session_override or session, "payee": "Alex Smith",
                "amountCents": amount_cents, "currency": "USD"}
        raw = json.dumps(body).encode()
        import time

        ts = int(time.time() * 1000)
        key_der = session_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        sig = raw_es256(session_key, canonical_request("POST", "/v1/transfers", raw, ts, counter))
        headers = {
            "X-Integrity-Token": token,
            "X-Integrity-Key": base64.b64encode(key_der).decode(),
            "X-Integrity-Sig": sig,
            "X-Integrity-Ts": str(ts),
            "X-Integrity-Counter": str(counter),
        }
        return raw, headers

    def send(self, raw, headers):
        request = urllib.request.Request(self.base + "/v1/transfers", raw,
                                         {"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def transfer(self, session, session_key, token, **kwargs):
        return self.send(*self.build_transfer(session, session_key, token, **kwargs))

    # --- tests ----------------------------------------------------------------------------------------------

    def test_clean_transfer_is_allowed(self):
        session = self.login()
        chain, bound = self.bind()
        self.assertTrue(bound["userAuthRequired"])
        token, session_key = self.get_token(chain)
        status, body = self.transfer(session, session_key, token)
        self.assertEqual((200, "allow"), (status, body["decision"]))
        self.assertEqual(5000, body["fields"]["amountCents"])

    def test_transfer_requires_a_session(self):
        self.assertEqual(401, self.post("/v1/transfers", {})[0])

    def test_wrong_pin_locks_the_customer(self):
        for _ in range(MAX_PIN_FAILURES):
            self.assertEqual(401, self.post("/v1/sessions", {"customerId": "alice", "pin": "0000"})[0])
        self.assertEqual(429, self.post("/v1/sessions", {"customerId": "alice", "pin": "1111"})[0])

    def test_malware_on_device_is_denied(self):
        session = self.login()
        chain, _ = self.bind()
        token, sk = self.get_token(chain, signals=[("accessibilityAbuse", 95, "fraud.a11y", "evil.apk")])
        status, body = self.transfer(session, sk, token)
        self.assertEqual((403, "deny"), (status, body["decision"]))

    def test_call_during_transfer_needs_step_up(self):
        session = self.login()
        chain, _ = self.bind()
        token, sk = self.get_token(chain, signals=[("activeCall", 90, "fraud.active_call", "mode=2")])
        status, body = self.transfer(session, sk, token)
        self.assertEqual((200, "step_up"), (status, body["decision"]))

    def test_replayed_request_proof_is_rejected(self):
        session = self.login()
        chain, _ = self.bind()
        token, sk = self.get_token(chain)
        raw, headers = self.build_transfer(session, sk, token, counter=1)
        self.assertEqual(200, self.send(raw, headers)[0])
        # Replaying the exact same proof (same token, session key and counter) is rejected.
        status, body = self.send(raw, headers)
        self.assertEqual((401, "replayed_proof"), (status, body.get("reason")))

    def test_a_new_token_restarts_the_counter(self):
        # Each token has its own session key, so a legitimate second transfer with counter 1 is allowed.
        session = self.login()
        chain, _ = self.bind()
        token, sk = self.get_token(chain)
        self.assertEqual(200, self.transfer(session, sk, token, counter=1)[0])
        token2, sk2 = self.get_token(chain)
        self.assertEqual(200, self.transfer(session, sk2, token2, counter=1)[0])

    def test_a_second_install_cannot_use_the_first_sessions(self):
        session = self.login()
        chain, _ = self.bind("install-1")
        token, sk = self.get_token(chain)
        self.assertEqual(200, self.transfer(session, sk, token)[0])
        other, _ = self.bind("install-2")
        token2, sk2 = self.get_token(other, install_id="install-2")
        status, body = self.transfer(session, sk2, token2, counter=2)
        self.assertEqual((403, "install_mismatch"), (status, body.get("reason")))

    def test_wrong_key_for_token_is_rejected(self):
        session = self.login()
        chain, _ = self.bind()
        token, _ = self.get_token(chain)
        wrong_key, _ = session_keypair()  # not the session key the token is bound to
        status, body = self.transfer(session, wrong_key, token)
        self.assertEqual((401, "key_mismatch"), (status, body.get("reason")))

    def test_key_without_user_auth_is_refused_at_bind(self):
        _, body = self.bind(user_auth=False, expect=403)
        self.assertEqual("attestation_failed", body["error"])
        self.assertIn("no_user_auth", body["detail"])

    def test_forged_certificate_below_the_leaf_cannot_bind(self):
        _, challenge, _ = self.post("/v1/challenge", {"installId": "install-1", "purpose": "bind"})
        raw = base64.b64decode(challenge["nonce"])
        chain = Chain(raw, locked=False, boot_state=2, user_auth=True)
        self.trust.trusted_roots = [chain.root]
        forged, outside_key = chain.forge_below_leaf(raw)
        status, body, _ = self.post("/v1/bind", {
            "installId": "install-1", "nonce": challenge["nonce"],
            "publicKey": base64.b64encode(outside_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            "certificateChain": chain.b64(extra_below_leaf=forged),
        })
        self.assertEqual((403, "attestation_failed"), (status, body.get("error")))
        self.assertIn("bad_chain", body["detail"])

    def test_bind_rejects_substituted_public_key(self):
        _, challenge, _ = self.post("/v1/challenge", {"installId": "install-1", "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=True)
        self.trust.trusted_roots = [chain.root]
        status, body, _ = self.post("/v1/bind", {
            "installId": "install-1", "nonce": challenge["nonce"],
            "publicKey": base64.b64encode(Chain(b"y" * 32).public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual((403, "key_mismatch"), (status, body.get("error")))

    def test_bind_fails_closed_without_revocation_list(self):
        self.trust.revocations = RevocationList(source=lambda: (_ for _ in ()).throw(OSError("down")))
        self.trust.revocations.refresh()
        _, body = self.bind(expect=503)
        self.assertEqual("revocation_unavailable", body["error"])

    def test_revoked_intermediate_cannot_bind(self):
        _, challenge, _ = self.post("/v1/challenge", {"installId": "install-1", "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=True, intermediate_serial=0xC0FFEE)
        self.trust.trusted_roots = [chain.root]
        self.trust.revocations = RevocationList(source=lambda: {"entries": {"c0ffee": {"status": "REVOKED"}}})
        self.trust.revocations.refresh()
        status, body, _ = self.post("/v1/bind", {
            "installId": "install-1", "nonce": challenge["nonce"],
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual((403, "attestation_failed"), (status, body.get("error")))
        self.assertIn("revoked", body["detail"])

    def test_jwks_is_served(self):
        request = urllib.request.Request(self.base + "/.well-known/jwks.json")
        with urllib.request.urlopen(request) as response:
            jwks = json.loads(response.read())
        self.assertEqual(1, len(jwks["keys"]))
        self.assertEqual("ES256", jwks["keys"][0]["alg"])


if __name__ == "__main__":
    unittest.main()

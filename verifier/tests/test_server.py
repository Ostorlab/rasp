import base64
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from rasp_verifier.revocation import RevocationList
from rasp_verifier.server import MAX_PIN_FAILURES, BankState, make_handler
from tests.helpers import APP_CERT_SHA256, PACKAGE, Chain


class BankServerTest(unittest.TestCase):
    def setUp(self):
        self.state = BankState(PACKAGE, [APP_CERT_SHA256], customers={"alice": "1111", "bob": "2222"})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, path, body):
        request = urllib.request.Request(self.base + path, json.dumps(body).encode(),
                                         {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def login(self, customer="alice", pin="1111"):
        status, body = self.post("/v1/sessions", {"customerId": customer, "pin": pin})
        self.assertEqual(201, status, body)
        return body["sessionToken"]

    def bind(self, session, *, user_auth=True, expect=201):
        _, challenge = self.post("/v1/challenge", {"sessionToken": session, "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=user_auth)
        self.state.trusted_roots = [chain.root]
        status, body = self.post("/v1/devices", {
            "sessionToken": session,
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual(expect, status, body)
        return chain, body.get("deviceId"), body

    def signed(self, session, chain, device_id, risk="none", threats="", amount="50.00"):
        _, challenge = self.post("/v1/challenge", {"sessionToken": session, "purpose": "transfer",
                                                   "deviceId": device_id})
        text = "\n".join([
            "v=rasp-tx-1", f"nonce={challenge['nonce']}", f"ts={int(time.time() * 1000)}", f"app={PACKAGE}",
            f"risk={risk}", f"threats={threats}", f"f.amount={amount}", "f.payee=Alex Smith",
        ])
        signature = base64.b64encode(chain.device_key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()
        return {"sessionToken": session, "deviceId": device_id, "signedData": text, "signature": signature}

    def test_bind_and_clean_transfer_is_allowed(self):
        session = self.login()
        chain, device_id, body = self.bind(session)
        self.assertTrue(body["userAuthRequired"])
        status, body = self.post("/v1/transfers", self.signed(session, chain, device_id))
        self.assertEqual((200, "allow"), (status, body["decision"]))
        self.assertEqual("50.00", body["fields"]["amount"])

    def test_everything_requires_a_session(self):
        for path in ("/v1/challenge", "/v1/devices", "/v1/transfers"):
            with self.subTest(path=path):
                self.assertEqual(401, self.post(path, {"purpose": "bind"})[0])

    def test_wrong_pin_locks_the_customer(self):
        for _ in range(MAX_PIN_FAILURES):
            self.assertEqual(401, self.post("/v1/sessions", {"customerId": "alice", "pin": "0000"})[0])
        self.assertEqual(429, self.post("/v1/sessions", {"customerId": "alice", "pin": "1111"})[0])

    def test_key_without_user_auth_is_refused(self):
        _, _, body = self.bind(self.login(), user_auth=False, expect=403)
        self.assertEqual("no_user_auth", body["reason"])

    def test_new_device_revokes_the_old_one(self):
        session = self.login()
        old_chain, old_device, _ = self.bind(session)
        _, _, body = self.bind(session)
        self.assertEqual(1, body["revokedDevices"])
        status, _ = self.post("/v1/challenge", {"sessionToken": session, "purpose": "transfer", "deviceId": old_device})
        self.assertEqual(404, status)

    def test_other_customers_device_is_not_usable(self):
        alice = self.login()
        chain, device_id, _ = self.bind(alice)
        bob = self.login("bob", "2222")
        self.assertEqual(404, self.post("/v1/challenge", {"sessionToken": bob, "purpose": "transfer",
                                                          "deviceId": device_id})[0])
        request = self.signed(alice, chain, device_id)
        request["sessionToken"] = bob
        self.assertEqual(404, self.post("/v1/transfers", request)[0])

    def test_replayed_transfer_is_rejected(self):
        session = self.login()
        chain, device_id, _ = self.bind(session)
        request = self.signed(session, chain, device_id)
        self.assertEqual(200, self.post("/v1/transfers", request)[0])
        status, body = self.post("/v1/transfers", request)
        self.assertEqual(400, status)
        self.assertIn("used", body["error"])

    def test_malware_on_device_is_denied(self):
        session = self.login()
        chain, device_id, _ = self.bind(session)
        status, body = self.post("/v1/transfers", self.signed(session, chain, device_id, "high", "accessibilityAbuse"))
        self.assertEqual((403, "deny"), (status, body["decision"]))

    def test_call_during_transfer_needs_step_up(self):
        session = self.login()
        chain, device_id, _ = self.bind(session)
        status, body = self.post("/v1/transfers", self.signed(session, chain, device_id, "medium", "activeCall"))
        self.assertEqual((200, "step_up"), (status, body["decision"]))

    def test_other_key_cannot_sign_for_device(self):
        session = self.login()
        _, device_id, _ = self.bind(session)
        status, body = self.post("/v1/transfers", self.signed(session, Chain(b"x" * 32), device_id))
        self.assertEqual((403, "bad_signature"), (status, body.get("reason")))

    def test_forged_certificate_below_the_leaf_cannot_bind(self):
        session = self.login()
        _, challenge = self.post("/v1/challenge", {"sessionToken": session, "purpose": "bind"})
        raw = base64.b64decode(challenge["nonce"])
        chain = Chain(raw, locked=False, boot_state=2, user_auth=True)
        self.state.trusted_roots = [chain.root]
        forged, outside_key = chain.forge_below_leaf(raw)
        from cryptography.hazmat.primitives import serialization
        status, body = self.post("/v1/devices", {
            "sessionToken": session,
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(outside_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            "certificateChain": chain.b64(extra_below_leaf=forged),
        })
        self.assertEqual((403, "bad_chain"), (status, body.get("reason")))

    def test_bind_rejects_substituted_public_key(self):
        session = self.login()
        _, challenge = self.post("/v1/challenge", {"sessionToken": session, "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=True)
        self.state.trusted_roots = [chain.root]
        status, body = self.post("/v1/devices", {
            "sessionToken": session,
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(Chain(b"y" * 32).public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual((403, "key_mismatch"), (status, body.get("reason")))

    def test_bind_fails_closed_without_revocation_list(self):
        def unavailable():
            raise OSError("network down")

        self.state.revocations = RevocationList(source=unavailable)
        self.state.revocations.refresh()
        _, _, body = self.bind(self.login(), expect=503)
        self.assertIn("revocation", body["error"])

    def test_revoked_intermediate_cannot_bind(self):
        session = self.login()
        _, challenge = self.post("/v1/challenge", {"sessionToken": session, "purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]), user_auth=True, intermediate_serial=0xC0FFEE)
        self.state.trusted_roots = [chain.root]
        self.state.revocations = RevocationList(source=lambda: {"entries": {"c0ffee": {"status": "REVOKED"}}})
        self.state.revocations.refresh()
        status, body = self.post("/v1/devices", {
            "sessionToken": session,
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual((403, "revoked"), (status, body.get("reason")))


class RevocationListTest(unittest.TestCase):
    def test_stale_list_is_treated_as_missing(self):
        now = [0.0]
        cache = RevocationList(source=lambda: {"entries": {"AB": {"status": "REVOKED"}}}, max_age=100,
                               clock=lambda: now[0])
        self.assertIsNone(cache.current())
        self.assertTrue(cache.refresh())
        self.assertEqual({"ab": "REVOKED"}, cache.current())
        now[0] = 101
        self.assertIsNone(cache.current())


if __name__ == "__main__":
    unittest.main()

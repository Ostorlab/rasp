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

from rasp_verifier.server import BankState, make_handler
from tests.helpers import APP_CERT_SHA256, PACKAGE, Chain


class BankServerTest(unittest.TestCase):
    def setUp(self):
        self.state = BankState(PACKAGE, [APP_CERT_SHA256])
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

    def bind(self):
        _, challenge = self.post("/v1/challenge", {"purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]))
        self.state.trusted_roots = [chain.root]
        status, body = self.post("/v1/devices", {
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual(201, status, body)
        return chain, body["deviceId"]

    def signed(self, chain, device_id, risk="none", threats="", amount="50.00"):
        _, challenge = self.post("/v1/challenge", {"purpose": "transfer", "deviceId": device_id})
        text = "\n".join([
            "v=rasp-tx-1", f"nonce={challenge['nonce']}", f"ts={int(time.time() * 1000)}", f"app={PACKAGE}",
            f"risk={risk}", f"threats={threats}", f"f.amount={amount}", "f.payee=Alex Smith",
        ])
        signature = base64.b64encode(chain.device_key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()
        return {"deviceId": device_id, "signedData": text, "signature": signature}

    def test_bind_and_clean_transfer_is_allowed(self):
        chain, device_id = self.bind()
        status, body = self.post("/v1/transfers", self.signed(chain, device_id))
        self.assertEqual((200, "allow"), (status, body["decision"]))
        self.assertEqual("50.00", body["fields"]["amount"])

    def test_replayed_transfer_is_rejected(self):
        chain, device_id = self.bind()
        request = self.signed(chain, device_id)
        self.assertEqual(200, self.post("/v1/transfers", request)[0])
        status, body = self.post("/v1/transfers", request)
        self.assertEqual(400, status)
        self.assertIn("used", body["error"])

    def test_malware_on_device_is_denied(self):
        chain, device_id = self.bind()
        status, body = self.post("/v1/transfers", self.signed(chain, device_id, "high", "accessibilityAbuse"))
        self.assertEqual((403, "deny"), (status, body["decision"]))

    def test_call_during_transfer_needs_step_up(self):
        chain, device_id = self.bind()
        status, body = self.post("/v1/transfers", self.signed(chain, device_id, "medium", "activeCall"))
        self.assertEqual((200, "step_up"), (status, body["decision"]))

    def test_other_key_cannot_sign_for_device(self):
        chain, device_id = self.bind()
        request = self.signed(Chain(b"x" * 32), device_id)
        status, body = self.post("/v1/transfers", request)
        self.assertEqual((403, "bad_signature"), (status, body.get("reason")))

    def test_bind_rejects_substituted_public_key(self):
        _, challenge = self.post("/v1/challenge", {"purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]))
        self.state.trusted_roots = [chain.root]
        other = Chain(b"y" * 32)
        status, body = self.post("/v1/devices", {
            "challenge": challenge["nonce"],
            "publicKey": base64.b64encode(other.public_key_der()).decode(),
            "certificateChain": chain.b64(),
        })
        self.assertEqual((403, "key_mismatch"), (status, body.get("reason")))

    def test_bind_challenge_is_single_use(self):
        _, challenge = self.post("/v1/challenge", {"purpose": "bind"})
        chain = Chain(base64.b64decode(challenge["nonce"]))
        self.state.trusted_roots = [chain.root]
        request = {"challenge": challenge["nonce"], "publicKey": base64.b64encode(chain.public_key_der()).decode(),
                   "certificateChain": chain.b64()}
        self.assertEqual(201, self.post("/v1/devices", request)[0])
        self.assertEqual(400, self.post("/v1/devices", request)[0])


if __name__ == "__main__":
    unittest.main()

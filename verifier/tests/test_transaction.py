import base64
import time
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rasp_verifier.transaction import TransactionError, decide, parse_signed_data, verify_transaction

PACKAGE = "dev.ostorlab.rasp.demo_bank"


def payload(nonce="n1", ts=None, risk="none", threats="", **fields):
    ts = int(time.time() * 1000) if ts is None else ts
    lines = ["v=rasp-tx-1", f"nonce={nonce}", f"ts={ts}", f"app={PACKAGE}", f"risk={risk}", f"threats={threats}"]
    lines += [f"f.{k}={v}" for k, v in sorted(fields.items())]
    return "\n".join(lines)


class TransactionTest(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public_der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, text: str) -> str:
        return base64.b64encode(self.key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()

    def verify(self, text, signature=None, nonce="n1"):
        return verify_transaction(text, signature or self.sign(text), self.public_der,
                                  expected_nonce=nonce, package_name=PACKAGE)

    def assert_reason(self, reason, fn):
        with self.assertRaises(TransactionError) as ctx:
            fn()
        self.assertEqual(reason, ctx.exception.reason)

    def test_valid_transaction(self):
        tx = self.verify(payload(amount="50.00", payee="Alex%0ASmith"))
        self.assertEqual({"amount": "50.00", "payee": "Alex\nSmith"}, tx.fields)
        self.assertEqual("allow", decide(tx).action)

    def test_modified_amount_fails_signature(self):
        text = payload(amount="50.00")
        signature = self.sign(text)
        self.assert_reason("bad_signature", lambda: self.verify(text.replace("50.00", "5000.00"), signature))

    def test_hidden_threat_fails_signature(self):
        text = payload(risk="high", threats="hooking")
        signature = self.sign(text)
        self.assert_reason("bad_signature", lambda: self.verify(payload(risk="none", threats=""), signature))

    def test_nonce_mismatch(self):
        self.assert_reason("nonce_mismatch", lambda: self.verify(payload(nonce="old"), nonce="n1"))

    def test_stale_timestamp(self):
        self.assert_reason("stale", lambda: self.verify(payload(ts=int((time.time() - 3600) * 1000))))

    def test_bad_format(self):
        self.assert_reason("bad_format", lambda: parse_signed_data("v=rasp-tx-0\nnonce=n"))

    def test_duplicate_field_is_rejected(self):
        text = payload(amount="1.00") + "\nf.amount=5000.00"
        self.assert_reason("bad_format", lambda: self.verify(text))

    def test_decisions(self):
        cases = {
            ("none", ""): "allow",
            ("medium", "emulator"): "step_up",
            ("medium", "activeCall"): "step_up",
            ("high", "accessibilityAbuse"): "deny",
            ("high", "hooking,root"): "deny",
            ("low", "devOptions"): "allow",
            ("medium", "detectorFailure"): "step_up",
        }
        for (risk, threats), expected in cases.items():
            with self.subTest(risk=risk, threats=threats):
                self.assertEqual(expected, decide(parse_signed_data(payload(risk=risk, threats=threats))).action)


if __name__ == "__main__":
    unittest.main()

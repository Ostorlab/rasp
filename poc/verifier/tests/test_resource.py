"""Tests for the resource-server helpers: DPoP request proofs and the risk-to-action mapping."""

import base64
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rasp_verifier import jose
from rasp_verifier import storage
from rasp_verifier.resource import ResourceError, canonical_request, decide, verify_request

from .helpers import raw_es256


def install_key():
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, base64.b64encode(der).decode(), jose.public_key_thumbprint(key.public_key())


class DpopProofs(unittest.TestCase):
    def setUp(self):
        self.signing_key = jose.SigningKey.generate()
        self.jwks = {"keys": [self.signing_key.public_jwk()]}["keys"]
        self.key, self.key_b64, self.jkt = install_key()

    def token(self, *, risk="none", signals=(), jkt=None, exp_in=120):
        now = int(time.time())
        return self.signing_key.sign_jwt({
            "iss": "rasp-trust", "aud": "rasp-resource", "sub": "install-1", "app": "com.example",
            "risk": risk, "signals": list(signals), "cnf": {"jkt": jkt or self.jkt},
            "iat": min(now, now + exp_in - 1), "exp": now + exp_in,
        })

    def request(self, token, *, method="POST", path="/v1/transfers", body=b'{"amountCents":5000}', counter=1,
                ts_ms=None, key=None, key_b64=None):
        ts = int(time.time() * 1000) if ts_ms is None else ts_ms
        sig = raw_es256(key or self.key, canonical_request(method, path, body, ts, counter))
        return dict(token=token, install_key_der_b64=key_b64 or self.key_b64, signature_b64=sig, ts_ms=ts,
                    counter=counter, method=method, path=path, body=body, jwks_keys=self.jwks)

    def test_valid_proof(self):
        verified = verify_request(**self.request(self.token()))
        self.assertEqual(verified.install_id, "install-1")
        self.assertEqual(verified.risk, "none")

    def test_body_change_breaks_the_proof(self):
        args = self.request(self.token())
        args["body"] = b'{"amountCents":999999}'  # a different amount than was signed
        with self.assertRaises(ResourceError) as cm:
            verify_request(**args)
        self.assertEqual(cm.exception.reason, "bad_proof")

    def test_path_change_breaks_the_proof(self):
        args = self.request(self.token())
        args["path"] = "/v1/admin"
        with self.assertRaises(ResourceError) as cm:
            verify_request(**args)
        self.assertEqual(cm.exception.reason, "bad_proof")

    def test_wrong_key_for_token_is_rejected(self):
        other_key, other_b64, _ = install_key()
        with self.assertRaises(ResourceError) as cm:
            verify_request(**self.request(self.token(), key=other_key, key_b64=other_b64))
        self.assertEqual(cm.exception.reason, "key_mismatch")

    def test_replayed_counter_is_rejected(self):
        args = self.request(self.token(), counter=5)
        verify_request(**args, last_counter=None)
        with self.assertRaises(ResourceError) as cm:
            verify_request(**args, last_counter=5)
        self.assertEqual(cm.exception.reason, "replayed_proof")

    def test_stale_proof_is_rejected(self):
        with self.assertRaises(ResourceError) as cm:
            verify_request(**self.request(self.token(), ts_ms=int((time.time() - 3600) * 1000)))
        self.assertEqual(cm.exception.reason, "stale_proof")

    def test_expired_token_is_rejected(self):
        with self.assertRaises(ResourceError) as cm:
            verify_request(**self.request(self.token(exp_in=-3600)))
        self.assertEqual(cm.exception.reason, "expired")

    def test_token_bound_to_a_different_key_is_rejected(self):
        # cnf.jkt names a key the client does not present.
        with self.assertRaises(ResourceError) as cm:
            verify_request(**self.request(self.token(jkt="not-our-key")))
        self.assertEqual(cm.exception.reason, "key_mismatch")

    def testRequest_whenScopeDiffers_rejectsBeforeCounterUpdate(self) -> None:
        claims = jose.decode_jwt(self.token(), self.jwks)
        claims.update({"tenant": "owner", "appId": "com.example"})
        token = self.signing_key.sign_jwt(claims)
        state = storage.MemoryStore(storage.Scope("other", "com.example"))
        with self.assertRaises(ResourceError) as caught:
            verify_request(**self.request(token), replay_store=state)
        self.assertEqual(caught.exception.reason, "wrong_scope")
        self.assertTrue(state.advance_counter("request:" + self.jkt, 1))

    def testRequest_whenSharedStoreSeesReplay_rejects(self) -> None:
        claims = jose.decode_jwt(self.token(), self.jwks)
        claims.update({"tenant": "owner", "appId": "com.example"})
        token = self.signing_key.sign_jwt(claims)
        state = storage.MemoryStore(storage.Scope("owner", "com.example"))
        request = self.request(token)
        verify_request(**request, replay_store=state)
        with self.assertRaises(ResourceError) as caught:
            verify_request(**request, replay_store=state.scoped(state.scope))
        self.assertEqual(caught.exception.reason, "replayed_proof")


class RiskMapping(unittest.TestCase):
    def test_payment_thresholds(self):
        self.assertEqual(decide("none", deny_at="high", step_up_at="medium").action, "allow")
        self.assertEqual(decide("low", deny_at="high", step_up_at="medium").action, "allow")
        self.assertEqual(decide("medium", deny_at="high", step_up_at="medium").action, "step_up")
        self.assertEqual(decide("high", deny_at="high", step_up_at="medium").action, "deny")
        self.assertEqual(decide("critical", deny_at="high", step_up_at="medium").action, "deny")

    def test_read_only_thresholds(self):
        self.assertEqual(decide("high").action, "step_up")
        self.assertEqual(decide("critical").action, "deny")


if __name__ == "__main__":
    unittest.main()

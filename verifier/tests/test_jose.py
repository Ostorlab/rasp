"""Regression tests for trust token parsing and mandatory claims."""
from __future__ import annotations

import time
import unittest

from rasp_verifier import jose


class ClaimsTest(unittest.TestCase):
    def testDecode_whenRequiredClaimsInvalid_rejects(self) -> None:
        key = jose.SigningKey.generate()
        claims = {"iss": "rasp-trust", "aud": "rasp-resource", "exp": int(time.time()) + 60}
        mutations = [{"exp": None}, {"exp": True}, {"exp": "9999999999"}, {"exp": float("inf")},
                     {"iss": "attacker"}, {"aud": "other"}, {"nbf": []}, {"iat": True}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(jose.JoseError):
                jose.decode_jwt(key.sign_jwt({**claims, **mutation}), [key.public_jwk()])
        for required in ("iss", "aud", "exp"):
            bad = dict(claims)
            del bad[required]
            with self.subTest(required=required), self.assertRaises(jose.JoseError):
                jose.decode_jwt(key.sign_jwt(bad), [key.public_jwk()])

    def testDecode_whenPayloadIsArray_rejectsCleanly(self) -> None:
        key = jose.SigningKey.generate()
        with self.assertRaises(jose.JoseError):
            jose.decode_jwt(key.sign_jwt([]), [key.public_jwk()])

    def testDecode_whenNumericDateIsHuge_rejectsCleanly(self) -> None:
        key = jose.SigningKey.generate()
        claims = {"iss": "rasp-trust", "aud": "rasp-resource", "exp": 10 ** 400}
        with self.assertRaises(jose.JoseError):
            jose.decode_jwt(key.sign_jwt(claims), [key.public_jwk()])

"""Regression tests for trust token parsing and mandatory claims."""
from __future__ import annotations

import time
import unittest

from rasp_verifier import jose


class ClaimsTest(unittest.TestCase):
    def testDecode_whenRequiredClaimsInvalid_rejects(self) -> None:
        key = jose.SigningKey.generate()
        claims = {"iss": "rasp-trust", "aud": "rasp-resource", "iat": int(time.time()), "exp": int(time.time()) + 60}
        mutations = [{"exp": None}, {"exp": True}, {"exp": "9999999999"}, {"exp": float("inf")},
                     {"iss": "attacker"}, {"aud": "other"}, {"nbf": []}, {"iat": True}, {"iat": int(time.time()) + 100}, {"exp": int(time.time()) - 1}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(jose.JoseError):
                jose.decode_jwt(key.sign_jwt({**claims, **mutation}), [key.public_jwk()])
        for required in ("iss", "aud", "exp", "iat"):
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
        claims = {"iss": "rasp-trust", "aud": "rasp-resource", "iat": int(time.time()), "exp": 10 ** 400}
        with self.assertRaises(jose.JoseError):
            jose.decode_jwt(key.sign_jwt(claims), [key.public_jwk()])


class FoundationMalformedJwtTest(unittest.TestCase):
    def testDecodeJwt_whenHeaderIsNotObject_raisesJoseError(self) -> None:
        for value in (b"[]", b"null", b'"text"', b"1", b"{"):
            with self.subTest(value=value), self.assertRaises(jose.JoseError):
                jose.decode_jwt(jose.b64u_encode(value) + ".e30.AA", [])

    def testDecodeJwt_whenSignedClaimsAreNotObject_raisesJoseError(self) -> None:
        signing_key = jose.SigningKey.generate()
        for value in ([], None, "text", 1):
            with self.subTest(value=value), self.assertRaises(jose.JoseError):
                jose.decode_jwt(signing_key.sign_jwt(value), [signing_key.public_jwk()])

    def testDecodeJwt_whenTimeClaimIsNotFiniteNumber_raisesJoseError(self) -> None:
        signing_key = jose.SigningKey.generate()
        for claim in ("exp", "nbf"):
            for value in (None, "tomorrow", [], True, float("nan"), float("inf")):
                with (
                    self.subTest(claim=claim, value=value),
                    self.assertRaises(jose.JoseError),
                ):
                    jose.decode_jwt(
                        signing_key.sign_jwt({claim: value}), [signing_key.public_jwk()]
                    )

    def testDecodeJwt_whenHeaderNestingExcessive_raisesJoseError(self) -> None:
        token = jose.b64u_encode(b"[" * 10000 + b"]" * 10000) + ".e30.AA"
        with self.assertRaises(jose.JoseError):
            jose.decode_jwt(token, [])

    def testDecodeJwt_whenExpiryIsLargeInteger_rejectsWithoutOverflow(self) -> None:
        signing_key = jose.SigningKey.generate()
        now = int(time.time())
        with self.assertRaises(jose.JoseError):
            jose.decode_jwt(signing_key.sign_jwt({"iss": "rasp-trust", "aud": "rasp-resource",
                            "iat": now, "exp": 10**1000}), [signing_key.public_jwk()], leeway=5.0)

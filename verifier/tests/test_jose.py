"""Malformed JOSE JSON must produce a controlled authentication refusal."""

import unittest

from rasp_verifier import jose


class MalformedJwtTest(unittest.TestCase):
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

    def testDecodeJwt_whenExpiryIsLargeInteger_doesNotOverflow(self) -> None:
        signing_key = jose.SigningKey.generate()
        expiry = 10**1000
        claims = jose.decode_jwt(
            signing_key.sign_jwt({"exp": expiry}),
            [signing_key.public_jwk()],
            leeway=5.0,
        )
        self.assertEqual(claims["exp"], expiry)

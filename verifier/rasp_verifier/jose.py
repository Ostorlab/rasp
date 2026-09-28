"""Minimal JOSE: ES256 JWS (compact JWTs), JWKS and RFC 7638 thumbprints.

Built on `cryptography` so the trust service adds no runtime dependency. Only ES256 (ECDSA P-256 /
SHA-256) is supported, which is what the trust service signs tokens with and what the device install key
signs proofs with. JWS uses the raw R||S signature encoding, not DER, so signatures are converted here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

P256_COORD_BYTES = 32


class JoseError(Exception):
    """A token or key is malformed, or a signature does not verify."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as e:
        raise JoseError("bad_encoding", str(e)) from e


def _der_to_raw(der_sig: bytes) -> bytes:
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(P256_COORD_BYTES, "big") + s.to_bytes(P256_COORD_BYTES, "big")


def _raw_to_der(raw_sig: bytes) -> bytes:
    if len(raw_sig) != 2 * P256_COORD_BYTES:
        raise JoseError("bad_signature", f"expected {2 * P256_COORD_BYTES} bytes, got {len(raw_sig)}")
    r = int.from_bytes(raw_sig[:P256_COORD_BYTES], "big")
    s = int.from_bytes(raw_sig[P256_COORD_BYTES:], "big")
    return encode_dss_signature(r, s)


def _require_p256(key: ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey) -> None:
    if not isinstance(key.curve, ec.SECP256R1):
        raise JoseError("bad_key", f"expected P-256, got {key.curve.name}")


def public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict:
    """The public key as a JWK (EC P-256), with the RFC 7638 thumbprint as `kid`."""
    _require_p256(public_key)
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(numbers.x.to_bytes(P256_COORD_BYTES, "big")),
        "y": b64u_encode(numbers.y.to_bytes(P256_COORD_BYTES, "big")),
    }
    return {**jwk, "kid": jwk_thumbprint(jwk), "use": "sig", "alg": "ES256"}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC public key: base64url(SHA-256 of the canonical JWK)."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u_encode(hashlib.sha256(canonical.encode()).digest())


def public_key_thumbprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """RFC 7638 thumbprint of a raw public key, used as the `cnf.jkt` claim."""
    return jwk_thumbprint(public_jwk(public_key))


def load_public_key_der(der_bytes: bytes) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_der_public_key(der_bytes)
    except (ValueError, TypeError) as e:
        raise JoseError("bad_key", str(e)) from e
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise JoseError("bad_key", "not an EC public key")
    _require_p256(key)
    return key


@dataclass
class SigningKey:
    """A trust-service token-signing key. Generate a fresh one, or load a stored PEM."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> "SigningKey":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise JoseError("bad_key", "signing key is not EC")
        _require_p256(key)
        return cls(key)

    def to_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def kid(self) -> str:
        return public_jwk(self.private_key.public_key())["kid"]

    def public_jwk(self) -> dict:
        return public_jwk(self.private_key.public_key())

    def sign_jwt(self, claims: dict) -> str:
        header = {"alg": "ES256", "typ": "JWT", "kid": self.kid}
        segments = [
            b64u_encode(json.dumps(header, separators=(",", ":")).encode()),
            b64u_encode(json.dumps(claims, separators=(",", ":")).encode()),
        ]
        signing_input = ".".join(segments).encode()
        der_sig = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        segments.append(b64u_encode(_der_to_raw(der_sig)))
        return ".".join(segments)


def jwks(keys: list[SigningKey]) -> dict:
    return {"keys": [key.public_jwk() for key in keys]}


def decode_jwt(token: str, jwks_keys: list[dict], *, now: float | None = None, leeway: float = 5) -> dict:
    """Verifies a compact ES256 JWT against a JWKS (public keys) and its `exp`. Returns the claims.

    The trust service is the only issuer, so the algorithm is pinned to ES256; a token that names any
    other algorithm, or a `kid` not in the JWKS, is refused rather than trusted.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as e:
        raise JoseError("bad_token", "a JWT has three segments") from e
    try:
        header = json.loads(b64u_decode(header_b64))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise JoseError("bad_token") from error
    if not isinstance(header, dict):
        raise JoseError("bad_token")
    if header.get("alg") != "ES256":
        raise JoseError("bad_alg", str(header.get("alg")))
    kid = header.get("kid")
    jwk = next((k for k in jwks_keys if k.get("kid") == kid), None)
    if jwk is None:
        raise JoseError("unknown_kid", str(kid))

    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64u_decode(jwk["x"]), "big"),
        int.from_bytes(b64u_decode(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        public_key.verify(_raw_to_der(b64u_decode(sig_b64)), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise JoseError("bad_signature") from e

    try:
        claims = json.loads(b64u_decode(payload_b64))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise JoseError("bad_token") from error
    if not isinstance(claims, dict):
        raise JoseError("bad_token")
    for name in ("exp", "nbf"):
        if name in claims:
            value = claims[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or (isinstance(value, float) and math.isfinite(value) is False):
                raise JoseError("bad_token")
    now = time.time() if now is None else now
    if "exp" in claims and now - leeway > claims["exp"]:
        raise JoseError("expired", f"exp={claims['exp']}")
    if "nbf" in claims and now + leeway < claims["nbf"]:
        raise JoseError("not_yet_valid", f"nbf={claims['nbf']}")
    return claims


def verify_proof(public_key: ec.EllipticCurvePublicKey, message: bytes, raw_sig_b64: str) -> None:
    """Verifies an ES256 proof (raw R||S, base64url) made by the device install key. Raises on failure."""
    try:
        public_key.verify(_raw_to_der(b64u_decode(raw_sig_b64)), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise JoseError("bad_signature") from e

"""Apple App Attest attestation and assertion verification.

The configured App ID prefix can differ from the Team ID. Trust roots are deployment-owned,
never accepted from a client. Receipts are discarded; fraud-metric retrieval and assessment are outside this verifier.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import hmac
import io
import typing

import cbor2
from cryptography import exceptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid

from rasp_verifier import der
from rasp_verifier import jose
from rasp_verifier import platform
from rasp_verifier import storage

NONCE_OID = oid.ObjectIdentifier("1.2.840.113635.100.8.2")
MAX_OBJECT_BYTES = 65536


@dataclasses.dataclass(frozen=True)
class AttestedKey:
    public_key_der: bytes
    key_id: str


def _cbor(raw: bytes) -> typing.Any:
    if len(raw) > MAX_OBJECT_BYTES:
        raise platform.PlatformAttestationError("bad_cbor")
    stream = io.BytesIO(raw)
    try:
        decoder = cbor2.CBORDecoder(stream, max_depth=8, allow_indefinite=False, allow_duplicate_keys=False)
        value = decoder.decode()
        if stream.read(1) != b"":
            raise platform.PlatformAttestationError("bad_cbor")
        return value
    except (ValueError, RecursionError, cbor2.CBORDecodeError) as error:
        raise platform.PlatformAttestationError("bad_cbor") from error


def _object(encoded: str) -> dict[str, typing.Any]:
    if not isinstance(encoded, str) or len(encoded) > MAX_OBJECT_BYTES * 2:
        raise platform.PlatformAttestationError("bad_cbor")
    try:
        value = _cbor(base64.b64decode(encoded, validate=True))
    except ValueError as error:
        raise platform.PlatformAttestationError("bad_cbor") from error
    if not isinstance(value, dict):
        raise platform.PlatformAttestationError("bad_cbor")
    return value


def _bytes(value: typing.Any) -> bytes:
    if not isinstance(value, bytes):
        raise platform.PlatformAttestationError("bad_attestation")
    return value


def _key_id(value: str) -> bytes:
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise platform.PlatformAttestationError("bad_key_id") from error
    if len(result) != 32:
        raise platform.PlatformAttestationError("bad_key_id")
    return result


def _verify_chain(chain: list[x509.Certificate], roots: list[x509.Certificate]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    root = next((root for root in roots if root.subject == chain[-1].issuer), None)
    if root is None:
        raise platform.PlatformAttestationError("untrusted_root")
    certificates = chain + [root]
    try:
        for index, certificate in enumerate(certificates):
            if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
                raise platform.PlatformAttestationError("expired_certificate")
            basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            if basic.ca != (index > 0):
                raise platform.PlatformAttestationError("bad_chain")
            if index > 0 and basic.path_length is not None and index - 1 > basic.path_length:
                raise platform.PlatformAttestationError("bad_chain")
            for extension in certificate.extensions:
                if extension.critical is True and extension.oid not in (oid.ExtensionOID.BASIC_CONSTRAINTS, oid.ExtensionOID.KEY_USAGE):
                    raise platform.PlatformAttestationError("unsupported_critical_extension")
                if extension.oid == oid.ExtensionOID.KEY_USAGE:
                    usage = extension.value
                    if index > 0 and usage.key_cert_sign is False:
                        raise platform.PlatformAttestationError("bad_chain")
                    if index == 0 and usage.digital_signature is False:
                        raise platform.PlatformAttestationError("bad_chain")
            if index < len(certificates) - 1:
                if certificate.signature_hash_algorithm is None or certificate.signature_hash_algorithm.name not in ("sha256", "sha384", "sha512"):
                    raise platform.PlatformAttestationError("bad_chain")
                certificate.verify_directly_issued_by(certificates[index + 1])
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError, TypeError, exceptions.InvalidSignature, exceptions.UnsupportedAlgorithm) as error:
        raise platform.PlatformAttestationError("bad_chain") from error


class AppAttestVerifier:
    def __init__(self, *, app_id: str, trusted_roots: list[x509.Certificate], development: bool = False) -> None:
        if len(trusted_roots) == 0 or "." not in app_id:
            raise ValueError("explicit App Attest trust roots and full App ID are required")
        self.app_id = app_id
        self.roots = trusted_roots
        self.rp_hash = hashlib.sha256(app_id.encode()).digest()
        self.aaguid = b"appattestdevelop" if development is True else b"appattest" + b"\x00" * 7

    def verify_attestation(self, encoded: str, key_id: str, client_data_hash: bytes) -> AttestedKey:
        obj = _object(encoded)
        if obj.get("fmt") != "apple-appattest" or not isinstance(obj.get("attStmt"), dict):
            raise platform.PlatformAttestationError("bad_attestation")
        statement = obj["attStmt"]
        chain_bytes = statement.get("x5c")
        if not isinstance(chain_bytes, list) or len(chain_bytes) != 2:
            raise platform.PlatformAttestationError("bad_chain")
        try:
            chain = [x509.load_der_x509_certificate(_bytes(raw)) for raw in chain_bytes]
        except ValueError as error:
            raise platform.PlatformAttestationError("bad_chain") from error
        _verify_chain(chain, self.roots)
        auth = _bytes(obj.get("authData"))
        if len(auth) < 88 or auth[:32] != self.rp_hash or auth[32] not in (0x40, 0x41):
            raise platform.PlatformAttestationError("bad_authenticator")
        if auth[33:37] != b"\x00" * 4 or auth[37:53] != self.aaguid or auth[53:55] != b"\x00\x20":
            raise platform.PlatformAttestationError("bad_authenticator")
        identifier = _key_id(key_id)
        if auth[55:87] != identifier or len(client_data_hash) != 32:
            raise platform.PlatformAttestationError("key_mismatch")
        key = chain[0].public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise platform.PlatformAttestationError("bad_key")
        public_bytes = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if hashlib.sha256(public_bytes).digest() != identifier:
            raise platform.PlatformAttestationError("key_mismatch")
        cose = _cbor(auth[87:])
        numbers = key.public_numbers()
        expected = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        if cose != expected:
            raise platform.PlatformAttestationError("key_mismatch")
        try:
            extension = chain[0].extensions.get_extension_for_oid(NONCE_OID).value
            node = der.parse(extension.value)
            context = node.children()
            if node.cls != der.UNIVERSAL or node.tag != der.SEQUENCE or len(context) != 1 or context[0].cls != der.CONTEXT or context[0].tag != 1:
                raise ValueError("bad nonce wrapper")
            octets = context[0].children()
            if len(octets) != 1 or octets[0].cls != der.UNIVERSAL or octets[0].tag != der.OCTET_STRING:
                raise ValueError("bad nonce octet string")
            nonce = octets[0].value
        except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError) as error:
            raise platform.PlatformAttestationError("bad_nonce_extension") from error
        if hmac.compare_digest(nonce, hashlib.sha256(auth + client_data_hash).digest()) is False:
            raise platform.PlatformAttestationError("nonce_mismatch")
        return AttestedKey(public_key_der=key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                           key_id=base64.b64encode(identifier).decode())

    def verify_assertion(self, encoded: str, public_key_der: bytes, key_id: str, client_data_hash: bytes,
                         state: storage.Store) -> int:
        obj = _object(encoded)
        auth = _bytes(obj.get("authenticatorData"))
        signature = _bytes(obj.get("signature"))
        if len(auth) != 37 or auth[:32] != self.rp_hash or auth[32] not in (0, 1) or len(client_data_hash) != 32:
            raise platform.PlatformAttestationError("bad_authenticator")
        key = jose.load_public_key_der(public_key_der)
        public_bytes = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if hashlib.sha256(public_bytes).digest() != _key_id(key_id):
            raise platform.PlatformAttestationError("key_mismatch")
        try:
            nonce = hashlib.sha256(auth + client_data_hash).digest()
            key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        except (exceptions.InvalidSignature, ValueError) as error:
            raise platform.PlatformAttestationError("bad_signature") from error
        counter = int.from_bytes(auth[33:37], "big")
        if state.advance_counter("appattest:" + key_id, counter) is False:
            raise platform.PlatformAttestationError("replayed_assertion")
        return counter

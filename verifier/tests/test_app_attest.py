"""Synthetic Apple-shaped attestations with independent certificate/signature generation."""
from __future__ import annotations

import base64
import concurrent.futures
import datetime
import hashlib
import unittest

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid

from rasp_verifier import app_attest
from rasp_verifier import platform
from rasp_verifier import storage
from rasp_verifier import trust
from rasp_verifier import registry
from rasp_verifier import jose
from tests import helpers

APP_ID = "TEAM123456.com.example"


def certificate(name: str, issuer: x509.Certificate | None, key: ec.EllipticCurvePrivateKey,
                signer: ec.EllipticCurvePrivateKey, ca: bool, nonce: bytes | None = None, *, expired: bool = False) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if issuer is None else issuer.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=2)).not_valid_after(now + datetime.timedelta(days=-1 if expired is True else 1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if nonce is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(oid.ObjectIdentifier("1.2.840.113635.100.8.2"),
                                                                  b"\x30\x24\xa1\x22\x04\x20" + nonce), critical=False)
    return builder.sign(signer, hashes.SHA256())


class AppleFixture:
    def __init__(self, client_hash: bytes, *, app_id: str = APP_ID, counter: int = 0,
                 aaguid: bytes = b"appattest" + b"\x00" * 7, expired: bool = False, intermediate_ca: bool = True) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        root_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.root = certificate("root", None, root_key, root_key, True)
        intermediate = certificate("intermediate", self.root, intermediate_key, root_key, intermediate_ca, expired=expired)
        key_bytes = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        key_id = hashlib.sha256(key_bytes).digest()
        self.key_id = base64.b64encode(key_id).decode()
        numbers = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        auth = hashlib.sha256(app_id.encode()).digest() + b"\x41" + counter.to_bytes(4, "big") + aaguid + b"\x00\x20" + key_id + cose
        leaf = certificate("leaf", intermediate, self.key, intermediate_key, False, hashlib.sha256(auth + client_hash).digest())
        self.object = {"fmt": "apple-appattest", "attStmt": {"x5c": [leaf.public_bytes(serialization.Encoding.DER), intermediate.public_bytes(serialization.Encoding.DER)], "receipt": b"receipt"}, "authData": auth}

    def encoded(self) -> str:
        return base64.b64encode(cbor2.dumps(self.object)).decode()

    def assertion(self, client_hash: bytes, counter: int = 1, app_id: str = APP_ID) -> str:
        auth = hashlib.sha256(app_id.encode()).digest() + b"\x00" + counter.to_bytes(4, "big")
        signature = self.key.sign(auth + client_hash, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(cbor2.dumps({"signature": signature, "authenticatorData": auth})).decode()


class AppleVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client_hash = hashlib.sha256(b"nonce").digest()
        self.fixture = AppleFixture(self.client_hash)
        self.verifier = app_attest.AppAttestVerifier(app_id=APP_ID, trusted_roots=[self.fixture.root])

    def testAttestation_whenValid_verifiesKey(self) -> None:
        result = self.verifier.verify_attestation(self.fixture.encoded(), self.fixture.key_id, self.client_hash)
        self.assertEqual(result.public_key_der, self.fixture.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    def testAttestation_whenIdentityOrNonceChanges_rejects(self) -> None:
        for field, value in (("app_id", "OTHER.com.example"), ("counter", 1), ("aaguid", b"appattestdevelop")):
            fixture = AppleFixture(self.client_hash, **{field: value})
            verifier = app_attest.AppAttestVerifier(app_id=APP_ID, trusted_roots=[fixture.root])
            with self.subTest(field=field), self.assertRaises(platform.PlatformAttestationError):
                verifier.verify_attestation(fixture.encoded(), fixture.key_id, self.client_hash)
        for key_id, client_hash in ((base64.b64encode(b"x" * 32).decode(), self.client_hash), (self.fixture.key_id, b"x" * 32)):
            with self.assertRaises(platform.PlatformAttestationError):
                self.verifier.verify_attestation(self.fixture.encoded(), key_id, client_hash)

    def testAttestation_whenChainIsUntrustedOrModified_rejects(self) -> None:
        other = AppleFixture(self.client_hash)
        with self.assertRaises(platform.PlatformAttestationError):
            self.verifier.verify_attestation(other.encoded(), other.key_id, self.client_hash)
        self.fixture.object["attStmt"]["x5c"][0] = self.fixture.object["attStmt"]["x5c"][0][:-1] + b"\x00"
        with self.assertRaises(platform.PlatformAttestationError):
            self.verifier.verify_attestation(self.fixture.encoded(), self.fixture.key_id, self.client_hash)

    def testAttestation_whenCborMalformedOrOversized_rejects(self) -> None:
        for raw in (b"\xa1", b"\x81" * 100 + b"\x00", cbor2.dumps(self.fixture.object) + b"\x00", b"x" * 70000, b"\xa2\x61a\x01\x61a\x02"):
            with self.subTest(length=len(raw)), self.assertRaises(platform.PlatformAttestationError):
                self.verifier.verify_attestation(base64.b64encode(raw).decode(), self.fixture.key_id, self.client_hash)

    def testAssertion_whenReplayedOrSubstituted_rejects(self) -> None:
        attested = self.verifier.verify_attestation(self.fixture.encoded(), self.fixture.key_id, self.client_hash)
        state = storage.MemoryStore()
        self.verifier.verify_assertion(self.fixture.assertion(self.client_hash), attested.public_key_der,
                                       self.fixture.key_id, self.client_hash, state)
        for assertion, client_hash in ((self.fixture.assertion(self.client_hash), self.client_hash),
                                       (self.fixture.assertion(self.client_hash, 2), b"x" * 32),
                                       (self.fixture.assertion(self.client_hash, 2, "other.app"), self.client_hash)):
            with self.assertRaises(platform.PlatformAttestationError):
                self.verifier.verify_assertion(assertion, attested.public_key_der, self.fixture.key_id, client_hash, state)
        self.verifier.verify_assertion(self.fixture.assertion(self.client_hash, 2), attested.public_key_der,
                                       self.fixture.key_id, self.client_hash, state)
    def testAttestation_whenIntermediateExpiredOrNotCa_rejects(self) -> None:
        for options in ({"expired": True}, {"intermediate_ca": False}):
            fixture = AppleFixture(self.client_hash, **options)
            verifier = app_attest.AppAttestVerifier(app_id=APP_ID, trusted_roots=[fixture.root])
            with self.subTest(options=options), self.assertRaises(platform.PlatformAttestationError):
                verifier.verify_attestation(fixture.encoded(), fixture.key_id, self.client_hash)

    def testAssertion_whenRaced_acceptsOnlyOnce(self) -> None:
        attested = self.verifier.verify_attestation(self.fixture.encoded(), self.fixture.key_id, self.client_hash)
        state = storage.MemoryStore()
        assertion = self.fixture.assertion(self.client_hash)
        def verify_once(_: int) -> bool:
            try:
                self.verifier.verify_assertion(assertion, attested.public_key_der, self.fixture.key_id, self.client_hash, state)
                return True
            except platform.PlatformAttestationError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(sum(executor.map(verify_once, range(20))), 1)


class IosTrustTest(unittest.TestCase):
    def testIos_whenBoundAndAsserted_issuesSessionTokenWithoutBiometricClaim(self) -> None:
        service = trust.TrustService(signing_key=jose.SigningKey.generate(), package_name=helpers.PACKAGE,
            signing_cert_sha256=[helpers.APP_CERT_SHA256], builds=registry.BuildRegistry([
                registry.Build(helpers.BUILD_ID, helpers.BUILD_KEY, helpers.PACKAGE, [helpers.APP_CERT_SHA256])]))
        nonce = service.challenge("ios-install", "ios-bind")["nonce"]
        fixture = AppleFixture(hashlib.sha256(nonce.encode()).digest(), app_id="TEAM123456." + helpers.PACKAGE)
        service.app_attest = app_attest.AppAttestVerifier(app_id="TEAM123456." + helpers.PACKAGE, trusted_roots=[fixture.root])
        bound = service.bind_ios({"installId": "ios-install", "nonce": nonce, "keyId": fixture.key_id, "attestationObject": fixture.encoded()})
        self.assertFalse(bound["userAuthRequired"])
        nonce = service.challenge("ios-install", "ios-token")["nonce"]
        sealed = helpers.seal_report(nonce)
        session_key, session_b64 = helpers.session_keypair()
        message = trust.token_proof_message(nonce, sealed["mac"], jose.public_key_thumbprint(session_key.public_key()))
        assertion = fixture.assertion(hashlib.sha256(message).digest(), app_id="TEAM123456." + helpers.PACKAGE)
        body = {"installId": "ios-install", "nonce": nonce, "keyId": fixture.key_id, "assertion": assertion,
                "sessionPublicKey": session_b64, "sealedReport": sealed}
        issued = service.token_ios(body)
        claims = jose.decode_jwt(issued["token"], service.jwks()["keys"])
        self.assertFalse(claims["uauth"])
        self.assertEqual(claims["sec"], "app_attest")
        self.assertEqual(claims["risk"], "none")
        with self.assertRaises(trust.TrustError):
            service.token_ios(body)
        # App Attest installs must not enter the Android proof flow.
        android_nonce = service.challenge("ios-install", "token")["nonce"]
        with self.assertRaises(trust.TrustError):
            service.token({**body, "nonce": android_nonce})

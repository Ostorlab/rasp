"""Builds synthetic Android Key Attestation chains for tests."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from rasp_verifier.attestation import KEY_DESCRIPTION_OID

APP_CERT = b"demo-bank-signing-certificate"
APP_CERT_SHA256 = hashlib.sha256(APP_CERT).hexdigest()
PACKAGE = "dev.ostorlab.rasp.demo_bank"


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag_byte: int, value: bytes) -> bytes:
    return bytes([tag_byte]) + _len(len(value)) + value


def integer(n: int) -> bytes:
    return tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def enum(n: int) -> bytes:
    return tlv(0x0A, bytes([n]))


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def explicit(tag: int, value: bytes) -> bytes:
    """Context-specific, constructed, explicit tag; high-tag-number form above 30."""
    if tag < 31:
        return tlv(0xA0 | tag, value)
    groups = []
    while True:
        groups.insert(0, tag & 0x7F)
        tag >>= 7
        if not tag:
            break
    encoded = bytes([g | 0x80 for g in groups[:-1]] + [groups[-1]])
    return bytes([0xBF]) + encoded + _len(len(value)) + value


def key_description(
    challenge: bytes,
    *,
    security_level: int = 1,
    package: str = PACKAGE,
    app_cert_sha256: str = APP_CERT_SHA256,
    boot_state: int = 0,
    locked: bool = True,
) -> bytes:
    app_id = seq(set_of(seq(octets(package.encode()), integer(1))), set_of(octets(bytes.fromhex(app_cert_sha256))))
    software = seq(explicit(709, octets(app_id)))
    hardware = seq(
        explicit(704, seq(octets(b"\x11" * 32), boolean(locked), enum(boot_state), octets(b"\x22" * 32))),
        explicit(706, integer(202609)),
    )
    return seq(integer(300), enum(security_level), integer(300), enum(security_level), octets(challenge),
               octets(b""), software, hardware)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public_key, signing_key, *, ca: bool, extension: bytes | None = None, serial: int | None = None,
          not_after: dt.datetime | None = None):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(not_after or now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if extension is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, extension), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


class Chain:
    """root -> intermediate -> leaf, where the leaf is the attested device key."""

    def __init__(self, challenge: bytes, *, intermediate_serial: int | None = None,
                 intermediate_not_after: dt.datetime | None = None, **kd):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert("Test Root", "Test Root", self.root_key.public_key(), self.root_key, ca=True)
        self.intermediate = _cert("Test Intermediate", "Test Root", self.intermediate_key.public_key(), self.root_key,
                                  ca=True, serial=intermediate_serial, not_after=intermediate_not_after)
        self.leaf = _cert("Android Keystore Key", "Test Intermediate", self.device_key.public_key(),
                          self.intermediate_key, ca=False, extension=key_description(challenge, **kd))

    def b64(self) -> list[str]:
        return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                for c in (self.leaf, self.intermediate, self.root)]

    def public_key_der(self) -> bytes:
        return self.device_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

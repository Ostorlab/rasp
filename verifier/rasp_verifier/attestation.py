"""Android Key Attestation verification, used when a device is bound.

References: https://developer.android.com/privacy-and-security/security-key-attestation
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from importlib import resources

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from . import der

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# AuthorizationList tags used here.
TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_AUTH_TIMEOUT = 505
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709

SECURITY_LEVELS = {0: "software", 1: "tee", 2: "strongbox"}
BOOT_STATES = {0: "verified", 1: "self_signed", 2: "unverified", 3: "failed"}


class AttestationError(Exception):
    """The attestation must not be trusted. `reason` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class AttestationResult:
    security_level: str
    attestation_version: int
    trusted_root: bool
    package_names: list[str]
    signing_cert_digests: list[str]
    verified_boot_state: str | None
    device_locked: bool | None
    os_patch_level: int | None
    user_auth_required: bool
    public_key_der: bytes
    warnings: list[str] = field(default_factory=list)

    @property
    def hardware_backed(self) -> bool:
        return self.security_level in ("tee", "strongbox")


def load_google_roots() -> list[x509.Certificate]:
    """Google's published attestation roots (RSA legacy root and the EC P-384 root used from February 2026)."""
    pems = json.loads(resources.files(__package__).joinpath("google_roots.json").read_text())
    return [x509.load_pem_x509_certificate(pem.encode()) for pem in pems]


def load_revocations(status_json: dict) -> dict[str, str]:
    """Parses https://android.googleapis.com/attestation/status into {serial_hex: status}."""
    return {serial.lower(): entry.get("status", "REVOKED") for serial, entry in status_json.get("entries", {}).items()}


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    except x509.ExtensionNotFound:
        return True


def _has_key_description(cert: x509.Certificate) -> bool:
    try:
        cert.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
        return True
    except x509.ExtensionNotFound:
        return False


def _authorization_list(node: der.Node) -> dict[int, der.Node]:
    """Maps each explicit [tag] to its inner value."""
    out = {}
    for item in node.children():
        if item.cls != der.CONTEXT:
            raise AttestationError("bad_extension", "authorization list entry is not context-tagged")
        inner = item.children()
        if len(inner) != 1:
            raise AttestationError("bad_extension", f"tag {item.tag} holds {len(inner)} values")
        out[item.tag] = inner[0]
    return out


def _application_id(value: der.Node) -> tuple[list[str], list[str]]:
    """Decodes AttestationApplicationId: the package names and signing-certificate SHA-256 digests of the app."""
    seq = der.parse(value.value).children()
    if len(seq) != 2:
        raise AttestationError("bad_extension", "attestationApplicationId must have two fields")
    packages = [info.children()[0].value.decode() for info in seq[0].children()]
    digests = [digest.value.hex() for digest in seq[1].children()]
    return packages, digests


def verify_key_attestation(
    chain_b64: list[str],
    challenge: bytes,
    package_name: str,
    signing_cert_sha256: list[str],
    *,
    require_hardware: bool = True,
    require_user_auth: bool = False,
    trusted_roots: list[x509.Certificate] | None = None,
    revocations: dict[str, str] | None = None,
    now: dt.datetime | None = None,
) -> AttestationResult:
    """Verifies a Key Attestation chain (leaf first) for a key generated with `challenge`.

    Checks, in order: chain structure, chain signatures and validity, root, revocation, challenge, app identity
    (package name and signing certificate, which stops relaying the challenge to another app or phone), the security
    level, and optionally that every use of the key needs the user (biometric or device credential).
    """
    if len(chain_b64) < 2:
        raise AttestationError("bad_chain", "need at least a leaf and a root")
    try:
        chain = [x509.load_der_x509_certificate(base64.b64decode(item)) for item in chain_b64]
    except ValueError as e:
        raise AttestationError("bad_chain", str(e)) from e
    now = now or dt.datetime.now(dt.timezone.utc)

    # Structure. The attested key is a signing key: code that controls it can sign an extra certificate "below" the
    # real leaf and put any claims in it. So only the leaf may carry the key description, the leaf must not be a CA,
    # and every certificate above it must be a CA.
    if _is_ca(chain[0]):
        raise AttestationError("bad_chain", "the attested leaf is a CA certificate")
    if not _has_key_description(chain[0]):
        raise AttestationError("no_attestation", "leaf has no key description extension")
    for cert in chain[1:]:
        if _has_key_description(cert):
            raise AttestationError("bad_chain", f"{cert.subject.rfc4514_string()} carries a key description")
        if not _is_ca(cert):
            raise AttestationError("bad_chain", f"{cert.subject.rfc4514_string()} is not a CA")

    for child, issuer in zip(chain, chain[1:]):
        try:
            child.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise AttestationError("bad_chain", f"{child.subject.rfc4514_string()} is not signed by its issuer") from e
    # The leaf's validity is set by the device and is often meaningless; check the issuing certificates only.
    for cert in chain[1:]:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise AttestationError("expired_chain", cert.subject.rfc4514_string())

    roots = trusted_roots if trusted_roots is not None else load_google_roots()
    trusted_root = _spki(chain[-1]) in {_spki(root) for root in roots}
    if require_hardware and not trusted_root:
        raise AttestationError("untrusted_root", chain[-1].subject.rfc4514_string())

    for cert in chain:
        status = (revocations or {}).get(format(cert.serial_number, "x"))
        if status:
            raise AttestationError("revoked", f"serial {cert.serial_number:x} is {status}")

    try:
        extension = chain[0].extensions.get_extension_for_oid(KEY_DESCRIPTION_OID).value
    except x509.ExtensionNotFound as e:
        raise AttestationError("no_attestation", "leaf has no key description extension") from e
    try:
        fields = der.parse(extension.value).children()
        attestation_version = fields[0].as_int()
        security_level = SECURITY_LEVELS.get(fields[1].as_int(), "unknown")
        attested_challenge = fields[4].value
        software = _authorization_list(fields[6])
        hardware = _authorization_list(fields[7])
    except (der.DerError, IndexError) as e:
        raise AttestationError("bad_extension", str(e)) from e

    if not hmac.compare_digest(attested_challenge, challenge):
        raise AttestationError("challenge_mismatch")

    app_id = software.get(TAG_ATTESTATION_APPLICATION_ID) or hardware.get(TAG_ATTESTATION_APPLICATION_ID)
    if app_id is None:
        raise AttestationError("no_application_id")
    packages, digests = _application_id(app_id)
    if package_name not in packages:
        raise AttestationError("wrong_package", ", ".join(packages))
    expected = {d.replace(":", "").lower() for d in signing_cert_sha256}
    if not expected or not set(digests) & expected:
        raise AttestationError("wrong_signer", ", ".join(digests))

    boot_state = device_locked = os_patch = None
    warnings = []
    root_of_trust = hardware.get(TAG_ROOT_OF_TRUST)
    if root_of_trust is not None:
        rot = root_of_trust.children()
        device_locked = rot[1].as_bool()
        boot_state = BOOT_STATES.get(rot[2].as_int(), "unknown")
    if TAG_OS_PATCH_LEVEL in hardware:
        os_patch = hardware[TAG_OS_PATCH_LEVEL].as_int()
    # Per-use user authentication: no "no auth required" tag, a user-auth type, and no timeout (a timeout would let
    # one unlock cover later signatures). Only the hardware-enforced list counts, except in lenient (emulator) mode.
    auth_tags = hardware if require_hardware else {**software, **hardware}
    user_auth = (
        TAG_NO_AUTH_REQUIRED not in auth_tags
        and TAG_USER_AUTH_TYPE in auth_tags
        and auth_tags[TAG_USER_AUTH_TYPE].as_int() != 0
        and (TAG_AUTH_TIMEOUT not in auth_tags or auth_tags[TAG_AUTH_TIMEOUT].as_int() == 0)
    )
    if require_user_auth and not user_auth:
        raise AttestationError("no_user_auth", "the key can be used without the user")

    if require_hardware:
        if security_level not in ("tee", "strongbox"):
            raise AttestationError("software_key", f"attestation security level is {security_level}")
        if boot_state != "verified" or not device_locked:
            raise AttestationError("unlocked_device", f"boot state {boot_state}, locked={device_locked}")
    else:
        if not trusted_root:
            warnings.append("untrusted_root")
        if security_level == "software":
            warnings.append("software_key")

    return AttestationResult(
        security_level=security_level,
        attestation_version=attestation_version,
        trusted_root=trusted_root,
        package_names=packages,
        signing_cert_digests=digests,
        verified_boot_state=boot_state,
        device_locked=device_locked,
        os_patch_level=os_patch,
        user_auth_required=user_auth,
        public_key_der=_spki(chain[0]),
        warnings=warnings,
    )


def cert_sha256(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()

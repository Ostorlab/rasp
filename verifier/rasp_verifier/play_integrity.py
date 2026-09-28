"""Google Play Integrity standard-request verification using Google's OAuth decode API."""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
import typing

import google.auth
from google.auth import exceptions as auth_exceptions
from google.auth.transport import requests as auth_requests
import requests

from rasp_verifier import platform

SCOPE = "https://www.googleapis.com/auth/playintegrity"


class GoogleOAuthDecoder:
    def __init__(self) -> None:
        credentials, _ = google.auth.default(scopes=[SCOPE])
        self.session = auth_requests.AuthorizedSession(credentials, refresh_timeout=10, max_refresh_attempts=1)

    def __call__(self, token: str, package_name: str) -> dict[str, typing.Any]:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package_name) is None:
            raise platform.PlatformAttestationError("wrong_package")
        url = f"https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"
        try:
            with self.session.post(url, json={"integrity_token": token}, timeout=10, allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise platform.PlatformAttestationError("google_unavailable")
                # Bound decompressed response bytes before parsing (Content-Length is not trusted).
                content = bytearray()
                for chunk in response.iter_content(chunk_size=16384):
                    content.extend(chunk)
                    if len(content) > 262144:
                        raise platform.PlatformAttestationError("bad_payload")
                decoded = json.loads(content)
                if not isinstance(decoded, dict):
                    raise platform.PlatformAttestationError("bad_payload")
                return decoded
        except (requests.RequestException, auth_exceptions.GoogleAuthError, ValueError) as error:
            raise platform.PlatformAttestationError("google_unavailable") from error


def _object(value: typing.Any) -> dict[str, typing.Any]:
    if not isinstance(value, dict):
        raise platform.PlatformAttestationError("bad_payload")
    return value


def _integer(value: typing.Any) -> int:
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and len(value) <= 20 and value.isascii() and value.isdecimal():
        return int(value)
    raise platform.PlatformAttestationError("bad_payload")


class GooglePlayIntegrityAttestation(platform.PlatformAttestation):
    def __init__(self, *, signing_cert_sha256: list[str], versions: set[int] | None = None,
                 require_licensed: bool = True, max_age_seconds: int = 120,
                 decoder: typing.Callable[[str, str], dict[str, typing.Any]] | None = None) -> None:
        self.certificates = {bytes.fromhex(digest) for digest in signing_cert_sha256}
        if len(self.certificates) == 0 or any(len(digest) != 32 for digest in self.certificates):
            raise ValueError("expected SHA-256 application signing certificates")
        self.versions = versions
        self.require_licensed = require_licensed
        self.max_age_seconds = max_age_seconds
        self.decoder = GoogleOAuthDecoder() if decoder is None else decoder

    def verify(self, token: str, *, request_hash: bytes, package_name: str) -> platform.PlatformVerdict:
        if not isinstance(token, str) or len(token) == 0 or len(token) > 131072:
            raise platform.PlatformAttestationError("bad_token")
        try:
            payload = _object(_object(self.decoder(token, package_name)).get("tokenPayloadExternal"))
        except OSError as error:
            raise platform.PlatformAttestationError("google_unavailable") from error
        details = _object(payload.get("requestDetails"))
        if details.get("requestPackageName") != package_name:
            raise platform.PlatformAttestationError("wrong_package")
        # requestHash is developer-defined, returned verbatim. Accept the two documented SDK encodings.
        expected = {base64.b64encode(request_hash).decode(), base64.urlsafe_b64encode(request_hash).decode().rstrip("=")}
        if not isinstance(details.get("requestHash"), str) or details["requestHash"] not in expected:
            raise platform.PlatformAttestationError("request_hash_mismatch")
        age_ms = time.time() * 1000 - _integer(details.get("timestampMillis"))
        if age_ms < -5000 or age_ms > self.max_age_seconds * 1000:
            raise platform.PlatformAttestationError("stale_token")
        app = _object(payload.get("appIntegrity"))
        if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED" or app.get("packageName") != package_name:
            raise platform.PlatformAttestationError("unrecognized_app")
        presented = app.get("certificateSha256Digest")
        if not isinstance(presented, list) or len(presented) == 0:
            raise platform.PlatformAttestationError("wrong_certificate")
        try:
            certificates = {base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True) for value in presented}
        except (ValueError, TypeError, binascii.Error) as error:
            raise platform.PlatformAttestationError("wrong_certificate") from error
        if certificates != self.certificates:
            raise platform.PlatformAttestationError("wrong_certificate")
        version = _integer(app.get("versionCode"))
        if self.versions is not None and version not in self.versions:
            raise platform.PlatformAttestationError("wrong_version")
        if self.require_licensed is True and _object(payload.get("accountDetails")).get("appLicensingVerdict") != "LICENSED":
            raise platform.PlatformAttestationError("unlicensed_app")
        labels = _object(payload.get("deviceIntegrity", {})).get("deviceRecognitionVerdict", [])
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise platform.PlatformAttestationError("bad_payload")
        verdict = "NONE"
        for label, tier in (("MEETS_STRONG_INTEGRITY", "STRONG"), ("MEETS_DEVICE_INTEGRITY", "DEVICE"), ("MEETS_BASIC_INTEGRITY", "BASIC")):
            if label in labels:
                verdict = tier
                break
        return platform.PlatformVerdict(verdict=verdict, app_recognized=True, raw=payload)

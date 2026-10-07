"""Google-decoded payload validation, never trusting the supplied token itself."""
from __future__ import annotations

import base64
import copy
import hashlib
import time
import unittest

from rasp_verifier import platform
from rasp_verifier import play_integrity


class GoogleVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = hashlib.sha256(b"challenge").digest()
        self.cert = b"a" * 32
        self.payload = {"tokenPayloadExternal": {
            "requestDetails": {"requestPackageName": "com.example", "requestHash": base64.b64encode(self.digest).decode(),
                               "timestampMillis": str(int(time.time() * 1000))},
            "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": "com.example",
                             "certificateSha256Digest": [base64.urlsafe_b64encode(self.cert).decode().rstrip("=")], "versionCode": "42"},
            "accountDetails": {"appLicensingVerdict": "LICENSED"},
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]}}}

    def verify(self) -> platform.PlatformVerdict:
        adapter = play_integrity.GooglePlayIntegrityAttestation(
            signing_cert_sha256=[self.cert.hex()], versions={42}, decoder=lambda token, package: self.payload)
        return adapter.verify("opaque-google-token", request_hash=self.digest, package_name="com.example")

    def testGoogle_whenResponseMatches_returnsStrong(self) -> None:
        self.assertEqual(self.verify().verdict, "STRONG")

    def testGoogle_whenAnyBindingIsWrong_rejects(self) -> None:
        mutations = [("requestDetails", "requestPackageName", "other.app"), ("requestDetails", "requestHash", "wrong"),
                     ("requestDetails", "timestampMillis", "0"), ("requestDetails", "timestampMillis", str(int(time.time() * 1000) + 60000)),
                     ("requestDetails", "timestampMillis", True), ("appIntegrity", "packageName", "other.app"),
                     ("appIntegrity", "certificateSha256Digest", []), ("appIntegrity", "certificateSha256Digest", ["Yg"]),
                     ("appIntegrity", "versionCode", "43"), ("appIntegrity", "appRecognitionVerdict", "UNEVALUATED"),
                     ("accountDetails", "appLicensingVerdict", "UNLICENSED")]
        original = copy.deepcopy(self.payload)
        for section, field, value in mutations:
            self.payload = copy.deepcopy(original)
            self.payload["tokenPayloadExternal"][section][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(platform.PlatformAttestationError):
                self.verify()

    def testGoogle_whenPayloadMalformed_failsClosed(self) -> None:
        for invalid in ([], None, {}, {"tokenPayloadExternal": []}, {"tokenPayloadExternal": {"requestDetails": None}}):
            self.payload = invalid
            with self.subTest(invalid=invalid), self.assertRaises(platform.PlatformAttestationError):
                self.verify()

    def testGoogle_whenNoDeviceVerdict_returnsNone(self) -> None:
        self.payload["tokenPayloadExternal"]["deviceIntegrity"] = {}
        self.assertEqual(self.verify().verdict, "NONE")

    def testGoogle_whenTransportFails_rejects(self) -> None:
        def unavailable(token: str, package: str) -> dict:
            raise OSError("offline")
        adapter = play_integrity.GooglePlayIntegrityAttestation(signing_cert_sha256=[self.cert.hex()], decoder=unavailable)
        with self.assertRaises(platform.PlatformAttestationError):
            adapter.verify("token", request_hash=self.digest, package_name="com.example")

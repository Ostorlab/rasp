"""Real signature and replay tests for the ELF authorizer."""

from __future__ import annotations

import concurrent.futures
import hashlib
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from rasp_elf import backend
    from rasp_elf import protocol
except ImportError:
    backend = None
    protocol = None


class AuthorizerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(protocol, "signed ELF protocol is not implemented")
        self.assertIsNotNone(backend, "ELF authorizer is not implemented")
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.client = ed25519.Ed25519PrivateKey.generate()
        self.server_key = ed25519.Ed25519PrivateKey.generate()
        self.manifest_values = {
            "v": "rasp-elf-manifest-1",
            "build": "ab" * 32,
            "exe": "cd" * 32,
            "runtime": "ef" * 32,
            "endpoint": "http://127.0.0.1:8788",
            "interval_ms": "250",
            "client_public": protocol.public_hex(self.client),
            "server_public": protocol.public_hex(self.server_key),
        }
        self.manifest = protocol.sign_message(self.manifest_values, self.publisher)
        self.authorizer = backend.Authorizer(self.server_key, protocol.public_hex(self.publisher))
        self.authorizer.register(self.manifest)

    def evidence(self, nonce: str, **changes: str) -> bytes:
        values = {
            "v": "rasp-elf-evidence-1",
            "build": "ab" * 32,
            "nonce": nonce,
            "pid": "123",
            "exe": "cd" * 32,
            "runtime": "ef" * 32,
            "threats": "none",
            "operation": "startup",
            "request": hashlib.sha256(b"").hexdigest(),
        }
        values.update(changes)
        return protocol.sign_message(values, self.client)

    def testAuthorizer_whenCleanEvidence_returnsBoundSignedAllow(self) -> None:
        nonce = self.authorizer.challenge("ab" * 32)
        evidence = self.evidence(nonce)
        decision = self.authorizer.authorize(evidence)
        fields, signed = protocol.verify_message(
            decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS
        )
        self.assertEqual("allow", fields["action"])
        self.assertEqual(nonce, fields["nonce"])
        self.assertEqual(hashlib.sha256(evidence.rsplit(b"signature=", 1)[0]).hexdigest(), fields["evidence"])
        self.assertGreater(int(fields["expires"]), time.time())
        self.assertGreater(len(signed), 0)

    def testAuthorizer_whenEvidenceReplayed_rejectsSecondUse(self) -> None:
        message = self.evidence(self.authorizer.challenge("ab" * 32))
        self.authorizer.authorize(message)
        with self.assertRaisesRegex(ValueError, "challenge"):
            self.authorizer.authorize(message)

    def testAuthorizer_whenConcurrentReplay_allowsExactlyOne(self) -> None:
        message = self.evidence(self.authorizer.challenge("ab" * 32))

        def attempt(_: int) -> bool:
            try:
                self.authorizer.authorize(message)
                return True
            except ValueError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(1, sum(outcomes))

    def testAuthorizer_whenFileHashWrong_returnsDeny(self) -> None:
        message = self.evidence(self.authorizer.challenge("ab" * 32), exe="11" * 32)
        fields, _ = protocol.verify_message(
            self.authorizer.authorize(message), protocol.public_hex(self.server_key), protocol.DECISION_FIELDS
        )
        self.assertEqual("deny", fields["action"])

    def testAuthorizer_whenThreatReported_returnsDeny(self) -> None:
        for threat in ("tamper", "debugger", "preload", "detectorFailure"):
            with self.subTest(threat=threat):
                message = self.evidence(self.authorizer.challenge("ab" * 32), threats=threat)
                fields, _ = protocol.verify_message(
                    self.authorizer.authorize(message), protocol.public_hex(self.server_key), protocol.DECISION_FIELDS
                )
                self.assertEqual("deny", fields["action"])

    def testAuthorizer_whenSignatureForged_rejectsAndConsumesNonce(self) -> None:
        nonce = self.authorizer.challenge("ab" * 32)
        message = self.evidence(nonce)
        forged = message.replace(b"pid=123", b"pid=124")
        with self.assertRaisesRegex(ValueError, "signature"):
            self.authorizer.authorize(forged)
        with self.assertRaisesRegex(ValueError, "challenge"):
            self.authorizer.authorize(message)

    def testAuthorizer_whenChallengeExpired_rejectsEvidence(self) -> None:
        clock = [100.0]
        authorizer = backend.Authorizer(self.server_key, protocol.public_hex(self.publisher), clock=lambda: clock[0])
        authorizer.register(self.manifest)
        nonce = authorizer.challenge("ab" * 32)
        clock[0] += 31
        with self.assertRaisesRegex(ValueError, "challenge"):
            authorizer.authorize(self.evidence(nonce))

    def testAuthorizer_whenChallengeCapacityReached_refusesUntilExpiry(self) -> None:
        clock = [100.0]
        authorizer = backend.Authorizer(
            self.server_key, protocol.public_hex(self.publisher), clock=lambda: clock[0], max_challenges=2
        )
        authorizer.register(self.manifest)
        authorizer.challenge("ab" * 32)
        authorizer.challenge("ab" * 32)
        with self.assertRaisesRegex(ValueError, "capacity"):
            authorizer.challenge("ab" * 32)
        clock[0] += 31
        self.assertEqual(64, len(authorizer.challenge("ab" * 32)))

    def testAuthorizer_whenBuildUnknown_refusesChallenge(self) -> None:
        with self.assertRaisesRegex(ValueError, "build"):
            self.authorizer.challenge("00" * 32)

    def testAuthorizer_whenNonceBoundToAnotherBuild_rejectsEvidence(self) -> None:
        other = self.manifest_values | {"build": "12" * 32}
        self.authorizer.register(protocol.sign_message(other, self.publisher))
        nonce = self.authorizer.challenge("12" * 32)
        with self.assertRaisesRegex(ValueError, "challenge"):
            self.authorizer.authorize(self.evidence(nonce))

    def testAuthorizer_whenCustomerNeedsStepUp_returnsSignedStepUp(self) -> None:
        authorizer = backend.Authorizer(
            self.server_key, protocol.public_hex(self.publisher), policy=lambda evidence: "step_up"
        )
        authorizer.register(self.manifest)
        fields, _ = protocol.verify_message(
            authorizer.authorize(self.evidence(authorizer.challenge("ab" * 32))),
            protocol.public_hex(self.server_key),
            protocol.DECISION_FIELDS,
        )
        self.assertEqual("step_up", fields["action"])

    def testAuthorizer_whenPolicyThrows_returnsDeny(self) -> None:
        def broken(evidence: backend.Evidence) -> str:
            raise RuntimeError("customer service unavailable")

        authorizer = backend.Authorizer(self.server_key, protocol.public_hex(self.publisher), policy=broken)
        authorizer.register(self.manifest)
        fields, _ = protocol.verify_message(
            authorizer.authorize(self.evidence(authorizer.challenge("ab" * 32))),
            protocol.public_hex(self.server_key),
            protocol.DECISION_FIELDS,
        )
        self.assertEqual("deny", fields["action"])

    def testProtocol_whenManifestChanged_rejectsRegistration(self) -> None:
        with self.assertRaisesRegex(ValueError, "signature"):
            self.authorizer.register(self.manifest.replace(b"interval_ms=250", b"interval_ms=251"))

    def testProtocol_whenFieldsDuplicated_rejectsMessage(self) -> None:
        message = self.evidence(self.authorizer.challenge("ab" * 32))
        with self.assertRaises(ValueError):
            self.authorizer.authorize(message.replace(b"pid=123\n", b"pid=123\npid=123\n"))

    def testProtocol_whenUnknownThreat_rejectsEvidence(self) -> None:
        message = self.evidence(self.authorizer.challenge("ab" * 32), threats="clean")
        with self.assertRaisesRegex(ValueError, "threat"):
            self.authorizer.authorize(message)

    def testProtocol_whenUnsafeEndpoint_rejectsManifest(self) -> None:
        for endpoint in ("http://example.com:80", "http://127.0.0.1:80/path", "https://user@host:443", "ftp://host:80"):
            with self.subTest(endpoint=endpoint):
                values = self.manifest_values | {"endpoint": endpoint}
                with self.assertRaises(ValueError):
                    self.authorizer.register(protocol.sign_message(values, self.publisher))

    def testProtocol_whenWrongSigningAuthority_rejectsManifest(self) -> None:
        with self.assertRaisesRegex(ValueError, "signature"):
            self.authorizer.register(protocol.sign_message(self.manifest_values, self.client))

    def testAuthorizer_whenSignedMetadataInvalid_rejectsEvidence(self) -> None:
        changes = (
            {"pid": "0"},
            {"pid": "abc"},
            {"pid": "9" * 20},
            {"v": "wrong"},
            {"operation": "unknown"},
            {"request": "invalid"},
            {"threats": "tamper,tamper"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.authorizer.authorize(self.evidence(self.authorizer.challenge("ab" * 32), **change))

    def testAuthorizer_whenRegistrationUsesWrongServerKey_rejectsBuild(self) -> None:
        values = self.manifest_values | {"server_public": "11" * 32}
        with self.assertRaisesRegex(ValueError, "backend key"):
            self.authorizer.register(protocol.sign_message(values, self.publisher))
        values = self.manifest_values | {"exe": "11" * 32}
        with self.assertRaisesRegex(ValueError, "registered"):
            self.authorizer.register(protocol.sign_message(values, self.publisher))

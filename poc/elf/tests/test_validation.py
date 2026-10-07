"""Security boundary validation for malformed messages, policy and bundle input."""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from rasp_elf import __main__ as cli
from rasp_elf import backend
from rasp_elf import packer
from rasp_elf import protocol


class ValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.values = {
            "v": "rasp-elf-manifest-1",
            "build": "ab" * 32,
            "exe": "cd" * 32,
            "runtime": "ef" * 32,
            "endpoint": "",
            "interval_ms": "250",
            "client_public": "12" * 32,
            "server_public": "00" * 32,
        }
        self.message = protocol.sign_message(self.values, self.publisher)

    def testProtocol_whenSignedEnvelopeMalformed_rejectsBeforeTrustingFields(self) -> None:
        messages = (
            self.message[:-1],
            self.message + b"extra\n",
            self.message + b"a" * 8192,
            self.message.replace(b"runtime=", b"runtime=\x00"),
            self.message.replace(b"runtime=", b"runtime=\xff"),
            self.message.replace(b"runtime=", b"runtime=\r"),
            self.message.replace(b"signature=", b"signature=x"),
            self.message.replace(b"signature=", b"wrong_signature="),
        )
        for message in messages:
            with self.subTest(message=message[:40]), self.assertRaises(ValueError):
                protocol.verify_message(message, protocol.public_hex(self.publisher), protocol.MANIFEST_FIELDS)
        with self.assertRaisesRegex(ValueError, "public key"):
            protocol.verify_message(self.message, "invalid", protocol.MANIFEST_FIELDS)

    def testProtocol_whenManifestValidlySignedButInvalid_rejectsConfiguration(self) -> None:
        changes = (
            {"v": "another-version"},
            {"build": "invalid"},
            {"exe": "invalid"},
            {"runtime": "invalid"},
            {"client_public": "invalid"},
            {"server_public": "invalid"},
            {"interval_ms": "99"},
            {"interval_ms": "60001"},
            {"interval_ms": "NaN"},
            {"endpoint": "http://127.0.0.1:8788", "server_public": "00" * 32},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                protocol.validate_manifest(
                    protocol.sign_message(self.values | change, self.publisher), protocol.public_hex(self.publisher)
                )

    def testProtocol_whenUnsafeEndpointSyntax_rejectsConfiguration(self) -> None:
        for endpoint in (
            "https://host:99999",
            "https://host",
            "https://host:443/path",
            "https://host:443?q=1",
            "https://host:443#fragment",
            "https://user:pass@host:443",
            "http://localhost:80",
            "https://host_name:443",
            "https://host:443/",
            "https://host:invalid",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                protocol.validate_endpoint(endpoint)

    def testProtocol_whenSigningUnsafeValues_rejectsAmbiguousEnvelope(self) -> None:
        for values in (
            {"signature": "reserved"},
            {"invalid=name": "x"},
            {"v": "a\nb"},
            {"v": "a\rb"},
            {"v": "a\x00b"},
            {"v": "a" * 8192},
        ):
            with self.subTest(values=list(values)), self.assertRaises(ValueError):
                protocol.sign_message(values, self.publisher)

    def testKeys_whenMalformed_rejectsBeforeUse(self) -> None:
        path = self.root / "key"
        for value in ("", "invalid", "AA" * 32, "12" * 31):
            path.write_text(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                protocol.read_private_key(path)
            with self.subTest(public=value), self.assertRaises(ValueError):
                protocol.read_public_key(path)

    def testFiles_whenOversizedOrSpecial_rejectsWithoutBlocking(self) -> None:
        path = self.root / "file"
        path.write_bytes(b"a" * 1024)
        with self.assertRaisesRegex(ValueError, "large"):
            protocol.read_regular_file(path, 128)
        with path.open("r+b") as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "256"):
            protocol.sha256_file(path)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            protocol.sha256_file(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            packer.pack(path, self.root / "output", self.publisher)

    def testPolicy_whenOperationsConfigured_enforcesCustomerDecisions(self) -> None:
        path = self.root / "policy.json"
        path.write_text(
            json.dumps({"default_action": "allow", "operations": {"connect": "deny", "checkpoint": "step_up"}})
        )
        policy = cli.load_policy(path)
        self.assertIsNotNone(policy)
        evidence = backend.Evidence("ab" * 32, "12" * 32, 123, "cd" * 32, "ef" * 32, (), "startup", "00" * 32)
        self.assertEqual("allow", policy(evidence))
        self.assertEqual("deny", policy(dataclasses.replace(evidence, operation="connect")))
        self.assertEqual("step_up", policy(dataclasses.replace(evidence, operation="checkpoint")))

    def testPolicy_whenUnknownFieldsOrInvalidTypes_rejectsPolicy(self) -> None:
        path = self.root / "policy.json"
        for values in (
            [],
            {"unknown": "allow"},
            {"default_action": None},
            {"default_action": []},
            {"operations": []},
            {"operations": {"unknown": "allow"}},
            {"operations": {"connect": "invalid"}},
            {"operations": {"connect": []}},
        ):
            path.write_text(json.dumps(values))
            with self.subTest(policy=values), self.assertRaises(ValueError):
                cli.load_policy(path)

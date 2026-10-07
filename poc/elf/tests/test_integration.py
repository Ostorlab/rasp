"""Exercise actual protected processes against the actual authorizer over HTTP."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from rasp_elf import backend
from rasp_elf import packer
from rasp_elf import protocol
from tests import test_packer


class IntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rasp-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.server_key = ed25519.Ed25519PrivateKey.generate()
        self.events: list[backend.Evidence] = []
        self.action = "allow"
        self.denied_operation = ""
        self.audit = self.root / "audit.jsonl"
        self.authorizer = backend.Authorizer(
            self.server_key, protocol.public_hex(self.publisher), policy=self.policy, audit_path=self.audit
        )
        self.server = backend.ReferenceServer(("127.0.0.1", 0), self.authorizer)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.source = self.root / "demo.c"
        self.source.write_text(test_packer.SOURCE)
        self.executable = self.root / "demo"
        subprocess.run(
            ["gcc", "-Wall", "-Wextra", "-Werror", str(self.source), "-ldl", "-o", str(self.executable)], check=True
        )

    def stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def policy(self, evidence: backend.Evidence) -> str:
        self.events.append(evidence)
        return self.action if self.denied_operation in ("", evidence.operation) else "allow"

    def protect(self) -> pathlib.Path:
        output = self.root / "protected"
        packer.pack(
            self.executable,
            output,
            self.publisher,
            endpoint=f"http://127.0.0.1:{self.server.server_port}",
            server_public=protocol.public_hex(self.server_key),
            interval_ms=250,
        )
        self.authorizer.register((output / "rasp.manifest").read_bytes())
        return output

    def execute(
        self, output: pathlib.Path, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(output / "demo"), *args], capture_output=True, text=True, check=False, timeout=12, env=env
        )

    def testRuntime_whenBackendAllows_runsOriginalAndAuditsEvidence(self) -> None:
        output = self.protect()
        result = self.execute(output, "hello")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("APP:hello\n", result.stdout)
        self.assertEqual("startup", self.events[0].operation)
        event = json.loads(self.audit.read_text().splitlines()[0])
        self.assertEqual("allow", event["action"])
        self.assertEqual(self.events[0].build, event["build"])

    def testRuntime_whenBackendDenies_blocksBeforeMain(self) -> None:
        self.action = "deny"
        result = self.execute(self.protect())
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testRuntime_whenBackendRequiresStepUp_blocksBeforeMain(self) -> None:
        self.action = "step_up"
        result = self.execute(self.protect())
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testRuntime_whenBackendUnavailable_failsClosed(self) -> None:
        output = self.protect()
        self.stop_server()
        result = self.execute(output)
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testRuntime_whenBackendUsesWrongDecisionKey_rejectsResponse(self) -> None:
        output = self.protect()
        self.authorizer.decision_key = ed25519.Ed25519PrivateKey.generate()
        result = self.execute(output)
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def testRuntime_whenCheckpointCalled_bindsExactPayload(self) -> None:
        result = self.execute(self.protect(), "checkpoint")
        self.assertEqual(0, result.returncode, result.stderr)
        checkpoint = next(event for event in self.events if event.operation == "checkpoint")
        self.assertEqual(hashlib.sha256(b"amount=5000").hexdigest(), checkpoint.request)
        self.assertEqual("APP:approved\n", result.stdout)

    def testRuntime_whenCheckpointRequiresStepUp_preventsApproval(self) -> None:
        self.action = "step_up"
        self.denied_operation = "checkpoint"
        result = self.execute(self.protect(), "checkpoint")
        self.assertEqual(9, result.returncode, result.stderr)
        self.assertNotIn("APP:approved", result.stdout)

    def testRuntime_whenAppConnects_instrumentsWithoutSourceChanges(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            result = self.execute(self.protect(), "connect", str(listener.getsockname()[1]))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("APP:connected\n", result.stdout)
        self.assertIn("connect", [event.operation for event in self.events])

    def testRuntime_whenConnectDenied_preventsNetworkSideEffect(self) -> None:
        self.action = "deny"
        self.denied_operation = "connect"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.2)
            result = self.execute(self.protect(), "connect", str(listener.getsockname()[1]))
            with self.assertRaises(TimeoutError):
                listener.accept()
        self.assertIn(result.returncode, (173, 8))
        self.assertEqual("", result.stdout)
        self.assertIn("connect", [event.operation for event in self.events])

    def testRuntime_whenPolicyChangesWhileRunning_monitorTerminates(self) -> None:
        output = self.protect()
        with subprocess.Popen(
            [str(output / "demo"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ) as process:
            self.assertEqual("APP:wait\n", process.stdout.readline())
            self.action = "deny"
            _, stderr = process.communicate(timeout=5)
        self.assertEqual(173, process.returncode, stderr)
        self.assertIn("monitor", [event.operation for event in self.events])

    def testRuntime_whenManifestChangesAfterStartup_monitorTerminates(self) -> None:
        output = self.protect()
        with subprocess.Popen(
            [str(output / "demo"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ) as process:
            self.assertEqual("APP:wait\n", process.stdout.readline())
            manifest = output / "rasp.manifest"
            manifest.write_bytes(manifest.read_bytes() + b"changed")
            _, stderr = process.communicate(timeout=5)
        self.assertEqual(173, process.returncode, stderr)
        self.assertIn("tamper", stderr)

    def testRuntime_whenTracerAttached_rejectsBeforeMain(self) -> None:
        output = self.protect()
        result = subprocess.run(
            ["strace", "-o", str(self.root / "trace"), str(output / "demo")],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertIn("debugger", result.stderr)

    def testRuntime_whenPreloadSet_rejectsBeforeMain(self) -> None:
        output = self.protect()
        environment = os.environ.copy() | {"LD_PRELOAD": "libm.so.6"}
        result = self.execute(output, env=environment)
        self.assertEqual(173, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertIn("preload", result.stderr)

    def testBackend_whenHTTPMessageOversized_rejectsBeforeParsing(self) -> None:
        with socket.create_connection(self.server.server_address, timeout=2) as connection:
            connection.sendall(b"POST /v1/authorize HTTP/1.0\r\nContent-Length: 10000\r\n\r\n")
            response = connection.recv(8192)
        self.assertIn(b"400", response)

    def testRuntime_whenDebuggerAttachesAfterStartup_monitorTerminates(self) -> None:
        output = self.protect()
        with subprocess.Popen(
            [str(output / "demo"), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ) as process:
            self.assertEqual("APP:wait\n", process.stdout.readline())
            libc = ctypes.CDLL(None, use_errno=True)
            libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            libc.ptrace.restype = ctypes.c_long
            result = libc.ptrace(16, process.pid, None, None)  # PTRACE_ATTACH from the parent.
            self.assertEqual(0, result, f"ptrace failed: {ctypes.get_errno()}")
            os.waitpid(process.pid, os.WUNTRACED)
            _, stderr = process.communicate(timeout=5)
        self.assertEqual(173, process.returncode, stderr)
        self.assertIn("debugger", stderr)

    def testRuntime_whenRequestEvidencePrepared_customerVerifiesExactBytes(self) -> None:
        result = self.execute(self.protect(), "prepare")
        self.assertEqual(0, result.returncode, result.stderr)
        message = result.stdout.encode("ascii")
        decision = self.authorizer.authorize(message, expected_request=b"amount=5000", expected_operation="checkpoint")
        fields, _ = protocol.verify_message(decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS)
        self.assertEqual("allow", fields["action"])
        with self.assertRaisesRegex(ValueError, "challenge"):
            self.authorizer.authorize(message, expected_request=b"amount=5000")

    def testRuntime_whenPreparedRequestBodyChanged_customerDenies(self) -> None:
        result = self.execute(self.protect(), "prepare")
        self.assertEqual(0, result.returncode, result.stderr)
        decision = self.authorizer.authorize(
            result.stdout.encode("ascii"), expected_request=b"amount=999999", expected_operation="checkpoint"
        )
        fields, _ = protocol.verify_message(decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS)
        self.assertEqual("deny", fields["action"])

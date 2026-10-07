"""Exercise public commands as users run them."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(
            (pathlib.Path(__file__).parents[1] / "rasp_elf" / "__main__.py").is_file(),
            "ELF command line interface is not implemented",
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "rasp_elf", *args], capture_output=True, text=True, check=False, timeout=10
        )

    def testCli_whenKeysGeneratedAndBinaryPacked_inspectsVerifiedBundle(self) -> None:
        keys = self.root / "keys"
        output = self.root / "bundle"
        result = self.command("keygen", "--output", str(keys))
        self.assertEqual(0, result.returncode, result.stderr)
        result = self.command(
            "pack", "/usr/bin/true", "--output", str(output), "--publisher-key", str(keys / "publisher.key")
        )
        self.assertEqual(0, result.returncode, result.stderr)
        result = self.command("inspect", str(output), "--publisher-public", str(keys / "publisher.pub"))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(json.loads(result.stdout)["verified"])
        self.assertEqual(
            0, subprocess.run([str(output / "true")], capture_output=True, check=False, timeout=5).returncode
        )

    def testCli_whenOutputExists_reportsFailureWithoutOverwrite(self) -> None:
        keys = self.root / "keys"
        keys.mkdir()
        result = self.command("keygen", "--output", str(keys))
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual([], list(keys.iterdir()))

    def testCli_whenPublicKeyWrong_inspectFails(self) -> None:
        keys = self.root / "keys"
        output = self.root / "bundle"
        self.command("keygen", "--output", str(keys))
        self.command("pack", "/usr/bin/true", "--output", str(output), "--publisher-key", str(keys / "publisher.key"))
        result = self.command("inspect", str(output), "--publisher-public", str(keys / "backend.pub"))
        self.assertEqual(2, result.returncode)
        self.assertIn("signature", result.stderr)

    def testCli_whenBackendPolicyInvalid_refusesToServe(self) -> None:
        keys = self.root / "keys"
        output = self.root / "bundle"
        self.command("keygen", "--output", str(keys))
        self.command(
            "pack",
            "/usr/bin/true",
            "--output",
            str(output),
            "--publisher-key",
            str(keys / "publisher.key"),
            "--backend",
            "http://127.0.0.1:8788",
            "--backend-public",
            str(keys / "backend.pub"),
        )
        policy = self.root / "policy.json"
        policy.write_text('{"default_action": "accept"}')
        result = self.command(
            "serve",
            "--publisher-public",
            str(keys / "publisher.pub"),
            "--decision-key",
            str(keys / "backend.key"),
            "--manifest",
            str(output / "rasp.manifest"),
            "--policy",
            str(policy),
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("policy", result.stderr)

    def testCli_whenBundleFileIsFIFO_rejectsWithoutBlocking(self) -> None:
        keys = self.root / "keys"
        self.command("keygen", "--output", str(keys))
        for filename in ("report.json", "rasp.manifest", "librasp_runtime.so"):
            with self.subTest(filename=filename):
                output = self.root / filename.replace(".", "_")
                result = self.command(
                    "pack", "/usr/bin/true", "--output", str(output), "--publisher-key", str(keys / "publisher.key")
                )
                self.assertEqual(0, result.returncode, result.stderr)
                target = output / filename
                target.unlink()
                os.mkfifo(target)
                try:
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "rasp_elf",
                            "inspect",
                            str(output),
                            "--publisher-public",
                            str(keys / "publisher.pub"),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=2,
                    )
                except subprocess.TimeoutExpired:
                    self.fail("inspection blocks on non-regular bundle files")
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertIn("regular", result.stderr)

    def testCli_whenReferenceBackendStarted_authorizesOnlineBundle(self) -> None:
        keys = self.root / "keys"
        output = self.root / "bundle"
        self.assertEqual(0, self.command("keygen", "--output", str(keys)).returncode)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = str(reservation.getsockname()[1])
        result = self.command(
            "pack",
            "/usr/bin/true",
            "--output",
            str(output),
            "--publisher-key",
            str(keys / "publisher.key"),
            "--backend",
            f"http://127.0.0.1:{port}",
            "--backend-public",
            str(keys / "backend.pub"),
        )
        self.assertEqual(0, result.returncode, result.stderr)
        command = [
            sys.executable,
            "-m",
            "rasp_elf",
            "serve",
            "--publisher-public",
            str(keys / "publisher.pub"),
            "--decision-key",
            str(keys / "backend.key"),
            "--manifest",
            str(output / "rasp.manifest"),
            "--port",
            port,
            "--audit",
            str(self.root / "audit.jsonl"),
        ]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as server:
            try:
                self.assertIn("listening", server.stdout.readline())
                result = subprocess.run([str(output / "true")], capture_output=True, check=False, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                event = json.loads((self.root / "audit.jsonl").read_text().splitlines()[0])
                self.assertEqual("allow", event["action"])
            finally:
                server.terminate()
                server.communicate(timeout=3)

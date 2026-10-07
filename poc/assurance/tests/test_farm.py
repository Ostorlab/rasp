from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import time
import sys
import tempfile
import unittest
from unittest import mock

from rasp_assurance import farm


class FarmTest(unittest.TestCase):
    def testRun_whenAmbientCredentialPresent_adapterDoesNotInheritIt(self) -> None:
        code = 'import os,json; x=json.loads(os.environ["RASP_FARM_CONTEXT"]); x.update(fixtureVerified=True,baselineAllowed="RASP_ARTIFACT_TOKEN" not in os.environ,enforced=False); print(json.dumps(x))'
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict("os.environ", {"RASP_ARTIFACT_TOKEN": "private-fixture"}),
        ):
            artifact = pathlib.Path(directory) / "app.apk"
            artifact.write_bytes(b"fixture")
            report = farm.run(
                {
                    "device": "unit",
                    "platform": "android",
                    "artifact": str(artifact),
                    "cases": [
                        {"scenario": "baseline", "probe": [sys.executable, "-c", code]}
                    ],
                }
            )
        self.assertEqual(report["cases"][0]["status"], "passed")

    def testRun_whenRealAdapterMissingScenarios_failsGate(self) -> None:
        code = 'import os,json; x=json.loads(os.environ["RASP_FARM_CONTEXT"]); x.update(fixtureVerified=True,baselineAllowed=True,enforced=False); print(json.dumps(x))'
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "app.apk"
            artifact.write_bytes(b"test binary")
            report = farm.run(
                {
                    "device": "unit-test-adapter",
                    "platform": "android",
                    "artifact": str(artifact),
                    "cases": [
                        {"scenario": "baseline", "probe": [sys.executable, "-c", code]}
                    ],
                }
            )
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"][0]["status"], "passed")
        self.assertIn('message="not_run"', farm.junit(report))

    def testEvaluate_whenStaleEvidence_refuses(self) -> None:
        expected = {
            "runId": "fresh",
            "device": "d",
            "artifactSha256": "a" * 64,
            "scenario": "frida-fork",
        }
        with self.assertRaises(ValueError):
            farm.evaluate(
                dict(
                    expected,
                    runId="old",
                    fixtureVerified=True,
                    baselineAllowed=True,
                    enforced=True,
                ),
                expected,
            )

    def testEvaluate_whenPositiveControlFails_doesNotCountAsBlocked(self) -> None:
        expected = {
            "runId": "fresh",
            "device": "d",
            "artifactSha256": "a" * 64,
            "scenario": "frida-fork",
        }
        with self.assertRaises(ValueError):
            farm.evaluate(
                dict(
                    expected, fixtureVerified=True, baselineAllowed=False, enforced=True
                ),
                expected,
            )

    def testRun_whenProbeFails_cleanupStillRuns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "app.apk"
            artifact.write_bytes(b"test binary")
            marker = pathlib.Path(directory) / "cleanup"
            cleanup = [
                sys.executable,
                "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('done')",
                str(marker),
            ]
            report = farm.run(
                {
                    "device": "test",
                    "platform": "android",
                    "artifact": str(artifact),
                    "cases": [
                        {
                            "scenario": "baseline",
                            "probe": [sys.executable, "-c", "raise SystemExit(1)"],
                            "cleanup": cleanup,
                        }
                    ],
                }
            )
            self.assertEqual(marker.read_text(), "done")
            self.assertEqual(report["cases"][0]["status"], "error")

    def testCommand_whenFinalReapNeverCompletes_returnsBoundedCleanupError(
        self,
    ) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired(["fixture"], 0)
        with (
            mock.patch.object(farm.subprocess, "Popen", return_value=process),
            mock.patch.object(
                farm.time, "monotonic", side_effect=[100.0, 101.0, 101.0]
            ),
            mock.patch.object(farm.os, "killpg") as kill,
        ):
            with self.assertRaisesRegex(ValueError, "cleanup deadline"):
                farm.command(["fixture"], {}, 1)
        self.assertEqual(
            process.wait.call_args_list, [mock.call(timeout=0), mock.call(timeout=0)]
        )
        self.assertEqual(kill.call_count, 2)

    def testCommand_whenRealProcessCompletes_reapsAndReturnsOutput(self) -> None:
        self.assertEqual(
            farm.command([sys.executable, "-c", "print('ready')"], {}, 1), b"ready\n"
        )

    def testCommand_whenRealProcessTimesOut_returnsWithoutUnboundedWait(self) -> None:
        start = time.monotonic()
        with self.assertRaises(ValueError):
            farm.command([sys.executable, "-c", "import time; time.sleep(20)"], {}, 1)
        self.assertLess(time.monotonic() - start, 2)

    def testMain_whenConfigurationJsonExceedsRecursionDepth_returnsSanitizedError(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            configuration = pathlib.Path(directory) / "farm.json"
            configuration.write_text("[" * 10000 + "0" + "]" * 10000)
            self.assertLess(configuration.stat().st_size, 262144)
            output = io.StringIO()
            with (
                mock.patch("sys.argv", ["rasp-device-farm", str(configuration)]),
                contextlib.redirect_stdout(output),
            ):
                status = farm.main()
        self.assertEqual(status, 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"passed": False, "error": "invalid_farm_configuration"},
        )

    def testRun_whenProbeJsonExceedsRecursionDepth_recordsErrorAndContinues(
        self,
    ) -> None:
        valid = 'import os,json; x=json.loads(os.environ["RASP_FARM_CONTEXT"]); x.update(fixtureVerified=True,baselineAllowed=True,enforced=True); print(json.dumps(x))'
        nested = "print('[' * 10000 + '0' + ']' * 10000)"
        self.assertLess(20002, 262144)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact, marker = root / "app.apk", root / "cleanup"
            artifact.write_bytes(b"fixture")
            cleanup = [
                sys.executable,
                "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('done')",
                str(marker),
            ]
            report = farm.run(
                {
                    "device": "unit",
                    "platform": "android",
                    "artifact": str(artifact),
                    "cases": [
                        {
                            "scenario": "baseline",
                            "probe": [sys.executable, "-c", nested],
                            "cleanup": cleanup,
                        },
                        {
                            "scenario": "frida-fork",
                            "probe": [sys.executable, "-c", valid],
                        },
                    ],
                }
            )
            self.assertEqual(marker.read_text(), "done")
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"][0]["status"], "error")
        self.assertEqual(report["cases"][1]["status"], "passed")

from __future__ import annotations

import pathlib
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

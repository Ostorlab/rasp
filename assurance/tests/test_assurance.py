from __future__ import annotations

import json
import pathlib
import stat
import sys
import tempfile
import unittest

from cryptography import exceptions
from rasp_assurance import crashmaps
from rasp_assurance import evidence
from rasp_assurance import farm


class CrashMapTest(unittest.TestCase):
    def testArchive_whenRoundTrip_resolvesOnlyWholeSymbols(self) -> None:
        key, binding = b"k" * 32, b"tenant/app/build/artifact"
        data = crashmaps.seal(b'{"_r123":"rasp_detector"}', key, binding)
        self.assertNotIn(b"rasp_detector", data)
        mapping = crashmaps.open_archive(data, key, binding)
        self.assertEqual(
            crashmaps.symbolize("_r123+0x10 _r123suffix", mapping),
            "rasp_detector+0x10 _r123suffix",
        )

    def testArchive_whenWrongContextKeyOrTamper_refuses(self) -> None:
        data = crashmaps.seal(b'{"a":"real"}', b"k" * 32, b"context")
        for archive, key, binding in [
            (data, b"k" * 32, b"other"),
            (data, b"z" * 32, b"context"),
            (data[:-1] + bytes([data[-1] ^ 1]), b"k" * 32, b"context"),
        ]:
            with self.assertRaises((ValueError, exceptions.InvalidTag)):
                crashmaps.open_archive(archive, key, binding)

    def testArchive_whenPersisted_privateAndImmutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = crashmaps.archive(pathlib.Path(directory), b"encrypted", b"binding")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                crashmaps.archive(pathlib.Path(directory), b"replacement", b"binding")
            self.assertEqual(path.read_bytes(), b"encrypted")

    def testContext_whenArtifactChanges_bindingChanges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "app.so"
            artifact.write_bytes(b"original")
            first = crashmaps.context("tenant", "app", "build", artifact)
            artifact.write_bytes(b"patched")
            self.assertNotEqual(
                first, crashmaps.context("tenant", "app", "build", artifact)
            )

    def testUpload_whenCleartextUrl_rejectsBeforeSending(self) -> None:
        with self.assertRaises(ValueError):
            crashmaps.upload("http://127.0.0.1/private", b"RCM1", "secret")


class EvidenceTest(unittest.TestCase):
    def testExport_whenReportIsNotObject_rejects(self) -> None:
        for report in ([], None, "text"):
            with self.subTest(report=report), self.assertRaises(TypeError):
                evidence.export(report, "a" * 64, "android")

    def testExport_whenSignalPresent_mapsAndRedactsEvidence(self) -> None:
        report = evidence.export(
            {
                "signals": [
                    {
                        "threat": "debugger",
                        "detector": "native.tracer",
                        "evidence": "private path",
                    }
                ]
            },
            "a" * 64,
            "android",
        )
        self.assertEqual(report["signals"][0]["mastg"], "MASTG-TEST-0353")
        self.assertNotIn("private path", json.dumps(report))
        self.assertEqual(report["assessment"], "not_assessed")

    def testExport_whenNoSignals_doesNotClaimCompliance(self) -> None:
        report = evidence.export({"signals": []}, "a" * 64, "android")
        self.assertEqual(report["assessment"], "not_assessed")
        self.assertEqual(report["signals"], [])


class FarmTest(unittest.TestCase):
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

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from rasp_assurance import evidence


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

    def testExport_whenDigestContainsNonHex_rejects(self) -> None:
        for digest in ("z" * 64, "a" * 63 + "!", " " * 64):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                evidence.export({"signals": []}, digest, "android")

    def testExport_whenDigestIsMixedCaseHex_accepts(self) -> None:
        digest = "aB12" * 16
        self.assertEqual(
            evidence.export({"signals": []}, digest, "android")["artifactSha256"],
            digest,
        )

    def testMain_whenReportJsonExceedsRecursionDepth_returnsSanitizedError(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            report, artifact = root / "report", root / "app.apk"
            artifact.write_bytes(b"fixture")
            report.write_text("[" * 10000 + "0" + "]" * 10000)
            self.assertLess(report.stat().st_size, 1024 * 1024)
            output = io.StringIO()
            arguments = [
                "rasp-evidence",
                str(report),
                "--artifact",
                str(artifact),
                "--platform",
                "android",
            ]
            with mock.patch("sys.argv", arguments), contextlib.redirect_stdout(output):
                status = evidence.main()
        self.assertEqual(status, 1)
        self.assertEqual(
            json.loads(output.getvalue()), {"error": "invalid_evidence_input"}
        )

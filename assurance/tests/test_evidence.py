from __future__ import annotations

import json
import unittest

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

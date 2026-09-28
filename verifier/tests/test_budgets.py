"""Budget gates validate measured evidence rather than generating benchmarks."""

from __future__ import annotations

import contextlib
import io
import json
import math
import pathlib
import tempfile
import unittest
from unittest import mock

from rasp_verifier import budgets


class BudgetTest(unittest.TestCase):
    def testSize_whenArtifactExceedsBudget_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "core.so"
            artifact.write_bytes(b"x" * 17)
            self.assertFalse(budgets.check_size(artifact, 16).passed)
            self.assertTrue(budgets.check_size(artifact, 17).passed)

    def testLatency_whenP95ExceedsBudget_fails(self) -> None:
        samples = [1.0] * 28 + [101.0, 102.0]
        result = budgets.check_latency("pixel-7", samples, 100)
        self.assertEqual(result.measured, 101.0)
        self.assertFalse(result.passed)

    def testLatency_whenInsufficientSamples_rejects(self) -> None:
        with self.assertRaises(ValueError):
            budgets.check_latency("pixel-7", [1.0] * 29, 10)

    def testLatency_whenSamplesNonFinite_rejects(self) -> None:
        for sample in [math.nan, math.inf, -1.0, True]:
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                budgets.check_latency("pixel-7", [1.0] * 29 + [sample], 10)

    def testLatency_whenDeviceMissing_rejects(self) -> None:
        with self.assertRaises(ValueError):
            budgets.check_latency("", [1.0] * 30, 10)

    def testLatency_whenMeasuredSamplesFit_passes(self) -> None:
        self.assertTrue(budgets.check_latency("pixel-7", [1.0] * 30, 1).passed)

    def testMain_whenMeasuredEvidenceSupplied_enforcesBothGates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "core.so"
            artifact.write_bytes(b"x" * 17)
            metrics = pathlib.Path(directory) / "metrics.json"
            metrics.write_text(
                json.dumps({"device": "pixel-7", "samplesMs": [2.0] * 30})
            )
            cases = [
                (["size", str(artifact), "--max-bytes", "16"], 1),
                (["size", str(artifact), "--max-bytes", "17"], 0),
                (["latency", str(metrics), "--max-p95-ms", "1"], 1),
                (["latency", str(metrics), "--max-p95-ms", "2"], 0),
                (["size", str(artifact), "--max-bytes", "0"], 2),
            ]
            for argv, expected in cases:
                with (
                    self.subTest(argv=argv),
                    mock.patch("sys.argv", ["budgets", *argv]),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(budgets.main(), expected)

    def testSize_whenEmptyOrDirectory_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "empty"
            artifact.touch()
            for path in [artifact, pathlib.Path(directory)]:
                with self.assertRaises(ValueError):
                    budgets.check_size(path, 100)

    def testLatency_whenBudgetInvalid_rejects(self) -> None:
        for limit in [0, -1, float("nan"), float("inf"), True]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                budgets.check_latency("pixel-7", [1.0] * 30, limit)

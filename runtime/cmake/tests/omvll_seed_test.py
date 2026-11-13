"""Canonical seed policy exercised through the actual configure-time CLI."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "omvll_seed.py"


def run_policy(seed: str | None, mode: str | None) -> subprocess.CompletedProcess[str]:
    """Run without Python import-path injection or an inherited seed."""
    environment = dict(os.environ)
    for name in ("RASP_OMVLL_SEED", "RASP_OMVLL_SEED_MODE"):
        environment.pop(name, None)
    if seed is not None:
        environment["RASP_OMVLL_SEED"] = seed
    if mode is not None:
        environment["RASP_OMVLL_SEED_MODE"] = mode
    return subprocess.run(
        [sys.executable, "-I", "-B", str(SCRIPT)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


class SeedTest(unittest.TestCase):
    def testSeed_whenAbsent_preservesDefaultOne(self) -> None:
        result = run_policy(None, None)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"seed": 1, "mode": "default"}

    def testSeed_whenCanonical_preservesExactValueAndMode(self) -> None:
        for seed in ("0", "1", "42", "2147483647"):
            for mode in (None, "explicit", "release", "diagnostic"):
                with self.subTest(seed=seed, mode=mode):
                    result = run_policy(seed, mode)
                    assert result.returncode == 0, result.stderr
                    assert json.loads(result.stdout) == {
                        "seed": int(seed),
                        "mode": "explicit" if mode is None else mode,
                    }

    def testSeed_whenMalformed_refusesWithoutEchoingValue(self) -> None:
        for seed in (
            "",
            "-1",
            "-0",
            "+1",
            "01",
            "00",
            " 1",
            "1 ",
            "1\n",
            "1\t",
            "1_000",
            "0x10",
            "1e2",
            "1.0",
            "true",
            "\u0661",
            "\uff11",
            "2147483648",
            "9999999999",
            "12345678901",
            "operator-private-value",
        ):
            with self.subTest(seed=seed):
                result = run_policy(seed, None)
                assert result.returncode == 1
                assert result.stdout == ""
                assert "invalid O-MVLL seed policy" in result.stderr
                if len(seed) > 10:
                    assert seed not in result.stderr

    def testSeed_whenModeConflicts_refuses(self) -> None:
        for seed, mode in (
            (None, ""),
            (None, "unknown"),
            (None, "release"),
            (None, "diagnostic"),
            (None, "explicit"),
            ("1", "default"),
            ("0", "Release"),
            ("0", "diagnostic\n"),
        ):
            with self.subTest(seed=seed, mode=mode):
                result = run_policy(seed, mode)
                assert result.returncode == 1
                assert result.stdout == ""

    def testSeed_whenDefaultModeExplicit_preservesDefaultOne(self) -> None:
        result = run_policy(None, "default")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"seed": 1, "mode": "default"}

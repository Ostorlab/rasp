"""Exercise public preparation with genuine installed resources and the real SDK."""

from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys

import pytest

from validation import run


@pytest.mark.parametrize("bad_pin", [False, True])
def testPreparation_whenGenuineInputsOrWrongToolPin_suppliesFullSuiteOrRefusesBeforeBuild(
    bad_pin: bool, tmp_path: pathlib.Path
) -> None:
    source = pathlib.Path(os.environ["VAL01_ANDROID_INPUTS"])
    rows = json.loads((source / "result.json").read_bytes())["input_files"]
    wheel = next(row for row in rows if row["role"] == "wheel")
    bridge = next(row for row in rows if row["role"] == "bridge_jar")
    adb = pathlib.Path(os.environ["VAL01_ADB_SNAPSHOT"])
    expected = "0" * 64 if bad_pin is True else run.sha(adb.read_bytes())
    output = tmp_path / "prepared"
    args = [
        sys.executable,
        "-B",
        "-m",
        "validation.prepare",
        "--wheel",
        str(source / wheel["path"]),
        "--bridge",
        str(source / bridge["path"]),
        "--android-jar",
        os.environ["ANDROID_JAR"],
        "--build-tools",
        os.environ["ANDROID_BUILD_TOOLS"],
        "--adb",
        str(adb),
        "--adb-sha256",
        expected,
        "--output",
        str(output),
    ]
    result = subprocess.run(args, capture_output=True, check=False, timeout=120)
    if bad_pin is True:
        assert result.returncode == 2 and b"ADB digest mismatch" in result.stderr
        assert output.exists() is False
        return
    assert result.returncode == 0, result.stderr.decode() + result.stdout.decode()
    report = json.loads((output / "result.json").read_bytes())
    plan = {"files": report["input_files"]}
    payloads = {
        row["id"]: run.read_file(output, row["path"], 64 * run.MIB)
        for row in plan["files"]
    }
    assert all(
        len(payloads[row["id"]]) == row["bytes"]
        and run.sha(payloads[row["id"]]) == row["sha256"]
        for row in plan["files"]
    )
    actual = run.android_preflight(plan, payloads, output, unsigned_preparation=True)
    assert actual["abis"] == ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
    assert (
        report["adb_invocations"] == 0
        and report["actual_device_execution"] == "NOT_RUN"
    )
    snapshot = output / report["adb_snapshot"]["path"]
    assert snapshot.read_bytes() == adb.read_bytes()
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o400
    assert report["adb_snapshot"]["sha256"] == expected
    assert (
        next(row for row in rows if row["role"] == "config")["sha256"]
        == next(row for row in report["input_files"] if row["role"] == "config")[
            "sha256"
        ]
    )

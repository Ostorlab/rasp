"""Exercise validation trust boundaries and real child lifetimes; no device claims."""

from __future__ import annotations

import copy
import importlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import typing

import pytest


def testCommand_whenBinaryOpenFails_reapsActualChildAndPreservesPriorOutput(
    runner: typing.Any, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "existing.apk"
    destination.write_bytes(b"prior output must survive")
    pid_file = tmp_path / "live.pid"
    processes: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen
    original_open = pathlib.Path.open

    def start(*args: typing.Any, **kwargs: typing.Any) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_after_child_starts(
        path: pathlib.Path, mode: str = "r", *args: typing.Any, **kwargs: typing.Any
    ) -> typing.Any:
        if path == destination and mode == "xb":
            deadline = time.monotonic() + 3
            while pid_file.exists() is False and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pid_file.exists() is True, "real long-running child did not start"
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", start)
    monkeypatch.setattr(pathlib.Path, "open", fail_after_child_starts)
    try:
        with pytest.raises(FileExistsError):
            runner.command(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,pathlib,time; pathlib.Path('live.pid').write_text(str(os.getpid())); time.sleep(20)",
                ],
                tmp_path,
                binary_path=destination,
            )
        assert len(processes) == 1 and processes[0].poll() is not None
        child_pid = int(pid_file.read_text())
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
        with pytest.raises(ProcessLookupError):
            os.killpg(child_pid, 0)
        assert destination.read_bytes() == b"prior output must survive"
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


@pytest.fixture
def runner() -> typing.Any:
    """Load the single runner without replacing its code or production gates."""
    return importlib.import_module("validation.run")


def testDecode_whenDuplicateOrNonfiniteOrDeepInput_rejects(runner: typing.Any) -> None:
    for raw in [
        b'{"version":1,"version":1}',
        b'{"n":NaN}',
        b'{"n":1e3}',
        b"[" * 13 + b"0" + b"]" * 13,
    ]:
        with pytest.raises(runner.ValidationError):
            runner.decode(raw)


def testRead_whenSymlinkOrHardlinkOrOversize_rejects(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    original = tmp_path / "original"
    original.write_bytes(b"12345")
    linked = tmp_path / "linked"
    linked.symlink_to(original)
    with pytest.raises(runner.ValidationError):
        runner.read_file(tmp_path, "linked", 10)
    linked.unlink()
    os.link(original, linked)
    with pytest.raises(runner.ValidationError):
        runner.read_file(tmp_path, "linked", 10)
    linked.unlink()
    with pytest.raises(runner.ValidationError):
        runner.read_file(tmp_path, "original", 4)


def testCommand_whenDeadlineExpires_killsAndReapsGroup(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    pidfile = tmp_path / "child"
    code = "import os,time,pathlib; pathlib.Path('child').write_text(str(os.getpid())); time.sleep(20)"
    result = runner.command([sys.executable, "-I", "-c", code], tmp_path, timeout=0.2)
    assert result.reason == "timeout"
    assert result.returncode < 0
    child_pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def testCommand_whenOutputOverflows_stopsWithoutTruncationSuccess(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    result = runner.command(
        [sys.executable, "-I", "-c", "import os; os.write(1,b'x'*300000)"], tmp_path
    )
    assert result.reason == "resource_limit"
    assert len(result.stdout) <= 262144


def testCommand_whenChildCrashes_preservesSignal(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    result = runner.command(
        [
            sys.executable,
            "-I",
            "-c",
            "import os,signal; os.kill(os.getpid(),signal.SIGKILL)",
        ],
        tmp_path,
    )
    assert result.returncode == -signal.SIGKILL
    assert result.reason == "process_crash"


def testCommand_whenClientTriesToAutostartDaemon_forkIsDenied(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    result = runner.command(
        [sys.executable, "-I", "-c", "import os; os.fork()"], tmp_path, no_fork=True
    )
    assert result.returncode != 0
    assert b"Resource temporarily unavailable" in result.stderr


def testMeasurements_whenMissingOrForgedPairs_neverAcceptsCompleteness(
    runner: typing.Any,
) -> None:
    pair = {
        "cell_id": "host",
        "metric": "scan",
        "unit": "ns",
        "conditions_sha256": "a" * 64,
        "baseline_artifact_id": "baseline",
        "protected_artifact_id": "protected",
        "expected_pairs": 30,
        "samples": [],
        "missing_indices": list(range(30)),
    }
    assert (
        runner.check_measurements([pair], {}, {"host"}, {"baseline", "protected"}) == 0
    )
    pair["missing_indices"] = []
    with pytest.raises(runner.ValidationError):
        runner.check_measurements([pair], {}, {"host"}, {"baseline", "protected"})
    pair["expected_pairs"] = 0
    with pytest.raises(runner.ValidationError):
        runner.check_measurements([pair], {}, {"host"}, {"baseline", "protected"})


def testSummary_whenExpectedStartupErrorOrMissingDevice_cannotPassRelease(
    runner: typing.Any,
) -> None:
    cells = [
        {"id": "host", "required": True, "expected": "error"},
        {"id": "android", "required": True, "expected": "not_run"},
    ]
    results = [
        {"cell_id": "host", "outcome": "error", "execution": {"state": "verified"}},
        {"cell_id": "android", "outcome": "not_run", "execution": {"state": "not_run"}},
    ]
    summary = runner.summarize(cells, results)
    assert summary["planned"] == 2
    assert summary["release_gate"] == "fail"
    assert summary["by_outcome"]["error"] == 1
    assert summary["missing_cells"] == ["android"]
    assert summary["effectiveness_gate"] == "not_run"


def testFixture_whenForgedSetupOrWrongPolicy_rejects(runner: typing.Any) -> None:
    with pytest.raises(runner.ValidationError):
        runner.check_fixture(
            {"setup_ok": True},
            "a" * 32,
            "baseline",
            "android_clean_receipt",
            "b" * 64,
            "c" * 64,
        )


def testFixture_whenProductionBenignVerdictAndChangedHash_verifiesOnlyExactBinding(
    runner: typing.Any,
) -> None:
    event = {
        "nonce": "a" * 32,
        "scenario": "android_clean_receipt",
        "phase": "baseline",
        "policy_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "status": 0,
        "action": 2,
        "reason": 12,
        "before": 0,
        "after": 1,
        "rule_id": "native.android.dbg.tracer_pid.proc_status",
        "rule_version": 1,
        "rule_status": 0,
        "rule_evaluated": True,
        "rule_verdict": 1,
    }
    assert (
        runner.check_fixture(
            event, "a" * 32, "baseline", "android_clean_receipt", "b" * 64, "c" * 64
        )
        == event
    )
    with pytest.raises(runner.ValidationError):
        runner.check_fixture(
            event, "a" * 32, "baseline", "android_clean_receipt", "d" * 64, "c" * 64
        )


def testXml_whenStaleOrDuplicateViewOrEntity_rejects(runner: typing.Any) -> None:
    for raw in [
        b'<!DOCTYPE x [<!ENTITY e "hi">]><hierarchy/>',
        b'<hierarchy><node resource-id="fixture.validation:id/status" text="{}"/><node resource-id="fixture.validation:id/status" text="{}"/></hierarchy>',
    ]:
        with pytest.raises(runner.ValidationError):
            runner.fixture_xml(raw)


def testPreflight_whenMissingInstalledPackerOrManifest_rejectsBeforeTransport(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(runner.ValidationError):
        runner.android_preflight({"files": []}, {}, tmp_path)


def testAndroid_whenNoLabSelected_makesZeroTransportCalls(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    result = runner.android_unavailable(
        {"id": "android", "adapter": "android_adb", "context": "clean", "target": {}},
        "a" * 32,
    )
    assert result["outcome"] == "not_run"
    assert result["reason"] == "facility_missing"
    assert list(tmp_path.iterdir()) == []


@pytest.fixture
def native_bundle(
    runner: typing.Any, tmp_path: pathlib.Path
) -> tuple[dict[str, typing.Any], pathlib.Path]:
    """Use the separately built real production fixture, never a mock gate."""
    executable = os.environ.get("VAL01_HOST")
    if executable is None:
        pytest.skip("set VAL01_HOST to the privately built rasp_validation_host")
    root = tmp_path / "bundle"
    root.mkdir(mode=0o700)
    native = pathlib.Path(executable).read_bytes()
    records: list[dict[str, typing.Any]] = []
    payloads = {
        "host": native,
        "registry": b"std::array<const Plugin*, 0> kPlugins{};",
        "suite": b"unit integration suite",
    }
    roles = {"host": "host_executable", "registry": "registry", "suite": "suite_source"}
    for file_id, data in payloads.items():
        records.append(
            {
                "id": file_id,
                "path": file_id,
                "role": roles[file_id],
                "bytes": len(data),
                "sha256": runner.sha(data),
            }
        )
    receipt = runner.canonical(
        {
            "version": 1,
            "source_head": "1" * 40,
            "source_tree": "2" * 40,
            "tool_ids": [],
            "flags": ["static"],
            "plugins": [],
            "registry_file": "registry",
            "products": ["host"],
            "dependency_manifest": None,
        }
    )
    payloads["receipt"] = receipt
    records.append(
        {
            "id": "receipt",
            "path": "receipt",
            "role": "build_receipt",
            "bytes": len(receipt),
            "sha256": runner.sha(receipt),
        }
    )
    cell = {
        "id": "host",
        "adapter": "host_c",
        "scenario": "host_startup_unavailable",
        "context": "clean",
        "facility": "host",
        "target": runner.host_environment(),
        "required": True,
        "artifact_ids": ["host"],
        "expected": "error",
    }
    plan = {
        "version": 1,
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "build_receipt_sha256": runner.sha(receipt),
        "suite_sha256": runner.sha(
            b"val01.suite.v1\0" + runner.canonical([records[2]])
        ),
        "files": records,
        "cells": [cell],
    }
    for row in records:
        runner.write_file(
            root,
            "inputs/" + row["path"],
            payloads[row["id"]],
            row["role"] == "host_executable",
        )
    runner.write_file(root, "plan.json", runner.canonical(plan))
    recorder = runner.Recorder(plan, root)
    result = runner.host_run(
        recorder, cell, "a" * 32, runner.checked_files(plan, root / "inputs")
    )
    bundle = {
        "version": 1,
        "run_id": recorder.run_id,
        "plan_sha256": runner.sha(b"val01.plan.v1\0" + runner.canonical(plan)),
        **{
            key: plan[key]
            for key in (
                "suite_sha256",
                "source_head",
                "source_tree",
                "build_receipt_sha256",
            )
        },
        "results": [result],
        "evidence": recorder.evidence,
        "artifacts": [],
        "measurements": [],
        "summary": runner.summarize([cell], [result]),
    }
    runner.write_file(root, "result.json", runner.canonical(bundle))
    return plan, root


def testNative_whenRealFacadeExecutes_independentVerifyPreservesError(
    native_bundle: tuple[dict[str, typing.Any], pathlib.Path], runner: typing.Any
) -> None:
    plan, root = native_bundle
    result = runner.verify_bundle(plan, root)
    assert result["results"][0]["operation"]["api_status"] == 3
    assert result["summary"]["conformance"] == "pass"
    assert result["summary"]["release_gate"] == "fail"
    assert (root / "inputs/host").stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "attack",
    [
        "artifact",
        "duplicate",
        "missing_cleanup",
        "cross_phase",
        "source",
        "summary",
        "forged_setup",
        "extra_field",
        "boolean_count",
    ],
)
def testVerify_whenEvidenceOrBindingIsForged_rejects(
    attack: str,
    native_bundle: tuple[dict[str, typing.Any], pathlib.Path],
    runner: typing.Any,
) -> None:
    plan, root = native_bundle
    bundle = json.loads((root / "result.json").read_bytes())
    if attack == "artifact":
        with (root / "inputs/host").open("ab") as stream:
            stream.write(b"changed")
    elif attack == "duplicate":
        bundle["evidence"].append(copy.deepcopy(bundle["evidence"][0]))
    elif attack == "missing_cleanup":
        bundle["results"][0]["cleanup"]["evidence_ids"] = []
    elif attack == "cross_phase":
        bundle["results"][0]["setup"]["evidence_ids"] = bundle["results"][0][
            "baseline"
        ]["evidence_ids"]
    elif attack == "source":
        plan["source_head"] = "3" * 40
    elif attack == "summary":
        bundle["summary"]["release_gate"] = "pass"
    elif attack == "boolean_count":
        bundle["summary"]["by_outcome"]["error"] = True
    elif attack == "extra_field":
        bundle["results"][0]["setup"]["claimed_setup"] = True
    else:
        entry = bundle["evidence"][1]
        path = root / entry["path"]
        envelope = json.loads(path.read_bytes())
        envelope["data"] = '{"setup_ok":true}'
        data = runner.canonical(envelope)
        path.write_bytes(data)
        entry.update(bytes=len(data), sha256=runner.sha(data))
    (root / "result.json").write_bytes(runner.canonical(bundle))
    with pytest.raises(runner.ValidationError):
        runner.verify_bundle(plan, root)


def testMeasurements_whenThirtyPairsThenReusedOrZeroEvidence_rejectsForgery(
    runner: typing.Any,
) -> None:
    records: dict[str, dict[str, typing.Any]] = {}
    samples = []
    for index in range(30):
        sample: dict[str, typing.Any] = {
            "index": index,
            "baseline": 10,
            "protected": 11,
        }
        for role, value in (("baseline", 10), ("protected", 11)):
            evidence_id = f"{role}_{index}"
            sample[role + "_evidence_id"] = evidence_id
            records[evidence_id] = {
                "run_id": "unit",
                "cell_id": "host",
                "nonce": "a" * 32,
                "phase": "execution",
                "metric": "scan",
                "index": index,
                "role": role,
                "value": value,
                "unit": "ns",
                "conditions_sha256": "b" * 64,
                "artifact_id": role,
            }
        samples.append(sample)
    pair = {
        "cell_id": "host",
        "metric": "scan",
        "unit": "ns",
        "conditions_sha256": "b" * 64,
        "baseline_artifact_id": "baseline",
        "protected_artifact_id": "protected",
        "expected_pairs": 30,
        "samples": samples,
        "missing_indices": [],
    }
    assert (
        runner.check_measurements([pair], records, {"host"}, {"baseline", "protected"})
        == 30
    )
    samples[0]["protected"] = 0
    with pytest.raises(runner.ValidationError):
        runner.check_measurements([pair], records, {"host"}, {"baseline", "protected"})
    samples[0]["protected"] = 11
    samples[0]["protected_evidence_id"] = samples[0]["baseline_evidence_id"]
    with pytest.raises(runner.ValidationError):
        runner.check_measurements([pair], records, {"host"}, {"baseline", "protected"})


def testTransport_whenBinaryStreamAndOwnedServerCleanup_keepsEndpointAndBounds(
    runner: typing.Any, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Labelled transport stand-in: no ADB binary, key use, socket or server connection."""
    root = tmp_path / "transport"
    root.mkdir(mode=0o700)
    data = b"binary transport fixture" * 16000
    files = [
        {
            "id": "adb",
            "path": "adb",
            "role": "tool",
            "bytes": 1,
            "sha256": runner.sha(b"x"),
        },
        {
            "id": "apk",
            "path": "apk",
            "role": "apk_signed",
            "bytes": len(data),
            "sha256": runner.sha(data),
        },
    ]
    recorder = runner.Recorder({"files": files}, root)
    cell = {"id": "android"}
    home = tmp_path / "synthetic_adb_home"
    (home / ".android").mkdir(parents=True)
    for name in ("adbkey", "adbkey.pub"):
        (home / ".android" / name).write_text("not a credential; transport fixture")
    python_path = pathlib.Path(sys.executable).resolve()
    interpreter = python_path.read_bytes()
    manifest = {
        "version": 1,
        "python": str(python_path),
        "prefix": sys.prefix,
        "files": [
            {
                "path": str(python_path),
                "bytes": len(interpreter),
                "sha256": runner.sha(interpreter),
            }
        ],
        "distributions": [],
    }
    lab = {
        "adb_file_id": "adb",
        "apk_file_id": "apk",
        "adb_home": str(home),
        "serial": "TRANSPORT_FIXTURE",
    }
    session = runner.AdbSession(
        recorder, cell, "a" * 32, lab, {"dependency_manifest": manifest}
    )
    calls: list[list[str]] = []
    killed: list[int] = []

    class TransportServer:
        pid = 2147483646
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            self.returncode = -signal.SIGKILL
            return self.returncode

    def transport(
        argv: list[str], cwd: pathlib.Path, **kwargs: typing.Any
    ) -> typing.Any:
        calls.append(argv)
        assert kwargs["no_fork"] is True
        assert kwargs["env"]["ADB_SERVER_SOCKET"] == session.endpoint
        binary_path = kwargs["binary_path"]
        binary_path.write_bytes(data)
        return runner.CommandResult(b"", b"", 0, "none", 1)

    def kill_owned(group: int, signum: int) -> None:
        assert signum == signal.SIGKILL
        killed.append(group)

    monkeypatch.setattr(runner, "command", transport)
    monkeypatch.setattr(os, "killpg", kill_owned)
    session.server = TransportServer()
    for name in ("server.stdout", "server.stderr"):
        (session.work / name).write_bytes(b"")
    artifact_path = root / "stream.apk"
    session.call(
        "apk_pre",
        ["exec-out", "cat", "/data/app/fixture/base.apk"],
        artifact_path=artifact_path,
    )
    assert artifact_path.stat().st_size > 256 * 1024
    assert recorder.artifacts[0]["sha256"] == runner.sha(data)
    assert calls[0][1:5] == ["-L", session.endpoint, "-s", "TRANSPORT_FIXTURE"]
    assert "5037" not in " ".join(calls[0])
    session.close()
    assert session.work.exists() is False
    assert killed == [TransportServer.pid]


def testCommand_whenBinaryArtifactExceedsTextCap_retainsExactStream(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    destination = tmp_path / "artifact"
    result = runner.command(
        [sys.executable, "-I", "-c", "import os; os.write(1,b'x'*300000)"],
        tmp_path,
        binary_path=destination,
    )
    assert result.reason == "none" and result.returncode == 0
    assert destination.read_bytes() == b"x" * 300000
    assert result.stdout == b""


def testRun_whenLabAbsentAndBenignContextsPlanned_neverInvokesAdbOrPassesRelease(
    native_bundle: tuple[dict[str, typing.Any], pathlib.Path],
    runner: typing.Any,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, bundle_root = native_bundle
    plan["cells"] = []
    for context in ("clean", "vpn", "accessibility", "ime", "support"):
        plan["cells"].append(
            {
                "id": context,
                "adapter": "android_adb",
                "scenario": "android_clean_receipt",
                "context": context,
                "facility": "physical",
                "target": {
                    "os": "android",
                    "os_version": "unit fixture",
                    "api": 35,
                    "model": "unit fixture",
                    "abi": "arm64-v8a",
                    "page_size": 4096,
                    "facility": "physical",
                    "device_id": "b" * 64,
                    "channel": "preinstalled_lab",
                },
                "required": True,
                "artifact_ids": [],
                "expected": "not_run",
            }
        )
    calls: list[list[str]] = []

    def only_source_reads(
        argv: list[str], cwd: pathlib.Path, **kwargs: typing.Any
    ) -> typing.Any:
        calls.append(argv)
        assert argv[0] == "/usr/bin/git"
        data = (
            ("1" * 40 + "\n" + "2" * 40 + "\n").encode() if "rev-parse" in argv else b""
        )
        return runner.CommandResult(data, b"", 0, "none", 1)

    monkeypatch.setattr(runner, "command", only_source_reads)
    result = runner.run_plan(plan, bundle_root / "inputs", tmp_path / "no_lab")
    assert len(calls) == 2
    assert result["summary"]["planned"] == 5
    assert result["summary"]["by_outcome"]["not_run"] == 5
    assert result["summary"]["release_gate"] == "fail"
    assert all(row["observation"]["state"] == "not_run" for row in result["results"])


def testSummary_whenExpectedErrorHasFailedCleanup_failsConformance(
    runner: typing.Any,
) -> None:
    cells = [{"id": "host", "required": False, "expected": "error"}]
    results = [
        {
            "cell_id": "host",
            "outcome": "error",
            "execution": {"state": "verified"},
            "cleanup": {"state": "failed"},
        }
    ]
    assert runner.summarize(cells, results)["conformance"] == "fail"

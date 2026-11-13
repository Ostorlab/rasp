"""Exercise validation trust boundaries and real child lifetimes; no device claims."""

from __future__ import annotations

import copy
import errno
import importlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import types
import typing
from xml.sax import saxutils

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
    monkeypatch.setattr(os, "waitid", lambda *args: None)
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


@pytest.fixture
def transport_session(runner: typing.Any, tmp_path: pathlib.Path) -> typing.Any:
    """Local protocol state only; placeholder text is neither a key nor an APK."""
    home = tmp_path / "synthetic_home"
    (home / ".android").mkdir(parents=True)
    for name in ("adbkey", "adbkey.pub"):
        (home / ".android" / name).write_text(
            "not a credential; unit transport placeholder"
        )
    payload = b"not a signed APK; unit transport placeholder"
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
            "bytes": len(payload),
            "sha256": runner.sha(payload),
        },
    ]
    python = pathlib.Path(sys.executable).resolve()
    manifest = {
        "version": 1,
        "python": str(python),
        "prefix": sys.prefix,
        "files": [
            {
                "path": str(python),
                "bytes": python.stat().st_size,
                "sha256": runner.sha(python.read_bytes()),
            }
        ],
        "distributions": [],
    }
    recorder = runner.Recorder({"files": files}, tmp_path)
    session = runner.AdbSession(
        recorder,
        {"id": "android"},
        "d" * 32,
        {
            "adb_file_id": "adb",
            "apk_file_id": "apk",
            "adb_home": str(home),
            "serial": "UNIT_ONLY",
        },
        {"dependency_manifest": manifest},
    )
    yield session
    if session.work.exists() is True and len(list(session.work.iterdir())) == 0:
        session.work.rmdir()


@pytest.mark.parametrize("route", ["command", "dead_server"])
def testProcessLease_whenLeaderExits_signalsBeforeReaping(
    route: str,
    runner: typing.Any,
    transport_session: typing.Any,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    processes: list[subprocess.Popen[bytes]] = []
    original_signal = os.killpg

    class Observed(subprocess.Popen[bytes]):
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            super().__init__(*args, **kwargs)
            processes.append(self)

        def wait(self, *args: typing.Any, **kwargs: typing.Any) -> int:
            value = super().wait(*args, **kwargs)
            events.append("reaped")
            return value

    def safe_signal(group: int, signum: int) -> None:
        process = next(process for process in processes if process.pid == group)
        events.append(
            "unsafe_signal" if process.returncode is not None else "leased_signal"
        )
        if process.returncode is None:
            original_signal(group, signum)

    monkeypatch.setattr(subprocess, "Popen", Observed)
    monkeypatch.setattr(os, "killpg", safe_signal)
    if route == "command":
        assert runner.command(["/usr/bin/true"], tmp_path).returncode == 0
    else:
        process = Observed(
            ["/usr/bin/true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        transport_session.server = process
        for name in ("server.stdout", "server.stderr"):
            (transport_session.work / name).write_bytes(b"")
        deadline = time.monotonic() + 2
        while (
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            is None
        ):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        with pytest.raises(runner.ValidationError):
            transport_session.alive()
        transport_session.close()
    assert "unsafe_signal" not in events
    assert events[0] == "leased_signal" and events[-1] == "reaped"


@pytest.mark.parametrize("refusal", ["wrong_device", "wrong_apk", "preexisting_xml"])
def testAndroidAdmission_whenRefused_preservesRemotePackageAndXml(
    refusal: str,
    runner: typing.Any,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace: list[str] = []
    serial, fingerprint = "UNIT", "SYNTHETIC_NOT_A_DEVICE"
    device = runner.sha(b"val01.device.v1\0" + (serial + "\n" + fingerprint).encode())
    lab = {
        "serial": serial,
        "device_id": "0" * 64 if refusal == "wrong_device" else device,
    }
    cell = {
        "id": "android",
        "scenario": "android_clean_receipt",
        "context": "clean",
        "facility": "physical",
        "target": {
            "os": "android",
            "os_version": "15",
            "api": 35,
            "model": "UNIT",
            "abi": "arm64-v8a",
            "page_size": 4096,
            "facility": "physical",
            "device_id": lab["device_id"],
            "channel": "preinstalled_lab",
        },
    }

    class TransportOnly:
        def __init__(self, *args: typing.Any) -> None:
            self.stage = "setup"
            self.server = object()
            self.refs: dict[str, list[str]] = {stage: [] for stage in runner.PHASES}

        def start(self) -> None:
            trace.append("local_start")

        def call(self, probe: str, args: list[str], **kwargs: typing.Any) -> bytes:
            trace.append(probe)
            if (probe == "apk_pre" and refusal == "wrong_apk") or (
                probe == "xml_pre" and refusal == "preexisting_xml"
            ):
                raise runner.ValidationError(
                    "artifact_mismatch"
                    if probe == "apk_pre"
                    else "collection_unavailable"
                )
            return {
                "get_state": b"device",
                "env_api": b"35",
                "env_os_version": b"15",
                "env_model": b"UNIT",
                "env_abi": b"arm64-v8a",
                "env_emulator": b"0",
                "env_fingerprint": fingerprint.encode(),
                "env_pages": b"4096",
                "package_path": b"package:/data/app/UNIT/base.apk",
            }.get(probe, b"")

        def close(self) -> None:
            trace.append("local_close")

    monkeypatch.setattr(runner, "AdbSession", TransportOnly)
    result = runner.android_run(
        types.SimpleNamespace(root=tmp_path),
        cell,
        "e" * 32,
        lab,
        {"abis": ["arm64-v8a"]},
    )
    assert result["outcome"] == "error"
    assert trace[-1] == "local_close"
    assert set(trace).isdisjoint(
        {"force_stop_pre", "force_stop_post", "remove_xml", "launch_baseline"}
    )


@pytest.mark.parametrize("boundary", ["count", "bytes"])
def testStreamCapacity_whenCleanupReservationCannotFit_refusesBeforeTransport(
    boundary: str,
    runner: typing.Any,
    transport_session: typing.Any,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = transport_session
    if boundary == "count":
        session.recorder.plan["files"].extend(
            {
                "id": f"padding_{index}",
                "path": f"padding_{index}",
                "role": "fixture_source",
                "bytes": 0,
                "sha256": runner.sha(b""),
            }
            for index in range(93)
        )
    else:
        total = sum(row["bytes"] for row in session.recorder.plan["files"])
        remaining = 256 * runner.MIB - total - 1
        for index in range(4):
            size = min(remaining, 64 * runner.MIB)
            session.recorder.plan["files"].append(
                {
                    "id": f"padding_{index}",
                    "path": f"padding_{index}",
                    "role": "fixture_source",
                    "bytes": size,
                    "sha256": "0" * 64,
                }
            )
            remaining -= size
    session.server = types.SimpleNamespace(
        pid=2147483645, returncode=None, poll=lambda: None
    )
    for name in ("server.stdout", "server.stderr"):
        (session.work / name).write_bytes(b"")
    called: list[str] = []

    def transport(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        called.append("transport")
        kwargs["binary_path"].write_bytes(b"x")
        return runner.CommandResult(b"", b"", 0, "none", 1)

    monkeypatch.setattr(runner, "command", transport)
    destination = tmp_path / "refused.apk"
    with pytest.raises(runner.ValidationError):
        session.call(
            "apk_pre",
            ["exec-out", "cat", "/data/app/UNIT/base.apk"],
            artifact_path=destination,
        )
    assert called == [] and destination.exists() is False
    for name in ("server.stdout", "server.stderr"):
        (session.work / name).unlink()


def testReader_whenRealAuditRefusesWrapper_closesRawDescriptor(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    code = """import json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
from validation import run
root=pathlib.Path(sys.argv[2]);target=root/'owned';target.write_bytes(b'owned')
def refuse(event,args):
    if event=='open' and isinstance(args[0],int): raise OSError(13,'unit audit refusal')
sys.addaudithook(refuse)
try: run.read_file(root,'owned',32)
except run.ValidationError: pass
leaked=[]
for name in os.listdir('/proc/self/fd'):
    try:
        if os.readlink('/proc/self/fd/'+name)==str(target): leaked.append(int(name))
    except FileNotFoundError: pass
for descriptor in leaked: os.close(descriptor)
print(json.dumps({'leaked':len(leaked)}))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            str(pathlib.Path(__file__).parents[2]),
            str(tmp_path),
        ],
        capture_output=True,
        check=True,
        timeout=5,
    )
    assert json.loads(result.stdout) == {"leaked": 0}


@pytest.mark.parametrize("failure", ["host_target", "host_invoke", "constructor"])
def testScratch_whenHostOrConstructorAdmissionFails_leavesNoUnownedDirectory(
    failure: str,
    native_bundle: tuple[dict[str, typing.Any], pathlib.Path],
    runner: typing.Any,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, root = native_bundle
    cell = copy.deepcopy(plan["cells"][0])
    recorder = runner.Recorder(plan, root)
    if failure != "constructor":
        if failure == "host_target":
            cell["target"]["page_size"] += 1
        else:

            def fail_invoke(*args: typing.Any, **kwargs: typing.Any) -> typing.NoReturn:
                raise OSError(errno.EMFILE, "unit process acquisition failure")

            monkeypatch.setattr(recorder, "invoke", fail_invoke)
        try:
            with pytest.raises(
                runner.ValidationError if failure == "host_target" else OSError
            ):
                runner.host_run(
                    recorder,
                    cell,
                    "f" * 32,
                    runner.checked_files(plan, root / "inputs"),
                )
            assert list(root.glob("scratch_*")) == []
            assert recorder.commands == 0
        finally:
            for path in root.glob("scratch_*"):
                path.rmdir()

        return
    recorder.plan = {"files": [{"id": "adb", "path": "adb", "role": "tool"}]}
    home = tmp_path / "empty_noncredential_home"
    home.mkdir()
    original_temp = runner.tempfile.mkdtemp
    created: list[pathlib.Path] = []

    def owned_temp(**kwargs: typing.Any) -> str:
        path = original_temp(prefix="unit-", dir=tmp_path)
        created.append(pathlib.Path(path))
        return str(path)

    monkeypatch.setattr(runner.tempfile, "mkdtemp", owned_temp)
    try:
        with pytest.raises(FileNotFoundError):
            runner.AdbSession(
                recorder,
                {"id": "android"},
                "f" * 32,
                {"adb_file_id": "adb", "adb_home": str(home)},
                {},
            )
        assert all(path.exists() is False for path in created)
    finally:
        for path in created:
            if path.exists() is True:
                path.rmdir()


@pytest.fixture(scope="module")
def android_protocol_bundle(tmp_path_factory: pytest.TempPathFactory) -> typing.Any:
    """Synthetic protocol claims over genuine unsigned prepared bytes; no device/signature credit."""
    run = importlib.import_module("validation.run")
    source = pathlib.Path(os.environ["VAL01_ANDROID_INPUTS"])
    root = tmp_path_factory.mktemp("synthetic_offline_android")
    root.chmod(0o700)
    records = copy.deepcopy(
        json.loads((source / "result.json").read_bytes())["input_files"]
    )
    payloads = {row["id"]: (source / row["path"]).read_bytes() for row in records}
    next(row for row in records if row["id"] == "apk")["role"] = "apk_signed"
    for module in (
        "archive_validation",
        "capabilities",
        "local_policy",
        "runtime_config",
        "verification",
        "platforms",
        "errors",
        "android.resources",
        "android.runtime_library",
    ):
        importlib.import_module("rasp_packer." + module)
    dependencies = run.decode(payloads["dependencies"])
    assert dependencies["prefix"] == sys.prefix, (
        "run integration controls in the pinned installed packer environment"
    )
    bindings = {row["path"]: row for row in dependencies["files"]}
    # This test process adds pytest/native mappings and the changed runner under test.
    # Measure their actual bytes; do not change any original production dependency.
    extra = {
        str(pathlib.Path(str(run.__file__)).resolve()),
        str(pathlib.Path(os.environ["VAL01_ADB_SNAPSHOT"]).resolve()),
    }
    for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith("/"):
            extra.add(str(pathlib.Path(parts[5]).resolve()))
    for name in extra:
        path = pathlib.Path(name)
        bindings[name] = {
            "path": name,
            "bytes": path.stat().st_size,
            "sha256": run.sha(path.read_bytes()),
        }
    dependencies["files"] = sorted(bindings.values(), key=lambda row: row["path"])
    payloads["dependencies"] = run.canonical(dependencies)
    dependency_record = next(row for row in records if row["id"] == "dependencies")
    dependency_record.update(
        bytes=len(payloads["dependencies"]), sha256=run.sha(payloads["dependencies"])
    )

    def add(file_id: str, role: str, data: bytes) -> None:
        payloads[file_id] = data
        records.append(
            {
                "id": file_id,
                "path": file_id,
                "role": role,
                "bytes": len(data),
                "sha256": run.sha(data),
            }
        )

    tool = pathlib.Path(os.environ["VAL01_ADB_SNAPSHOT"]).read_bytes()
    add("adb", "tool", tool)
    add("registry", "registry", b"std::array<const Plugin*, 0> kPlugins{};")
    add("runner", "suite_source", pathlib.Path(str(run.__file__)).read_bytes())
    serial, fingerprint = "UNIT_PROTOCOL_ONLY", "SYNTHETIC_NOT_A_DEVICE"
    device = run.sha(b"val01.device.v1\0" + (serial + "\n" + fingerprint).encode())
    provision = b"synthetic protocol unit fixture; not a lab provisioning receipt"
    add("provision", "provisioning_receipt", provision)
    lab = {
        "version": 1,
        "owned_lab": True,
        "serial": serial,
        "device_id": device,
        "apk_file_id": "apk",
        "provisioning_receipt_sha256": run.sha(provision),
        "adb_file_id": "adb",
        "transport": "usb",
        "network_isolation": True,
        "preauthorized": True,
        "adb_home": "/tmp/UNIT_NO_CREDENTIALS_OR_SERVER",
    }
    add("lab", "lab_descriptor", run.canonical(lab))
    receipt = run.canonical(
        {
            "version": 1,
            "source_head": "1" * 40,
            "source_tree": "2" * 40,
            "tool_ids": ["adb"],
            "flags": ["synthetic protocol claims only"],
            "plugins": [],
            "registry_file": "registry",
            "products": [
                row["id"]
                for row in records
                if row["role"]
                in {
                    "native_pristine",
                    "native_injected",
                    "apk_signed",
                    "stub",
                    "bridge_jar",
                }
            ],
            "dependency_manifest": "dependencies",
        }
    )
    add("receipt", "build_receipt", receipt)
    suite = sorted(
        (row for row in records if row["role"] in {"suite_source", "fixture_source"}),
        key=lambda row: row["path"],
    )
    actual = {
        "os": "android",
        "os_version": "15",
        "api": 35,
        "model": "UNIT",
        "abi": "arm64-v8a",
        "page_size": 4096,
        "facility": "physical",
        "device_id": device,
        "channel": "preinstalled_lab",
    }
    cell = {
        "id": "android",
        "adapter": "android_adb",
        "scenario": "android_clean_receipt",
        "context": "clean",
        "facility": "physical",
        "target": actual,
        "required": True,
        "artifact_ids": [row["id"] for row in records],
        "expected": "benign",
    }
    plan = {
        "version": 1,
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "build_receipt_sha256": run.sha(receipt),
        "suite_sha256": run.sha(b"val01.suite.v1\0" + run.canonical(suite)),
        "files": records,
        "cells": [cell],
    }
    for row in records:
        run.write_file(
            root, "inputs/" + row["path"], payloads[row["id"]], row["role"] == "tool"
        )
    run.write_file(root, "plan.json", run.canonical(plan))
    preflight = run.android_preflight(plan, payloads, root / "inputs")
    recorder = run.Recorder(plan, root)
    nonce = "a" * 32
    refs: dict[str, list[str]] = {stage: [] for stage in run.PHASES}

    def capture(
        stage: str,
        probe: str,
        data: bytes = b"",
        code: int = 0,
        artifact: typing.Any = None,
    ) -> None:
        refs[stage].append(
            recorder.capture(
                cell,
                nonce,
                stage,
                "adb",
                probe,
                data,
                run.CommandResult(b"", b"", code, "none", 0),
                artifact,
            )
        )

    endpoint, server_pid = "localfilesystem:/tmp/v01-UNIT/server.sock", 12345
    capture(
        "setup",
        "adb_help",
        b"Version 35.0.2-12147458 -L SOCKET server nodaemon one USB device",
    )
    capture(
        "setup",
        "server_started",
        run.canonical(
            {
                "pid": server_pid,
                "endpoint": endpoint,
                "device_restriction": "usb_only",
                "tool_sha256": run.sha(tool),
            }
        ),
    )
    capture("setup", "get_state", b"device")
    for key, value in {
        "api": "35",
        "os_version": "15",
        "model": "UNIT",
        "abi": "arm64-v8a",
        "emulator": "0",
        "fingerprint": fingerprint,
        "pages": "4096",
    }.items():
        capture("setup", "env_" + key, value.encode())
    capture("setup", "package_path", b"package:/data/app/UNIT/base.apk")
    for stage, probe in (("setup", "apk_pre"), ("cleanup", "apk_post")):
        artifact_path = "artifacts/" + probe + ".apk"
        run.write_file(root, artifact_path, payloads["apk"])
        artifact = {
            "path": artifact_path,
            "bytes": len(payloads["apk"]),
            "sha256": run.sha(payloads["apk"]),
            "file_id": "apk",
            "run_id": recorder.run_id,
            "cell_id": "android",
            "nonce": nonce,
            "phase": stage,
        }
        recorder.artifacts.append(artifact)
        capture(stage, probe, artifact=artifact)
    for stage, probes in (
        ("setup", ["xml_pre", "force_stop_pre", "process_pre"]),
        ("cleanup", ["force_stop_post", "remove_xml", "xml_post", "process_post"]),
    ):
        for probe in probes:
            capture(
                stage, probe, code=1 if probe.startswith(("process_", "xml_")) else 0
            )
    # Reorder the synthetic post-state stream to the actual fixed cleanup sequence.
    refs["cleanup"].append(refs["cleanup"].pop(0))
    for stage in ("baseline", "execution"):
        capture(stage, "launch_" + stage)
        capture(stage, "dump_" + stage)
        event = {
            "nonce": nonce,
            "scenario": cell["scenario"],
            "phase": stage,
            "policy_sha256": preflight["policy_sha256"],
            "config_sha256": preflight["config_sha256"],
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
        capture(
            stage,
            "ui_" + stage,
            (
                '<hierarchy><node resource-id="fixture.validation:id/status" text='
                + saxutils.quoteattr(run.canonical(event).decode())
                + "/></hierarchy>"
            ).encode(),
        )
    capture("cleanup", "server_stdout")
    capture("cleanup", "server_stderr")
    capture(
        "cleanup",
        "server_cleanup",
        run.canonical(
            {
                "server_reaped": True,
                "endpoint_removed": True,
                "client_fork_limit": 0,
                "pid": server_pid,
                "endpoint": endpoint,
            }
        ),
    )
    result = run.empty_result(cell, nonce, "none")
    result.update(environment=actual, outcome="benign", reason="none")
    for stage in run.PHASES:
        result[stage] = run.phase("verified", "none", refs[stage])
    result["observation"] = {
        "state": "absent",
        "rule_id": event["rule_id"],
        "rule_version": 1,
        "status": 0,
        "evidence_ids": refs["execution"],
    }
    result["operation"] = {
        "state": "completed",
        "api_status": 0,
        "action": 2,
        "gate_reason": 12,
        "before": 0,
        "after": 1,
        "policy_sha256": preflight["policy_sha256"],
        "config_sha256": preflight["config_sha256"],
        "evidence_ids": refs["execution"],
    }
    bundle = {
        "version": 1,
        "run_id": recorder.run_id,
        "plan_sha256": run.sha(b"val01.plan.v1\0" + run.canonical(plan)),
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
        "artifacts": recorder.artifacts,
        "measurements": [],
        "summary": run.summarize([cell], [result]),
    }
    run.write_file(root, "result.json", run.canonical(bundle))
    assert run.verify_bundle(plan, root)["summary"]["release_gate"] == "pass"
    return plan, root, payloads


@pytest.mark.parametrize(
    "fault",
    [
        "absence_stderr",
        "absence_stdout",
        "offline",
        "unowned",
        "bad_help",
        "bad_path",
        "missing_pre_stop",
        "missing_launch",
        "missing_dump",
        "failed_launch",
    ],
)
def testOfflineAndroid_whenProtocolContradictsAdmission_rejectsThroughRealValidators(
    fault: str, android_protocol_bundle: typing.Any, runner: typing.Any
) -> None:
    baseline_plan, root, _ = android_protocol_bundle
    plan = copy.deepcopy(baseline_plan)
    original_bundle = (root / "result.json").read_bytes()
    bundle = json.loads(original_bundle)
    restored: dict[pathlib.Path, bytes] = {
        root / "result.json": original_bundle,
        root / "plan.json": (root / "plan.json").read_bytes(),
    }
    try:
        if fault == "unowned":
            path = root / "inputs/lab"
            restored[path] = path.read_bytes()
            lab = json.loads(restored[path])
            lab.update(
                owned_lab=False,
                preauthorized=False,
                network_isolation=False,
                transport="tcp",
            )
            data = runner.canonical(lab)
            path.write_bytes(data)
            next(row for row in plan["files"] if row["id"] == "lab").update(
                bytes=len(data), sha256=runner.sha(data)
            )
            bundle["plan_sha256"] = runner.sha(
                b"val01.plan.v1\0" + runner.canonical(plan)
            )
            (root / "plan.json").write_bytes(runner.canonical(plan))
        else:
            probe = {
                "absence_stderr": "process_post",
                "absence_stdout": "xml_post",
                "offline": "get_state",
                "bad_help": "adb_help",
                "bad_path": "package_path",
                "missing_pre_stop": "force_stop_pre",
                "missing_launch": "launch_baseline",
                "missing_dump": "dump_execution",
                "failed_launch": "launch_execution",
            }[fault]
            entry = next(
                row
                for row in bundle["evidence"]
                if json.loads((root / row["path"]).read_bytes())["probe"] == probe
            )
            path = root / entry["path"]
            restored[path] = path.read_bytes()
            envelope = json.loads(restored[path])
            if fault == "absence_stderr":
                envelope["stderr"] = "pidof: Permission denied\n"
            elif fault == "absence_stdout":
                envelope["data"] = "file still exists"
            elif fault == "offline":
                envelope["data"] = "offline"
            elif fault == "bad_help":
                envelope["data"] = "unsupported tool"
            elif fault == "bad_path":
                envelope["data"] = (
                    "package:/data/app/OTHER/base.apk\npackage:/data/app/SPLIT/base.apk"
                )
            elif fault.startswith("missing_"):
                bundle["evidence"].remove(entry)
                for stage in runner.PHASES:
                    refs = bundle["results"][0][stage]["evidence_ids"]
                    if entry["id"] in refs:
                        refs.remove(entry["id"])
                for role in ("operation", "observation"):
                    refs = bundle["results"][0][role]["evidence_ids"]
                    if entry["id"] in refs:
                        refs.remove(entry["id"])
                path.unlink()
            else:
                envelope["exit_code"] = 1
            if fault.startswith("missing_") is False:
                data = runner.canonical(envelope)
                path.write_bytes(data)
                entry.update(bytes=len(data), sha256=runner.sha(data))
        (root / "result.json").write_bytes(runner.canonical(bundle))
        with pytest.raises(runner.ValidationError):
            runner.verify_bundle(plan, root)
    finally:
        for path, data in restored.items():
            path.write_bytes(data)
            path.chmod(0o600)


def testPreflight_whenRetainedConfigDiffersFromProductionConfig_rejects(
    android_protocol_bundle: typing.Any, runner: typing.Any
) -> None:
    baseline_plan, root, payloads = android_protocol_bundle
    config_module = importlib.import_module("rasp_packer.runtime_config")
    policy_module = importlib.import_module("rasp_packer.local_policy")
    policy = policy_module.parse(payloads["policy"])
    different = config_module.RuntimeConfig(
        build_id="different-valid-config",
        checks=("debugger", "identity"),
        local_policy=policy,
    ).to_json()
    changed = {**payloads, "config": different}
    plan = copy.deepcopy(baseline_plan)
    next(row for row in plan["files"] if row["role"] == "config").update(
        bytes=len(different), sha256=runner.sha(different)
    )
    with pytest.raises(runner.ValidationError, match="retained config mismatch"):
        runner.android_preflight(plan, changed, root / "inputs")


@pytest.mark.parametrize("route", ["normal", "timeout", "overflow"])
def testCommand_whenLeaderHasDescendant_killsOriginalGroupBeforeReaping(
    route: str, tmp_path: pathlib.Path
) -> None:
    # A separate subreaper owns/reaps the grandchild; no persistent test-process state.
    harness = """import ctypes,json,os,pathlib,signal,sys,time
sys.path.insert(0,sys.argv[1])
from validation import run
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
root=pathlib.Path(sys.argv[2]);route=sys.argv[3]
code=\"\"\"import os,pathlib,sys,time
child=os.fork()
if child==0:
    os.close(1);os.close(2);time.sleep(20);os._exit(0)
pathlib.Path('descendant').write_text(str(child))
if sys.argv[1]=='normal': sys.exit(0)
if sys.argv[1]=='overflow': os.write(1,b'x'*300000)
time.sleep(20)
\"\"\"
result=run.command([sys.executable,'-I','-c',code,route],root,timeout=0.5)
child=int((root/'descendant').read_text());deadline=time.monotonic()+2
status=None
try:
    while time.monotonic()<deadline:
        pid,state=os.waitpid(child,os.WNOHANG)
        if pid==child: status=state;break
        time.sleep(0.01)
finally:
    if status is None:
        os.kill(child,signal.SIGKILL);os.waitpid(child,0)
assert status is not None and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
try: os.kill(child,0)
except ProcessLookupError: pass
else: raise AssertionError('descendant survived')
print(json.dumps({'reason':result.reason,'reaped_descendant':True}))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            harness,
            str(pathlib.Path(__file__).parents[2]),
            str(tmp_path),
            route,
        ],
        capture_output=True,
        check=True,
        timeout=6,
    )
    assert json.loads(result.stdout) == {
        "reason": {
            "normal": "none",
            "timeout": "timeout",
            "overflow": "resource_limit",
        }[route],
        "reaped_descendant": True,
    }


def testCommand_whenBinaryStreamExceedsPinnedSize_refusesWithinReservation(
    runner: typing.Any, tmp_path: pathlib.Path
) -> None:
    destination = tmp_path / "bounded.apk"
    result = runner.command(
        [sys.executable, "-I", "-c", "import os; os.write(1,b'x'*20000)"],
        tmp_path,
        binary_path=destination,
        binary_limit=10000,
    )
    assert result.reason == "resource_limit"
    assert destination.stat().st_size <= 10000

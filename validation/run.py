"""Bounded local validation. Client evidence is neither attestation nor a sandbox."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.metadata
import io
import json
import os
import pathlib
import platform
import re
import resource
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import typing
import uuid
import xml.etree.ElementTree as element_tree
import zipfile

MIB = 1024 * 1024
OUTCOMES = (
    "observed_detection",
    "business_denial",
    "bypass",
    "benign",
    "crash",
    "error",
    "unsupported",
    "not_run",
)
PHASES = ("baseline", "setup", "execution", "cleanup")
PROBES = {
    "host_event",
    "host_failure",
    "host_cleanup",
    "adb_help",
    "server_started",
    "server_stdout",
    "server_stderr",
    "server_cleanup",
    "get_state",
    "env_api",
    "env_os_version",
    "env_model",
    "env_abi",
    "env_emulator",
    "env_fingerprint",
    "env_pages",
    "package_path",
    "apk_pre",
    "apk_post",
    "force_stop_pre",
    "force_stop_post",
    "process_pre",
    "process_post",
    "xml_pre",
    "xml_post",
    "launch_baseline",
    "launch_execution",
    "dump_baseline",
    "dump_execution",
    "ui_baseline",
    "ui_execution",
    "remove_xml",
}
REASONS = {
    "none",
    "runtime_unavailable",
    "facility_missing",
    "adapter_unavailable",
    "budget_exhausted",
    "unsupported_environment",
    "invalid_input",
    "artifact_mismatch",
    "source_mismatch",
    "evidence_mismatch",
    "duplicate_evidence",
    "baseline_failed",
    "setup_failed",
    "cleanup_failed",
    "timeout",
    "resource_limit",
    "process_crash",
    "operation_mismatch",
    "policy_hash_mismatch",
    "collection_unavailable",
}
ROLES = {
    "host_executable",
    "native_pristine",
    "native_injected",
    "apk_signed",
    "apk_unsigned",
    "stub",
    "bridge_jar",
    "capabilities",
    "policy_support",
    "policy",
    "config",
    "registry",
    "build_receipt",
    "suite_source",
    "fixture_source",
    "tool",
    "lab_descriptor",
    "provisioning_receipt",
    "dependency_manifest",
    "wheel",
    "injection_manifest",
    "injected_entry",
}
ENV_KEYS = "os os_version api model abi page_size facility device_id channel"
FIXTURE_KEYS = "nonce scenario phase policy_sha256 config_sha256 status action reason before after rule_id rule_version rule_status rule_evaluated rule_verdict"


class ValidationError(Exception):
    """Reject input or evidence before it can establish success."""


def require(condition: bool, message: str) -> None:
    """Fail a checked invariant, including under python -O."""
    if condition is not True:
        raise ValidationError(message)


def obj(value: typing.Any, keys: str) -> dict[str, typing.Any]:
    """Require a closed dictionary."""
    require(
        type(value) is dict and set(value) == set(keys.split()),
        "unknown or missing fields",
    )
    return typing.cast(dict[str, typing.Any], value)


def integer(value: typing.Any, low: int = 0, high: int = 2**63 - 1) -> int:
    """Reject bool, floats and overflow at numeric boundaries."""
    require(type(value) is int and low <= value <= high, "integer outside bounds")
    return typing.cast(int, value)


def text(value: typing.Any, pattern: str = r"[\x20-\x7e]{1,128}") -> str:
    """Validate ASCII labels and identifiers without coercion."""
    require(
        type(value) is str and re.fullmatch(pattern, value) is not None, "invalid text"
    )
    return typing.cast(str, value)


def ident(value: typing.Any) -> str:
    """Validate a local record identifier."""
    return text(value, r"[a-z][a-z0-9_]{0,47}")


def digest(value: typing.Any) -> str:
    """Require an exact SHA-256 representation."""
    return text(value, r"[a-f0-9]{64}")


def array(value: typing.Any, maximum: int, minimum: int = 0) -> list[typing.Any]:
    """Bound collection cardinality before iteration."""
    require(
        type(value) is list and minimum <= len(value) <= maximum, "array outside bounds"
    )
    return typing.cast(list[typing.Any], value)


def canonical(value: typing.Any) -> bytes:
    """Encode validation identities, independently of production policy hashing."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def sha(data: bytes) -> str:
    """Hash exact bytes, never an artifact label."""
    return hashlib.sha256(data).hexdigest()


def decode(data: bytes, limit: int = MIB) -> typing.Any:
    """Bound JSON lexical depth and reject ambiguous numbers and duplicate members."""
    require(
        len(data) <= limit and data.startswith(b"\xef\xbb\xbf") is False,
        "JSON byte limit/BOM",
    )
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted is True:
            if escaped is True:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 12, "JSON depth limit")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items: list[tuple[str, typing.Any]]) -> dict[str, typing.Any]:
        result: dict[str, typing.Any] = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    def number(token: str) -> int:
        require(re.fullmatch(r"[0-9]{1,19}", token) is not None, "invalid integer")
        return integer(int(token))

    def invalid(token: str) -> typing.NoReturn:
        raise ValidationError("noninteger JSON number: " + token[:24])

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_int=number,
            parse_float=invalid,
            parse_constant=invalid,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValidationError("invalid JSON") from error


def relative(value: typing.Any) -> str:
    """Refuse path aliases before walking directory descriptors."""
    path = text(value, r"[A-Za-z0-9_./+-]{1,240}")
    require(all(part not in {"", ".", ".."} for part in path.split("/")), "unsafe path")
    return path


def read_file(root: pathlib.Path, name: str, maximum: int) -> bytes:
    """Read below a caller-prevalidated root; refuse its final link and relative links."""
    parts = relative(name).split("/")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            following = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = following
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                before = os.fstat(stream.fileno())
                require(
                    stat.S_ISREG(before.st_mode)
                    and before.st_nlink == 1
                    and before.st_size <= maximum,
                    "unsafe file or byte limit",
                )
                data = stream.read(maximum + 1)
                after = os.fstat(stream.fileno())
                linked = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
                require(
                    (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    == (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ),
                    "changed input",
                )
                require(
                    (linked.st_dev, linked.st_ino) == (before.st_dev, before.st_ino)
                    and len(data) <= maximum,
                    "replaced input",
                )
                return data
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValidationError("unreadable regular input") from error
    finally:
        os.close(directory)


def write_file(
    root: pathlib.Path, name: str, data: bytes, executable: bool = False
) -> None:
    """Create private artifacts without replacing existing files."""
    destination = root / relative(name)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    destination.chmod(0o700 if executable is True else 0o600)


@dataclasses.dataclass(frozen=True, slots=True)
class CommandResult:
    """Actual process termination and bounded captured bytes."""

    stdout: bytes
    stderr: bytes
    returncode: int
    reason: str
    elapsed_ms: int


def child_limits() -> None:
    """Set limits only in our child, never in the application runtime."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_AS, (256 * MIB, 256 * MIB))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MIB, MIB))


def child_argv(argv: list[str], no_fork: bool = False) -> list[str]:
    """Set limits in a fresh interpreter before exec, avoiding unsafe preexec hooks."""
    return [
        sys.executable,
        "-I",
        "-B",
        str(pathlib.Path(__file__).resolve()),
        "--bounded-child",
        "1" if no_fork is True else "0",
        *argv,
    ]


def process_exited(process: subprocess.Popen[bytes]) -> bool:
    """Observe exit without releasing the leader PID/PGID ownership lease."""
    require(process.returncode is None, "owned process already reaped")
    try:
        return (
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            is not None
        )
    except ChildProcessError as error:
        raise ValidationError("owned process lease lost") from error


def signal_owned_group(process: subprocess.Popen[bytes]) -> None:
    """Signal only while our unreaped child still reserves its group identity."""
    process_exited(process)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def command(
    argv: list[str],
    cwd: pathlib.Path,
    timeout: float = 15,
    binary_path: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    no_fork: bool = False,
    binary_limit: int = 64 * MIB,
) -> CommandResult:
    """Drain both pipes under deadline; kill/reap the owned group on every exit."""
    require(0 < timeout <= 15, "command deadline")
    start = time.monotonic()
    output = bytearray()
    errors = bytearray()
    maximum = (
        integer(binary_limit, 0, 64 * MIB) if binary_path is not None else 256 * 1024
    )
    binary_count = 0
    reason = "none"
    environment = (
        {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": str(cwd),
            "TMPDIR": str(cwd),
        }
        if env is None
        else env
    )
    require(
        no_fork is False or os.geteuid() != 0, "root clients cannot enforce no-fork"
    )
    process = subprocess.Popen(
        child_argv(argv, no_fork),
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    binary: typing.BinaryIO | None = None
    try:
        require(
            process.stdout is not None and process.stderr is not None, "missing pipes"
        )
        stdout = typing.cast(typing.BinaryIO, process.stdout)
        stderr = typing.cast(typing.BinaryIO, process.stderr)
        binary = (
            typing.cast(typing.BinaryIO, binary_path.open("xb"))
            if binary_path is not None
            else None
        )
        with selectors.DefaultSelector() as selector:
            selector.register(stdout, selectors.EVENT_READ, "out")
            selector.register(stderr, selectors.EVENT_READ, "err")
            while len(selector.get_map()) > 0:
                remaining = start + timeout - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fd, 65536)
                    if len(chunk) == 0:
                        selector.unregister(key.fileobj)
                    elif key.data == "out" and binary is not None:
                        binary_count += len(chunk)
                        if binary_count > maximum:
                            reason = "resource_limit"
                            break
                        binary.write(chunk)
                    else:
                        target = output if key.data == "out" else errors
                        if len(target) + len(chunk) > min(maximum, 256 * 1024):
                            reason = "resource_limit"
                            break
                        target.extend(chunk)
                if reason != "none":
                    break
            if reason == "none":
                while process_exited(process) is False:
                    remaining = start + timeout - time.monotonic()
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    time.sleep(min(remaining, 0.01))
    finally:
        try:
            signal_owned_group(process)
        finally:
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            if binary is not None:
                binary.close()
                typing.cast(pathlib.Path, binary_path).chmod(0o600)
    if reason == "none" and process.returncode < 0:
        reason = "process_crash"
    return CommandResult(
        bytes(output),
        bytes(errors),
        process.returncode,
        reason,
        int((time.monotonic() - start) * 1000),
    )


def environment(value: typing.Any) -> dict[str, typing.Any]:
    """Validate actual/target environment without inventing unavailable properties."""
    row = obj(value, ENV_KEYS)
    require(row["os"] in {"linux", "android", "ios"}, "OS")
    for key in ("os_version", "model"):
        if row[key] is not None:
            text(row[key])
    if row["api"] is not None:
        integer(row["api"], 1, 1000)
    if row["device_id"] is not None:
        digest(row["device_id"])
    require(
        row["abi"] in {"x86_64", "x86", "arm64-v8a", "armeabi-v7a", "arm64", "unknown"},
        "ABI",
    )
    require(
        row["page_size"] in {None, 4096, 16384, 65536}
        and type(row["page_size"]) is not bool,
        "page size",
    )
    require(row["facility"] in {"host", "physical", "emulator"}, "facility")
    require(
        row["channel"] in {"host_native", "preinstalled_lab", "unavailable"}, "channel"
    )
    return row


def check_plan(value: typing.Any) -> dict[str, typing.Any]:
    """Close the execution plan before any adapter/tool command."""
    plan = obj(
        value,
        "version source_head source_tree build_receipt_sha256 suite_sha256 files cells",
    )
    require(type(plan["version"]) is int and plan["version"] == 1, "plan version")
    for key in ("source_head", "source_tree"):
        text(plan[key], r"[a-f0-9]{40}")
    digest(plan["suite_sha256"])
    digest(plan["build_receipt_sha256"])
    file_ids: set[str] = set()
    paths: set[str] = set()
    total = 0
    for entry in array(plan["files"], 96, 1):
        row = obj(entry, "id path role bytes sha256")
        file_id = ident(row["id"])
        path = relative(row["path"])
        require(
            file_id not in file_ids and path not in paths and row["role"] in ROLES,
            "duplicate file or unknown role",
        )
        total += integer(row["bytes"], 0, 64 * MIB)
        digest(row["sha256"])
        file_ids.add(file_id)
        paths.add(path)
    require(total <= 256 * MIB, "aggregate artifact bytes")
    suite = sorted(
        (
            row
            for row in plan["files"]
            if row["role"] in {"suite_source", "fixture_source"}
        ),
        key=lambda row: row["path"],
    )
    require(
        len(suite) > 0
        and sha(b"val01.suite.v1\0" + canonical(suite)) == plan["suite_sha256"],
        "suite hash",
    )
    cell_ids: set[str] = set()
    for entry in array(plan["cells"], 8, 1):
        cell = obj(
            entry,
            "id adapter scenario context facility target required artifact_ids expected",
        )
        cell_id = ident(cell["id"])
        require(
            cell_id not in cell_ids and type(cell["required"]) is bool,
            "duplicate cell or required type",
        )
        require(
            cell["context"] in {"clean", "vpn", "accessibility", "ime", "support"},
            "context",
        )
        require(
            cell["expected"] in {"error", "benign", "business_denial", "not_run"},
            "expected outcome",
        )
        target = environment(cell["target"])
        require(target["facility"] == cell["facility"], "target facility")
        refs = array(cell["artifact_ids"], 96)
        require(
            len(refs) == len({ident(ref) for ref in refs}) and set(refs) <= file_ids,
            "artifact references",
        )
        if cell["adapter"] == "host_c":
            require(
                cell["scenario"] == "host_startup_unavailable"
                and cell["context"] == "clean"
                and cell["facility"] == "host"
                and target["os"] == "linux"
                and target["channel"] == "host_native",
                "host cell",
            )
        elif cell["adapter"] == "android_adb":
            require(
                cell["scenario"]
                in {"android_clean_receipt", "android_policy_hash_mismatch"}
                and cell["facility"] in {"physical", "emulator"}
                and target["os"] == "android"
                and target["channel"] == "preinstalled_lab",
                "Android cell",
            )
            require(
                all(
                    target[key] is not None
                    for key in ("os_version", "api", "model", "page_size", "device_id")
                )
                and target["abi"] != "unknown",
                "Android target pins",
            )
        else:
            require(
                cell["adapter"] == "ios_unavailable"
                and cell["scenario"] == "ios_receipt"
                and target["os"] == "ios",
                "unsupported adapter",
            )
        cell_ids.add(cell_id)
    return plan


def phase(
    state: str = "not_run",
    reason: str = "facility_missing",
    evidence_ids: list[str] | None = None,
) -> dict[str, typing.Any]:
    """Represent one measured or explicitly missing phase."""
    return {
        "state": state,
        "reason": reason,
        "evidence_ids": [] if evidence_ids is None else evidence_ids,
    }


def empty_result(
    cell: dict[str, typing.Any], nonce: str, reason: str
) -> dict[str, typing.Any]:
    """Retain a missing cell in the planned denominator."""
    target = cell.get("target", {})
    actual: dict[str, typing.Any] = {key: None for key in ENV_KEYS.split()}
    actual.update(
        os=target.get("os", "android"),
        abi="unknown",
        facility=cell.get("facility", "physical"),
        channel="unavailable",
    )
    return {
        "cell_id": cell["id"],
        "nonce": nonce,
        "environment": actual,
        **{key: phase(reason=reason) for key in PHASES},
        "observation": {
            "state": "not_run",
            "rule_id": None,
            "rule_version": None,
            "status": None,
            "evidence_ids": [],
        },
        "operation": {
            "state": "not_run",
            "api_status": None,
            "action": None,
            "gate_reason": None,
            "before": None,
            "after": None,
            "policy_sha256": None,
            "config_sha256": None,
            "evidence_ids": [],
        },
        "outcome": "not_run",
        "reason": reason,
    }


def android_unavailable(
    cell: dict[str, typing.Any], nonce: str
) -> dict[str, typing.Any]:
    """Do not probe tools, daemons or devices without an explicit lab selection."""
    return empty_result(cell, nonce, "facility_missing")


def summarize(
    cells: list[dict[str, typing.Any]], results: list[dict[str, typing.Any]]
) -> dict[str, typing.Any]:
    """Compute gate status over every planned cell, never an effective denominator."""
    require(len(cells) > 0 and len(results) == len(cells), "missing result cells")
    by_cell = {row["cell_id"]: row for row in results}
    require(
        len(by_cell) == len(cells) and set(by_cell) == {cell["id"] for cell in cells},
        "duplicate result",
    )
    counts = {outcome: 0 for outcome in OUTCOMES}
    conform = True
    release = "not_requested"
    missing: list[str] = []
    for cell in cells:
        result = by_cell[cell["id"]]
        require(result["outcome"] in OUTCOMES, "outcome")
        counts[result["outcome"]] += 1
        if result["outcome"] != cell["expected"] or any(
            result.get(stage, {}).get("state") == "failed" for stage in PHASES
        ):
            conform = False
        if result["execution"]["state"] != "verified":
            missing.append(cell["id"])
        if cell["required"] is True:
            if release == "not_requested":
                release = "pass"
            if result["outcome"] not in {
                "benign",
                "business_denial",
                "observed_detection",
            } or any(
                result.get(stage, {}).get("state") != "verified" for stage in PHASES
            ):
                release = "fail"
    return {
        "planned": len(cells),
        "by_outcome": counts,
        "missing_cells": missing,
        "conformance": "pass" if conform is True else "fail",
        "release_gate": release,
        "effectiveness_gate": "not_run",
        "performance_gate": "not_run",
    }


def check_fixture(
    value: typing.Any,
    nonce: str,
    expected_phase: str,
    scenario: str,
    policy_hash: str,
    config_hash: str,
) -> dict[str, typing.Any]:
    """Verify actual owned production API fields and receipt mutation, not setup flags."""
    row = obj(value, FIXTURE_KEYS)
    require(
        row["nonce"] == nonce
        and row["phase"] == expected_phase
        and row["scenario"] == scenario,
        "fixture binding",
    )
    require(
        row["policy_sha256"] == policy_hash and row["config_sha256"] == config_hash,
        "fixture policy/config",
    )
    mismatch = (
        expected_phase == "execution" and scenario == "android_policy_hash_mismatch"
    )
    require(
        row["status"] == 0
        and type(row["status"]) is int
        and row["action"] == (0 if mismatch is True else 2)
        and type(row["action"]) is int,
        "fixture API decision",
    )
    require(
        row["before"] == 0
        and type(row["before"]) is int
        and row["after"] == (0 if mismatch is True else 1)
        and type(row["after"]) is int,
        "receipt count",
    )
    require(
        row["reason"] == (3 if mismatch is True else 12) and type(row["reason"]) is int,
        "gate reason",
    )
    if mismatch is True:
        require(
            row["rule_evaluated"] is False
            and all(
                row[key] is None
                for key in ("rule_id", "rule_version", "rule_status", "rule_verdict")
            ),
            "invented mismatch predicate",
        )
    else:
        require(
            row["rule_id"] == "native.android.dbg.tracer_pid.proc_status"
            and row["rule_version"] == 1
            and type(row["rule_version"]) is int
            and row["rule_status"] == 0
            and type(row["rule_status"]) is int
            and row["rule_evaluated"] is True
            and row["rule_verdict"] == 1
            and type(row["rule_verdict"]) is int,
            "baseline predicate",
        )
    return row


def check_measurements(
    pairs: typing.Any,
    evidence: dict[str, dict[str, typing.Any]],
    cells: set[str],
    artifacts: set[str],
) -> int:
    """Validate paired measured samples and exact complements without accepting performance."""
    total = 0
    used: set[str] = set()
    pairs_seen: set[tuple[str, str, str]] = set()
    for value in array(pairs, 8):
        pair = obj(
            value,
            "cell_id metric unit conditions_sha256 baseline_artifact_id protected_artifact_id expected_pairs samples missing_indices",
        )
        require(
            pair["cell_id"] in cells
            and pair["metric"]
            in {"cold_start", "warm_start", "scan", "dex_first", "dex_later", "rss"},
            "measurement cell/metric",
        )
        require(
            pair["unit"] == ("bytes" if pair["metric"] == "rss" else "ns"),
            "measurement unit",
        )
        digest(pair["conditions_sha256"])
        pair_key = (pair["cell_id"], pair["metric"], pair["conditions_sha256"])
        require(pair_key not in pairs_seen, "duplicate paired measurement")
        pairs_seen.add(pair_key)
        require(
            pair["baseline_artifact_id"] in artifacts
            and pair["protected_artifact_id"] in artifacts
            and pair["baseline_artifact_id"] != pair["protected_artifact_id"],
            "paired artifacts",
        )
        expected = integer(pair["expected_pairs"], 30, 64)
        seen: set[int] = set()
        for sample in array(pair["samples"], 64):
            obj(
                sample,
                "index baseline protected baseline_evidence_id protected_evidence_id",
            )
            index = integer(sample["index"], 0, expected - 1)
            require(index not in seen, "duplicate sample")
            seen.add(index)
            for role in ("baseline", "protected"):
                integer(sample[role], 1, 2**53 - 1)
                evidence_id = ident(sample[role + "_evidence_id"])
                require(
                    evidence_id in evidence and evidence_id not in used,
                    "missing/duplicate measured evidence",
                )
                used.add(evidence_id)
                row = obj(
                    evidence[evidence_id],
                    "run_id cell_id nonce phase metric index role value unit conditions_sha256 artifact_id",
                )
                integer(row["value"], 1, 2**53 - 1)
                integer(row["index"], 0, expected - 1)
                require(
                    row["cell_id"] == pair["cell_id"]
                    and row["phase"] == "execution"
                    and row["metric"] == pair["metric"]
                    and row["index"] == index
                    and row["role"] == role
                    and row["value"] == sample[role]
                    and row["unit"] == pair["unit"]
                    and row["conditions_sha256"] == pair["conditions_sha256"]
                    and row["artifact_id"] == pair[role + "_artifact_id"],
                    "measurement binding",
                )
            total += 1
        missing = array(pair["missing_indices"], 64)
        for missing_index in missing:
            integer(missing_index, 0, expected - 1)
        require(missing == sorted(set(range(expected)) - seen), "hidden missing pairs")
    require(total <= 64, "suite sample limit")
    return total


def checked_files(plan: dict[str, typing.Any], root: pathlib.Path) -> dict[str, bytes]:
    """Recheck the full artifact inventory, including retained production verifiers."""
    result: dict[str, bytes] = {}
    for row in plan["files"]:
        limit = (
            2048
            if row["role"] == "policy"
            else 4096
            if row["role"] == "config"
            else 64 * 1024
            if row["role"]
            in {"build_receipt", "lab_descriptor", "provisioning_receipt"}
            else MIB
            if row["role"] == "dependency_manifest"
            else 64 * MIB
        )
        data = read_file(root, row["path"], limit)
        require(
            len(data) == row["bytes"] and sha(data) == row["sha256"],
            "artifact_mismatch",
        )
        result[row["id"]] = data
    receipt_ids = [row["id"] for row in plan["files"] if row["role"] == "build_receipt"]
    require(len(receipt_ids) == 1, "one build receipt required")
    receipt_data = result[receipt_ids[0]]
    require(sha(receipt_data) == plan["build_receipt_sha256"], "build receipt hash")
    receipt = obj(
        decode(receipt_data),
        "version source_head source_tree tool_ids flags plugins registry_file products dependency_manifest",
    )
    require(
        type(receipt["version"]) is int
        and receipt["version"] == 1
        and receipt["source_head"] == plan["source_head"]
        and receipt["source_tree"] == plan["source_tree"]
        and receipt["plugins"] == [],
        "source/plugin receipt binding",
    )
    files = {row["id"]: row for row in plan["files"]}
    registry_id = ident(receipt["registry_file"])
    require(
        registry_id in files and files[registry_id]["role"] == "registry",
        "registry reference",
    )
    registry = result[registry_id]
    require(
        b"std::array<const Plugin*, 0>" in registry
        and b"&" not in registry.split(b"kPlugins", 1)[-1].split(b";", 1)[0],
        "nonempty plugin registry",
    )
    for key in ("tool_ids", "products"):
        refs = array(receipt[key], 96)
        require(
            len(refs) == len({ident(ref) for ref in refs}) and set(refs) <= set(files),
            "receipt artifact references",
        )
    products = {
        row["id"]
        for row in plan["files"]
        if row["role"]
        in {
            "host_executable",
            "native_pristine",
            "native_injected",
            "apk_signed",
            "apk_unsigned",
            "stub",
            "bridge_jar",
        }
    }
    require(set(receipt["products"]) == products, "unbound product")
    for flag in array(receipt["flags"], 64):
        text(flag)
    if receipt["dependency_manifest"] is not None:
        require(
            receipt["dependency_manifest"] in files
            and files[receipt["dependency_manifest"]]["role"] == "dependency_manifest",
            "dependency reference",
        )
    return result


def static_host(binary: bytes) -> None:
    """V1 host is Linux static ELF64; reject a silently unbound interpreter/DSO."""
    require(
        len(binary) >= 64 and binary[:6] == b"\x7fELF\x02\x01",
        "host must be static little-endian ELF64",
    )
    offset = struct.unpack_from("<Q", binary, 32)[0]
    size, count = struct.unpack_from("<HH", binary, 54)
    require(
        size >= 56 and 1 <= count <= 128 and offset + size * count <= len(binary),
        "ELF program bounds",
    )
    for index in range(count):
        kind = struct.unpack_from("<I", binary, offset + index * size)[0]
        require(kind not in {2, 3}, "host dynamic dependencies unsupported")


class Recorder:
    """One bounded local suite; fixed adapters share counters and evidence storage."""

    def __init__(self, plan: dict[str, typing.Any], root: pathlib.Path) -> None:
        self.plan = plan
        self.root = root
        self.run_id = str(uuid.uuid4())
        self.evidence: list[dict[str, typing.Any]] = []
        self.total_text = 0
        self.commands = 0
        self.deadline = time.monotonic() + 900
        self.cell_deadline = self.deadline
        self.artifacts: list[dict[str, typing.Any]] = []
        self.binary_files = 0
        self.binary_bytes = 0

    def reserve_binary_pair(self, artifact: dict[str, typing.Any]) -> None:
        """Reserve both APK reads before acquisition; failures keep their spent budget."""
        size = integer(artifact["bytes"], 1, 64 * MIB)
        require(
            len(self.plan["files"]) + self.binary_files + 2 <= 96,
            "aggregate streamed artifact cap",
        )
        require(
            sum(row["bytes"] for row in self.plan["files"])
            + self.binary_bytes
            + 2 * size
            <= 256 * MIB,
            "aggregate streamed artifact cap",
        )
        self.binary_files += 2
        self.binary_bytes += 2 * size

    def capture(
        self,
        cell: dict[str, typing.Any],
        nonce: str,
        stage: str,
        kind: str,
        probe: str,
        data: bytes,
        result: CommandResult | None = None,
        artifact: dict[str, typing.Any] | None = None,
    ) -> str:
        """Index one captured event, retaining binary references outside text output."""
        require(len(self.evidence) < 256 and len(data) <= 240 * 1024, "evidence limit")
        require(probe in PROBES, "unknown evidence probe")
        evidence_id = f"e{len(self.evidence):03d}"
        envelope = {
            "run_id": self.run_id,
            "cell_id": cell["id"],
            "nonce": nonce,
            "phase": stage,
            "kind": kind,
            "probe": probe,
            "data": data.decode("utf-8", errors="strict"),
            "stderr": ""
            if result is None
            else result.stderr.decode("utf-8", errors="strict"),
            "exit_code": 0
            if result is None
            else result.returncode
            if result.returncode >= 0
            else None,
            "signal": None
            if result is None or result.returncode >= 0
            else -result.returncode,
            "elapsed_ms": 0 if result is None else result.elapsed_ms,
            "artifact": artifact,
        }
        encoded = canonical(envelope)
        self.total_text += len(encoded)
        require(
            len(encoded) <= 256 * 1024 and self.total_text <= 16 * MIB,
            "text evidence limit",
        )
        path = "evidence/" + evidence_id + ".json"
        write_file(self.root, path, encoded)
        self.evidence.append(
            {
                "id": evidence_id,
                "path": path,
                "bytes": len(encoded),
                "sha256": sha(encoded),
                "run_id": self.run_id,
                "cell_id": cell["id"],
                "nonce": nonce,
                "phase": stage,
                "kind": kind,
            }
        )
        return evidence_id

    def invoke(
        self,
        argv: list[str],
        cwd: pathlib.Path,
        cleanup: bool = False,
        binary_path: pathlib.Path | None = None,
        env: dict[str, str] | None = None,
        no_fork: bool = False,
        binary_limit: int = 64 * MIB,
    ) -> CommandResult:
        """Never extend a cell/suite budget, including during cleanup."""
        self.commands += 1
        require(self.commands <= 256, "process limit")
        deadline = min(self.deadline, self.cell_deadline) - (
            0 if cleanup is True else 20
        )
        require(time.monotonic() < deadline, "budget_exhausted")
        return command(
            argv,
            cwd,
            timeout=min(15, deadline - time.monotonic()),
            binary_path=binary_path,
            env=env,
            no_fork=no_fork,
            binary_limit=binary_limit,
        )


def host_environment() -> dict[str, typing.Any]:
    """Record actual host properties without a device claim."""
    require(platform.system() == "Linux", "unsupported_environment")
    return environment(
        {
            "os": "linux",
            "os_version": platform.release(),
            "api": None,
            "model": platform.machine(),
            "abi": platform.machine(),
            "page_size": os.sysconf("SC_PAGE_SIZE"),
            "facility": "host",
            "device_id": None,
            "channel": "host_native",
        }
    )


def match_target(actual: dict[str, typing.Any], target: dict[str, typing.Any]) -> None:
    """Match every declared cell dimension, including page size and install channel."""
    require(
        all(
            expected is None or actual[key] == expected
            for key, expected in target.items()
        ),
        "environment binding mismatch",
    )


def host_run(
    recorder: Recorder, cell: dict[str, typing.Any], nonce: str, files: dict[str, bytes]
) -> dict[str, typing.Any]:
    """Execute the real production facade; expected NOT_READY remains an error."""
    entries = [
        row
        for row in recorder.plan["files"]
        if row["id"] in cell["artifact_ids"] and row["role"] == "host_executable"
    ]
    require(len(entries) == 1, "one host executable required")
    artifact = entries[0]
    static_host(files[artifact["id"]])
    executable = recorder.root / "inputs" / artifact["path"]
    scratch = recorder.root / ("scratch_" + nonce)
    result = empty_result(cell, nonce, "runtime_unavailable")
    result["environment"] = host_environment()
    match_target(result["environment"], cell["target"])
    scratch.mkdir(mode=0o700)
    try:
        actual = recorder.invoke([str(executable), nonce], scratch)
    except BaseException:
        if len(list(scratch.iterdir())) == 0:
            scratch.rmdir()
        raise
    references: dict[str, str] = {}
    try:
        require(
            actual.reason == "none" and actual.returncode == 0 and actual.stderr == b"",
            actual.reason if actual.reason != "none" else "operation_mismatch",
        )
        lines = actual.stdout.splitlines()
        require(len(lines) == 3, "host event count")
        expected = [
            {"nonce": nonce, "phase": "baseline", "before": 0, "after": 1},
            {"nonce": nonce, "phase": "setup", "info_status": 3},
            {
                "nonce": nonce,
                "phase": "execution",
                "api_status": 3,
                "action": 0,
                "info_status": 3,
                "before": 0,
                "after": 0,
            },
        ]
        for stage, line, event in zip(PHASES[:3], lines, expected, strict=True):
            require(canonical(decode(line)) == canonical(event), "host event mismatch")
            references[stage] = recorder.capture(
                cell, nonce, stage, "host", "host_event", line, actual
            )
            result[stage] = phase("verified", "none", [references[stage]])
        result["outcome"] = "error"
        result["reason"] = "runtime_unavailable"
        result["observation"]["state"] = "unavailable"
        result["operation"].update(
            state="unknown",
            api_status=3,
            action=0,
            before=0,
            after=0,
            evidence_ids=[references["execution"]],
        )
    except ValidationError as error:
        reason = str(error) if str(error) in REASONS else "evidence_mismatch"
        reference = recorder.capture(
            cell, nonce, "execution", "host", "host_failure", actual.stdout, actual
        )
        result["outcome"] = "crash" if actual.reason == "process_crash" else "error"
        result["reason"] = reason
        result["execution"] = phase("failed", reason, [reference])
        result["observation"]["state"] = "unavailable"
        result["operation"]["state"] = "unknown"
    finally:
        unchanged = (
            read_file(recorder.root / "inputs", artifact["path"], 64 * MIB)
            == files[artifact["id"]]
        )
        clean = len(list(scratch.iterdir())) == 0 and unchanged is True
        proof = {
            "process_reaped": True,
            "scratch_empty": len(list(scratch.iterdir())) == 0,
            "artifact_sha256": sha(
                read_file(recorder.root / "inputs", artifact["path"], 64 * MIB)
            ),
        }
        reference = recorder.capture(
            cell, nonce, "cleanup", "host", "host_cleanup", canonical(proof)
        )
        result["cleanup"] = phase(
            "verified" if clean is True else "failed",
            "none" if clean is True else "cleanup_failed",
            [reference],
        )
        if clean is False:
            result.update(outcome="error", reason="cleanup_failed")
        if len(list(scratch.iterdir())) == 0:
            scratch.rmdir()
    return result


def one_file(plan: dict[str, typing.Any], role: str) -> dict[str, typing.Any]:
    """Require exactly one role when the fixed protocol needs it."""
    entries = [entry for entry in plan["files"] if entry["role"] == role]
    require(len(entries) == 1, "missing/ambiguous " + role)
    return typing.cast(dict[str, typing.Any], entries[0])


def dependency_bindings(value: typing.Any) -> dict[str, dict[str, typing.Any]]:
    """Rehash pinned tool/runtime dependencies at their actual installed paths."""
    manifest = obj(value, "version python prefix files distributions")
    require(
        type(manifest["version"]) is int and manifest["version"] == 1,
        "dependency version",
    )
    require(
        manifest["python"] == str(pathlib.Path(sys.executable).resolve())
        and manifest["prefix"] == sys.prefix,
        "installed interpreter binding",
    )
    bindings: dict[str, dict[str, typing.Any]] = {}
    total = 0
    for entry in array(manifest["files"], 1024, 1):
        row = obj(entry, "path bytes sha256")
        path = pathlib.Path(text(row["path"], r"/[A-Za-z0-9_./+-]{1,1024}"))
        require(
            str(path.resolve()) == str(path) and str(path) not in bindings,
            "dependency path alias",
        )
        maximum = integer(row["bytes"], 0, 64 * MIB)
        total += maximum
        require(total <= 256 * MIB, "dependency byte cap")
        data = read_file(path.parent, path.name, maximum)
        require(
            len(data) == maximum and sha(data) == digest(row["sha256"]),
            "changed tool/runtime dependency",
        )
        bindings[str(path)] = row
    require(manifest["python"] in bindings, "unbound interpreter")
    return bindings


def process_bindings(pid: int, bindings: dict[str, dict[str, typing.Any]]) -> None:
    """Reject a live tool's file-backed native mappings outside its pinned closure."""
    maps = pathlib.Path(f"/proc/{pid}/maps").read_text()
    paths = {
        line.split(maxsplit=5)[5]
        for line in maps.splitlines()
        if len(line.split(maxsplit=5)) == 6
        and line.split(maxsplit=5)[5].startswith("/")
    }
    for path in paths:
        require(path in bindings, "unbound runtime mapping")


def android_preflight(
    plan: dict[str, typing.Any],
    files: dict[str, bytes],
    root: pathlib.Path,
    unsigned_preparation: bool = False,
) -> dict[str, typing.Any]:
    """Reuse the pinned installed packer; never substitute source imports or loose JSON."""
    descriptor = one_file(plan, "dependency_manifest")
    manifest = decode(files[descriptor["id"]])
    bindings = dependency_bindings(manifest)
    distributions = array(manifest["distributions"], 16, 1)
    names: set[str] = set()
    packer_error_type: type[Exception] = ValidationError
    try:
        for value in distributions:
            row = obj(value, "name version wheel_id")
            name = text(row["name"], r"[a-zA-Z0-9_.-]{1,64}")
            require(name not in names, "distribution binding")
            names.add(name)
            distribution = importlib.metadata.distribution(name)
            require(
                distribution.version == text(row["version"]),
                "installed version mismatch",
            )
            if row["wheel_id"] is None:
                require(
                    name != "rasp-packer" and distribution.files is not None,
                    "packer wheel required",
                )
                for installed_name in typing.cast(
                    typing.Sequence[typing.Any], distribution.files
                ):
                    installed = pathlib.Path(
                        str(distribution.locate_file(installed_name))
                    ).resolve()
                    require(
                        str(installed) in bindings, "unbound installed dependency file"
                    )
                continue
            require(row["wheel_id"] in files, "missing pinned wheel")
            wheel_path = root / one_file_by_id(plan, row["wheel_id"])["path"]
            require(
                one_file_by_id(plan, row["wheel_id"])["role"] == "wheel", "wheel role"
            )
            with zipfile.ZipFile(wheel_path) as wheel:
                require(
                    len(wheel.infolist()) <= 4096
                    and sum(item.file_size for item in wheel.infolist()) <= 256 * MIB,
                    "wheel bounds",
                )
                for item in wheel.infolist():
                    if (
                        item.is_dir() is False
                        and item.filename.endswith(".dist-info/RECORD") is False
                    ):
                        relative(item.filename)
                        installed = pathlib.Path(
                            str(distribution.locate_file(item.filename))
                        ).resolve()
                        require(
                            str(installed) in bindings,
                            "unbound installed verifier file",
                        )
                        require(
                            read_file(installed.parent, installed.name, 64 * MIB)
                            == wheel.read(item),
                            "wheel/installed mismatch",
                        )
        require(
            {"rasp-packer", "lief", "cryptography"} <= names,
            "incomplete installed verifier distributions",
        )
        modules: dict[str, typing.Any] = {
            name: importlib.import_module("rasp_packer." + name)
            for name in (
                "archive_validation",
                "capabilities",
                "local_policy",
                "runtime_config",
                "verification",
                "platforms",
                "errors",
                "android.resources",
                "android.runtime_library",
            )
        }
        packer_error_type = modules["errors"].Error
        installed_packer_root = pathlib.Path(
            str(
                importlib.metadata.distribution("rasp-packer").locate_file(
                    "rasp_packer"
                )
            )
        ).resolve()
        for module in modules.values():
            require(
                str(pathlib.Path(module.__file__).resolve()) in bindings
                and pathlib.Path(module.__file__)
                .resolve()
                .is_relative_to(installed_packer_root),
                "source import substitution",
            )
        for name in ("lief", "cryptography"):
            imported = importlib.import_module(name)
            origin = pathlib.Path(typing.cast(str, imported.__file__)).resolve()
            installed_root = pathlib.Path(
                str(importlib.metadata.distribution(name).locate_file(""))
            ).resolve()
            require(
                origin.is_relative_to(installed_root) is True
                and str(origin) in bindings,
                "source dependency substitution",
            )
        process_bindings(os.getpid(), bindings)
        injection = obj(
            decode(files[one_file(plan, "injection_manifest")["id"]]),
            "version entries runtimes stub_file bridge_file compiled_policy_sha256 compiled_expectation_file build_id checks policy_file",
        )
        require(
            type(injection["version"]) is int and injection["version"] == 1,
            "injection version",
        )
        policy_module = modules["local_policy"]
        policy = policy_module.parse(files[injection["policy_file"]])
        require(
            policy.sha256 == digest(injection["compiled_policy_sha256"]),
            "compiled policy mismatch",
        )
        require(
            one_file_by_id(plan, injection["bridge_file"])["role"] == "bridge_jar"
            and one_file_by_id(plan, injection["compiled_expectation_file"])["role"]
            == "fixture_source",
            "compile input roles",
        )
        require(
            files[injection["compiled_expectation_file"]]
            == (
                'package fixture.validation; final class ExpectedPolicy { static final String SHA256 = "'
                + policy.sha256
                + '"; }\n'
            ).encode(),
            "compiled expectation source mismatch",
        )
        require(
            policy.platform == "android"
            and len(policy.operations) == 1
            and policy.operations[0].name == "append_demo_receipt"
            and len(policy.operations[0].rules) == 1
            and policy.operations[0].rules[0].rule_id
            == "native.android.dbg.tracer_pid.proc_status"
            and policy.operations[0].rules[0].rule_version == 1,
            "fixture policy shape",
        )
        config = modules["runtime_config"].RuntimeConfig(
            build_id=text(injection["build_id"]),
            checks=tuple(array(injection["checks"], 64, 1)),
            local_policy=policy,
        )
        require(
            files[one_file(plan, "config")["id"]] == config.to_json(),
            "retained config mismatch",
        )
        config_hash = policy_module.effective_hash(
            config.build_id, config.checks, policy
        )
        resources = modules["android.resources"].load()
        require(
            resources.stub_dex == files[injection["stub_file"]],
            "installed stub mismatch",
        )
        expected: dict[str, bytes] = {}
        for entry in array(injection["entries"], 96, 1):
            obj(entry, "name file_id")
            name = relative(entry["name"])
            require(
                name not in expected and entry["file_id"] in files, "injection entries"
            )
            expected[name] = files[entry["file_id"]]
        covered: set[str] = set()
        for entry in array(injection["runtimes"], 4, 1):
            obj(entry, "abi pristine_file injected_file capability_file support_file")
            abi = text(entry["abi"])
            require(abi not in covered and abi in resources.libraries, "runtime ABI")
            covered.add(abi)
            pristine = files[entry["pristine_file"]]
            require(
                resources.libraries[abi] == pristine,
                "installed pristine runtime mismatch",
            )
            modules["capabilities"].bind(
                pristine, files[entry["capability_file"]], "android", abi
            )
            policy_module.bind(
                pristine, files[entry["support_file"]], "android", abi, required=True
            )
            modules["android.runtime_library"].verify_policy_exports(pristine)
            injected = modules["android.runtime_library"].write_config(pristine, config)
            require(
                injected == files[entry["injected_file"]]
                and expected.get("lib/" + abi + "/librasp.so") == injected,
                "injected runtime/config mismatch",
            )
        apk = one_file(
            plan, "apk_unsigned" if unsigned_preparation is True else "apk_signed"
        )
        app = root / apk["path"]
        modules["archive_validation"].check(app)
        with zipfile.ZipFile(app) as archive:
            require(
                sum(item.file_size for item in archive.infolist()) <= 256 * MIB
                and all(item.file_size <= 64 * MIB for item in archive.infolist()),
                "APK expansion cap",
            )
        verified = modules["verification"].verify(
            app=app,
            platform=modules["platforms"].Platform.ANDROID,
            config=config,
            expected_entries=expected,
        )
        require(
            verified.app_identity.package_name == "fixture.validation",
            "owned fixture package",
        )
        dependency_bindings(manifest)
        return {
            "policy_sha256": policy.sha256,
            "config_sha256": config_hash,
            "abis": sorted(covered),
            "apk_id": apk["id"],
            "dependency_manifest": manifest,
            "bindings": bindings,
        }
    except (
        importlib.metadata.PackageNotFoundError,
        ImportError,
        KeyError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        raise ValidationError(
            "installed Android verifier prerequisite failed"
        ) from error
    except packer_error_type as error:
        raise ValidationError("production Android verification failed") from error


def one_file_by_id(plan: dict[str, typing.Any], file_id: str) -> dict[str, typing.Any]:
    """Resolve an exact inventory identity."""
    rows = [row for row in plan["files"] if row["id"] == file_id]
    require(len(rows) == 1, "unknown artifact id")
    return typing.cast(dict[str, typing.Any], rows[0])


def fixture_xml(data: bytes) -> dict[str, typing.Any]:
    """Read exactly one bounded fixture status view; entities are never expanded."""
    require(len(data) <= 240 * 1024 and b"<!" not in data, "unsafe XML")
    try:
        document = element_tree.fromstring(data)
        nodes = [
            node
            for node in document.iter("node")
            if node.get("resource-id") == "fixture.validation:id/status"
        ]
        require(len(nodes) == 1, "missing/duplicate fixture status")
        return obj(decode(nodes[0].attrib["text"].encode(), 8192), FIXTURE_KEYS)
    except (element_tree.ParseError, KeyError) as error:
        raise ValidationError("invalid fixture XML") from error


def lab_descriptor(
    value: typing.Any,
    plan: dict[str, typing.Any],
    preflight: dict[str, typing.Any],
) -> dict[str, typing.Any]:
    """Accept only an explicitly provisioned isolated USB lab, never ambient devices."""
    lab = obj(
        value,
        "version owned_lab serial device_id apk_file_id provisioning_receipt_sha256 adb_file_id transport network_isolation preauthorized adb_home",
    )
    require(
        type(lab["version"]) is int
        and lab["version"] == 1
        and lab["owned_lab"] is True
        and lab["network_isolation"] is True
        and lab["preauthorized"] is True
        and lab["transport"] == "usb",
        "unsupported provisioning shape",
    )
    text(lab["serial"], r"[A-Za-z0-9_-]{1,64}")
    digest(lab["device_id"])
    require(lab["apk_file_id"] == preflight["apk_id"], "lab APK binding")
    require(
        any(
            row["role"] == "provisioning_receipt"
            and row["sha256"] == lab["provisioning_receipt_sha256"]
            for row in plan["files"]
        ),
        "unreviewed provisioning receipt",
    )
    adb = one_file_by_id(plan, lab["adb_file_id"])
    require(adb["role"] == "tool", "missing pinned adb")
    require(
        sum(
            row["sha256"] == adb["sha256"] and row["bytes"] == adb["bytes"]
            for row in preflight["bindings"].values()
        )
        == 1,
        "missing/ambiguous installed adb binding",
    )
    home = pathlib.Path(text(lab["adb_home"], r"/[A-Za-z0-9_./-]{1,240}"))
    require(
        str(home) == lab["adb_home"] and ".." not in home.parts and str(home) != "/",
        "provisioned adb home path",
    )
    return lab


def check_lab(
    value: typing.Any,
    plan: dict[str, typing.Any],
    files: dict[str, bytes],
    preflight: dict[str, typing.Any],
) -> dict[str, typing.Any]:
    """Add local tool closure and credential metadata checks to pure lab admission."""
    lab = lab_descriptor(value, plan, preflight)
    adb = one_file_by_id(plan, lab["adb_file_id"])
    require(adb["id"] in files, "missing pinned adb")
    matching = [
        row
        for row in preflight["bindings"].values()
        if row["sha256"] == adb["sha256"] and row["bytes"] == adb["bytes"]
    ]
    tool_closure(matching[0]["path"], preflight["bindings"])
    home = pathlib.Path(text(lab["adb_home"], r"/[A-Za-z0-9_./-]{1,240}"))
    require(
        str(home.resolve()) == str(home)
        and home != pathlib.Path.home()
        and home.is_dir() is True
        and home.stat().st_uid == os.geteuid()
        and home.stat().st_mode & 0o077 == 0,
        "private provisioned adb home required",
    )
    for name in ("adbkey", "adbkey.pub"):
        path = home / ".android" / name
        require(
            path.is_file() is True and path.is_symlink() is False,
            "preauthorized keys required; runner never generates keys",
        )
    return lab


def check_probe(
    probe: str,
    data: bytes,
    stderr: bytes,
    exit_code: int | None,
    term_signal: int | None,
) -> None:
    """Share the fixed route's pure command predicates between live and offline checks."""
    absent = probe in {"process_pre", "process_post", "xml_pre", "xml_post"}
    require(
        term_signal is None
        and type(exit_code) is int
        and exit_code == (1 if absent is True else 0),
        "collection_unavailable",
    )
    if absent is True:
        require(data == b"" and stderr == b"", "unproved absence")
    elif probe == "get_state":
        require(data.strip() == b"device", "unsupported device state")
    elif probe == "package_path":
        require(
            re.fullmatch(
                rb"package:/data/app/[A-Za-z0-9_./=+-]+/base\.apk", data.strip()
            )
            is not None
            and b".." not in data,
            "installed package path",
        )
    elif probe == "adb_help":
        require(
            all(
                token in data
                for token in (
                    b"Version 35.0.2-12147458",
                    b"-L SOCKET",
                    b"server nodaemon",
                    b"one USB device",
                )
            ),
            "unsupported pinned adb tool",
        )


def tool_closure(executable: str, bindings: dict[str, dict[str, typing.Any]]) -> None:
    """Use the pinned installed ELF parser to reject absent tool dependencies before ADB."""
    lief = importlib.import_module("lief")
    pending = [executable]
    seen: set[str] = set()
    while len(pending) > 0:
        path = pending.pop()
        if path in seen:
            continue
        require(path in bindings and len(seen) < 128, "unbound tool dependency")
        seen.add(path)
        filename = pathlib.Path(path)
        elf = lief.ELF.parse(
            io.BytesIO(read_file(filename.parent, filename.name, 64 * MIB))
        )
        require(elf is not None, "unsupported tool ELF")
        if elf.interpreter != "":
            loader = str(pathlib.Path(elf.interpreter).resolve())
            require(loader in bindings, "unbound tool loader")
            pending.append(loader)
        for name in elf.libraries:
            matches = [
                candidate
                for candidate in bindings
                if pathlib.Path(candidate).name == name
            ]
            require(len(matches) == 1, "missing/ambiguous tool DSO")
            pending.append(matches[0])


class AdbSession:
    """A single supervised private server; clients cannot fork an automatic daemon."""

    def __init__(
        self,
        recorder: Recorder,
        cell: dict[str, typing.Any],
        nonce: str,
        lab: dict[str, typing.Any],
        preflight: dict[str, typing.Any],
    ) -> None:
        self.recorder = recorder
        self.cell = cell
        self.nonce = nonce
        self.lab = lab
        self.preflight = preflight
        self.stage = "setup"
        self.refs: dict[str, list[str]] = {stage: [] for stage in PHASES}
        self.streams_reserved = False
        self.remaining_streams = 0
        self.adb = (
            recorder.root
            / "inputs"
            / one_file_by_id(recorder.plan, lab["adb_file_id"])["path"]
        )
        self.key_state = [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_size)
            for path in (
                pathlib.Path(lab["adb_home"]) / ".android" / "adbkey",
                pathlib.Path(lab["adb_home"]) / ".android" / "adbkey.pub",
            )
        ]
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="v01-", dir="/tmp"))
        self.endpoint = "localfilesystem:" + str(self.work / "server.sock")
        self.env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": lab["adb_home"],
            "TMPDIR": str(self.work),
            "ADB_MDNS_AUTO_CONNECT": "0",
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "0",
            "ADB_SERVER_SOCKET": self.endpoint,
        }
        self.server: subprocess.Popen[bytes] | None = None
        self.streams: list[typing.BinaryIO] = []

    def start(self) -> None:
        """Check pinned help locally, then own the only permitted foreground server."""
        dependency_bindings(self.preflight["dependency_manifest"])
        result = self.recorder.invoke(
            [str(self.adb), "--help"], self.work, env=self.env, no_fork=True
        )
        self.record("adb_help", result)
        require(result.reason == "none", result.reason)
        check_probe("adb_help", result.stdout, result.stderr, result.returncode, None)
        for name in ("server.stdout", "server.stderr"):
            self.streams.append(
                typing.cast(typing.BinaryIO, (self.work / name).open("xb"))
            )
        self.recorder.commands += 1
        require(self.recorder.commands <= 256, "process limit")
        self.server = subprocess.Popen(
            child_argv(
                [
                    str(self.adb),
                    "-L",
                    self.endpoint,
                    "--one-device",
                    self.lab["serial"],
                    "server",
                    "nodaemon",
                ]
            ),
            cwd=self.work,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=self.streams[0],
            stderr=self.streams[1],
            start_new_session=True,
        )
        for _ in range(30):
            self.alive()
            socket_path = self.work / "server.sock"
            if socket_path.exists() is True:
                require(
                    stat.S_ISSOCK(socket_path.lstat().st_mode),
                    "private endpoint is not a socket",
                )
                bindings = dict(self.preflight["bindings"])
                bindings[str(self.adb)] = one_file_by_id(
                    self.recorder.plan, self.lab["adb_file_id"]
                )
                process_bindings(self.server.pid, bindings)
                self.refs["setup"].append(
                    self.recorder.capture(
                        self.cell,
                        self.nonce,
                        "setup",
                        "adb",
                        "server_started",
                        canonical(
                            {
                                "pid": self.server.pid,
                                "endpoint": self.endpoint,
                                "device_restriction": "usb_only",
                                "tool_sha256": one_file_by_id(
                                    self.recorder.plan, self.lab["adb_file_id"]
                                )["sha256"],
                            }
                        ),
                    )
                )
                return
            time.sleep(0.1)
        raise ValidationError("timeout")

    def alive(self) -> None:
        """Fail before clients if the owned server dies or exceeds its output cap."""
        require(
            self.server is not None and process_exited(self.server) is False,
            "owned adb server unavailable",
        )
        require(
            time.monotonic() < self.recorder.cell_deadline
            and all(
                (self.work / name).stat().st_size <= 240 * 1024
                for name in ("server.stdout", "server.stderr")
            ),
            "server deadline/output limit",
        )

    def record(
        self,
        probe: str,
        result: CommandResult,
        artifact: dict[str, typing.Any] | None = None,
    ) -> None:
        """Retain every bounded client transcript, including failures."""
        require(len(self.refs[self.stage]) < 32, "phase evidence limit")
        self.refs[self.stage].append(
            self.recorder.capture(
                self.cell,
                self.nonce,
                self.stage,
                "adb",
                probe,
                result.stdout,
                result,
                artifact,
            )
        )

    def call(
        self,
        probe: str,
        args: list[str],
        allow_absent: bool = False,
        artifact_path: pathlib.Path | None = None,
    ) -> bytes:
        """All clients use the owned endpoint and a no-fork process limit."""
        limit = 64 * MIB
        if artifact_path is not None:
            source = one_file_by_id(self.recorder.plan, self.lab["apk_file_id"])
            limit = integer(source["bytes"], 1, 64 * MIB)
            if probe == "apk_pre":
                require(self.streams_reserved is False, "duplicate APK stream")
                self.recorder.reserve_binary_pair(source)
                self.streams_reserved = True
                self.remaining_streams = 2
            require(
                probe in {"apk_pre", "apk_post"}
                and self.streams_reserved is True
                and self.remaining_streams > 0,
                "unreserved APK stream",
            )
            self.remaining_streams -= 1
        self.alive()
        result = self.recorder.invoke(
            [str(self.adb), "-L", self.endpoint, "-s", self.lab["serial"], *args],
            self.work,
            cleanup=self.stage == "cleanup",
            binary_path=artifact_path,
            env=self.env,
            no_fork=True,
            binary_limit=limit,
        )
        artifact: dict[str, typing.Any] | None = None
        if (
            artifact_path is not None
            and result.reason == "none"
            and result.returncode == 0
        ):
            data = read_file(artifact_path.parent, artifact_path.name, 64 * MIB)
            source = one_file_by_id(self.recorder.plan, self.lab["apk_file_id"])
            require(
                len(data) == source["bytes"] and sha(data) == source["sha256"],
                "artifact_mismatch",
            )
            artifact = {
                "path": artifact_path.relative_to(self.recorder.root).as_posix(),
                "bytes": len(data),
                "sha256": sha(data),
                "file_id": source["id"],
                "run_id": self.recorder.run_id,
                "cell_id": self.cell["id"],
                "nonce": self.nonce,
                "phase": self.stage,
            }
            self.recorder.artifacts.append(artifact)
        self.record(probe, result, artifact)
        self.alive()
        require(result.reason == "none", result.reason)
        require(
            allow_absent
            is (probe in {"process_pre", "process_post", "xml_pre", "xml_post"}),
            "absence probe shape",
        )
        check_probe(probe, result.stdout, result.stderr, result.returncode, None)
        return result.stdout

    def close(self) -> None:
        """Kill/reap only our server, capture its bounded output and remove its endpoint."""
        self.stage = "cleanup"
        if self.server is not None:
            signal_owned_group(self.server)
            self.server.wait(timeout=2)
        for stream in self.streams:
            stream.close()
        for name in ("server.stdout", "server.stderr"):
            path = self.work / name
            if path.exists() is True:
                raw = read_file(self.work, name, 240 * 1024)
                self.refs["cleanup"].append(
                    self.recorder.capture(
                        self.cell,
                        self.nonce,
                        "cleanup",
                        "adb",
                        name.replace(".", "_"),
                        raw,
                    )
                )
                path.unlink()
        endpoint = self.work / "server.sock"
        if endpoint.exists() is True:
            require(stat.S_ISSOCK(endpoint.lstat().st_mode), "changed owned endpoint")
            endpoint.unlink()
        after = [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_size)
            for path in (
                pathlib.Path(self.lab["adb_home"]) / ".android" / "adbkey",
                pathlib.Path(self.lab["adb_home"]) / ".android" / "adbkey.pub",
            )
        ]
        require(
            after == self.key_state and len(list(self.work.iterdir())) == 0,
            "cleanup_failed",
        )
        dependency_bindings(self.preflight["dependency_manifest"])
        self.refs["cleanup"].append(
            self.recorder.capture(
                self.cell,
                self.nonce,
                "cleanup",
                "adb",
                "server_cleanup",
                canonical(
                    {
                        "server_reaped": self.server is None
                        or self.server.returncode is not None,
                        "endpoint_removed": endpoint.exists() is False,
                        "client_fork_limit": 0,
                        "pid": None if self.server is None else self.server.pid,
                        "endpoint": self.endpoint,
                    }
                ),
            )
        )
        self.work.rmdir()


def android_run(
    recorder: Recorder,
    cell: dict[str, typing.Any],
    nonce: str,
    lab: dict[str, typing.Any],
    preflight: dict[str, typing.Any],
) -> dict[str, typing.Any]:
    """Run only the owned receipt fixture using measured setup and verified cleanup."""
    result = empty_result(cell, nonce, "setup_failed")
    result.update(outcome="error", reason="setup_failed")
    session = AdbSession(recorder, cell, nonce, lab, preflight)
    remote_xml = "/sdcard/val01_" + nonce + ".xml"
    package_path: str | None = None
    device_admitted = False
    fixture_touched = False
    xml_owned = False
    try:
        session.start()
        require(
            session.call("get_state", ["get-state"]).strip() == b"device",
            "setup_failed",
        )
        props: dict[str, str] = {}
        for key, prop in (
            ("api", "ro.build.version.sdk"),
            ("os_version", "ro.build.version.release"),
            ("model", "ro.product.model"),
            ("abi", "ro.product.cpu.abi"),
            ("emulator", "ro.kernel.qemu"),
            ("fingerprint", "ro.build.fingerprint"),
        ):
            props[key] = (
                session.call("env_" + key, ["shell", "-n", "getprop", prop])
                .decode()
                .strip()
            )
            text(props[key])
        require(props["emulator"] == "0", "unsupported_environment")
        page_size = (
            session.call("env_pages", ["shell", "-n", "getconf", "PAGESIZE"])
            .decode()
            .strip()
        )
        require(
            page_size.isdecimal() is True and props["api"].isdecimal() is True,
            "environment values",
        )
        device_id = sha(
            b"val01.device.v1\0"
            + (lab["serial"] + "\n" + props["fingerprint"]).encode()
        )
        actual = environment(
            {
                "os": "android",
                "os_version": props["os_version"],
                "api": int(props["api"]),
                "model": props["model"],
                "abi": props["abi"],
                "page_size": int(page_size),
                "facility": "physical",
                "device_id": device_id,
                "channel": "preinstalled_lab",
            }
        )
        require(
            device_id == lab["device_id"]
            and actual["api"] >= 31
            and actual["abi"] in preflight["abis"],
            "environment binding mismatch",
        )
        match_target(actual, cell["target"])
        result["environment"] = actual
        raw_path = (
            session.call(
                "package_path", ["shell", "-n", "pm", "path", "fixture.validation"]
            )
            .decode()
            .strip()
        )
        require(
            re.fullmatch(r"package:/data/app/[A-Za-z0-9_./=+-]+/base\.apk", raw_path)
            is not None
            and ".." not in raw_path,
            "installed package path",
        )
        package_path = raw_path.removeprefix("package:")
        artifact_path = recorder.root / "artifacts" / ("pre_" + nonce + ".apk")
        artifact_path.parent.mkdir(mode=0o700, exist_ok=True)
        session.call(
            "apk_pre", ["exec-out", "cat", package_path], artifact_path=artifact_path
        )
        device_admitted = True
        require(
            session.call(
                "xml_pre", ["shell", "-n", "test", "-e", remote_xml], allow_absent=True
            )
            == b"",
            "setup_failed",
        )
        fixture_touched = True
        session.call(
            "force_stop_pre", ["shell", "-n", "am", "force-stop", "fixture.validation"]
        )
        require(
            session.call(
                "process_pre",
                ["shell", "-n", "pidof", "fixture.validation"],
                allow_absent=True,
            )
            == b"",
            "setup_failed",
        )
        result["setup"] = phase("verified", "none", session.refs["setup"])
        decisions: dict[str, dict[str, typing.Any]] = {}
        for stage in ("baseline", "execution"):
            session.stage = stage
            session.call(
                "launch_" + stage,
                [
                    "shell",
                    "-n",
                    "am",
                    "start",
                    "-W",
                    "-n",
                    "fixture.validation/.MainActivity",
                    "--es",
                    "validation_nonce",
                    nonce,
                    "--es",
                    "validation_scenario",
                    cell["scenario"],
                    "--es",
                    "validation_phase",
                    stage,
                ],
            )
            for attempt in range(15):
                xml_owned = True
                session.call(
                    "dump_" + stage, ["shell", "-n", "uiautomator", "dump", remote_xml]
                )
                raw = session.call("ui_" + stage, ["exec-out", "cat", remote_xml])
                try:
                    event = fixture_xml(raw)
                except ValidationError:
                    if attempt == 14:
                        raise
                    time.sleep(2)
                    continue
                decisions[stage] = check_fixture(
                    event,
                    nonce,
                    stage,
                    cell["scenario"],
                    preflight["policy_sha256"],
                    preflight["config_sha256"],
                )
                break
            result[stage] = phase("verified", "none", session.refs[stage])
        decision = decisions["execution"]
        mismatch = cell["scenario"] == "android_policy_hash_mismatch"
        result.update(
            outcome="business_denial" if mismatch is True else "benign",
            reason="policy_hash_mismatch" if mismatch is True else "none",
        )
        result["observation"].update(
            state="unavailable" if mismatch is True else "absent",
            rule_id=decision["rule_id"],
            rule_version=decision["rule_version"],
            status=decision["rule_status"],
            evidence_ids=session.refs["execution"],
        )
        result["operation"].update(
            state="denied" if mismatch is True else "completed",
            api_status=decision["status"],
            action=decision["action"],
            gate_reason=decision["reason"],
            before=decision["before"],
            after=decision["after"],
            policy_sha256=decision["policy_sha256"],
            config_sha256=decision["config_sha256"],
            evidence_ids=session.refs["execution"],
        )
    except (ValidationError, OSError, UnicodeError) as error:
        reason = str(error) if str(error) in REASONS else "evidence_mismatch"
        result.update(outcome="error", reason=reason)
        result[session.stage] = phase("failed", reason, session.refs[session.stage])
    finally:
        clean = True
        session.stage = "cleanup"
        try:
            if device_admitted is True and fixture_touched is True:
                session.call(
                    "force_stop_post",
                    ["shell", "-n", "am", "force-stop", "fixture.validation"],
                )
                if xml_owned is True:
                    session.call("remove_xml", ["shell", "-n", "rm", "-f", remote_xml])
                    require(
                        session.call(
                            "xml_post",
                            ["shell", "-n", "test", "-e", remote_xml],
                            allow_absent=True,
                        )
                        == b"",
                        "cleanup_failed",
                    )
                require(
                    session.call(
                        "process_post",
                        ["shell", "-n", "pidof", "fixture.validation"],
                        allow_absent=True,
                    )
                    == b"",
                    "cleanup_failed",
                )
                require(package_path is not None, "cleanup_failed")
                session.call(
                    "apk_post",
                    ["exec-out", "cat", typing.cast(str, package_path)],
                    artifact_path=recorder.root
                    / "artifacts"
                    / ("post_" + nonce + ".apk"),
                )
        except (ValidationError, OSError, UnicodeError):
            clean = False
        try:
            session.close()
        except (ValidationError, OSError, subprocess.TimeoutExpired):
            clean = False
        result["cleanup"] = phase(
            "verified" if clean is True else "failed",
            "none" if clean is True else "cleanup_failed",
            session.refs["cleanup"],
        )
        if clean is False:
            result.update(outcome="error", reason="cleanup_failed")
    return result


def check_result(
    value: typing.Any,
    cell: dict[str, typing.Any],
    evidence: dict[str, dict[str, typing.Any]],
) -> dict[str, typing.Any]:
    """Close result records and bind all referenced proof to its actual phase/cell."""
    result = obj(
        value,
        "cell_id nonce environment baseline setup execution cleanup observation operation outcome reason",
    )
    require(
        result["cell_id"] == cell["id"]
        and result["outcome"] in OUTCOMES
        and result["reason"] in REASONS,
        "result identity/outcome",
    )
    text(result["nonce"], r"[a-f0-9]{32}")
    environment(result["environment"])
    if result["execution"]["state"] == "verified":
        match_target(result["environment"], cell["target"])
    for stage in PHASES:
        row = obj(result[stage], "state evidence_ids reason")
        require(
            row["state"] in {"verified", "failed", "not_run"}
            and row["reason"] in REASONS,
            "phase state",
        )
        refs = array(row["evidence_ids"], 32)
        require(
            len(refs) == len({ident(ref) for ref in refs}), "duplicate phase reference"
        )
        require(
            (row["state"] == "not_run" and refs == [])
            or (row["state"] == "failed")
            or (
                row["state"] == "verified" and len(refs) > 0 and row["reason"] == "none"
            ),
            "missing phase evidence",
        )
        for ref in refs:
            require(
                ref in evidence
                and evidence[ref]["cell_id"] == cell["id"]
                and evidence[ref]["nonce"] == result["nonce"]
                and evidence[ref]["phase"] == stage,
                "cross-phase/stale evidence",
            )
    observation = obj(
        result["observation"], "state rule_id rule_version status evidence_ids"
    )
    require(
        observation["state"]
        in {"present", "absent", "unavailable", "unsupported", "not_run"},
        "observation state",
    )
    operation = obj(
        result["operation"],
        "state api_status action gate_reason before after policy_sha256 config_sha256 evidence_ids",
    )
    require(
        operation["state"] in {"completed", "denied", "unknown", "not_run"},
        "operation state",
    )
    for key in ("api_status", "action", "gate_reason"):
        if operation[key] is not None:
            integer(operation[key], 0, 2**32 - 1)
    for key in ("before", "after"):
        if operation[key] is not None:
            integer(operation[key], 0, 2)
    for key in ("policy_sha256", "config_sha256"):
        if operation[key] is not None:
            digest(operation[key])
    if observation["rule_id"] is not None:
        text(observation["rule_id"])
    for key in ("rule_version", "status"):
        if observation[key] is not None:
            integer(observation[key], 1 if key == "rule_version" else 0, 2**32 - 1)
    for row in (observation, operation):
        refs = array(row["evidence_ids"], 32)
        require(
            set(refs) <= set(result["execution"]["evidence_ids"])
            and len(refs) == len(set(refs)),
            "observation/operation evidence",
        )
    require(
        result["outcome"] not in {"observed_detection", "bypass", "unsupported"},
        "no such v1 adapter evidence",
    )
    return result


def verify_bundle(
    plan: dict[str, typing.Any], root: pathlib.Path
) -> dict[str, typing.Any]:
    """Independently derive outcomes from retained artifacts and phase transcripts."""
    check_plan(plan)
    files = checked_files(plan, root / "inputs")
    bundle = obj(
        decode(read_file(root, "result.json", 2 * MIB), 2 * MIB),
        "version run_id plan_sha256 suite_sha256 source_head source_tree build_receipt_sha256 results evidence artifacts measurements summary",
    )
    require(
        type(bundle["version"]) is int
        and bundle["version"] == 1
        and str(uuid.UUID(bundle["run_id"], version=4)) == bundle["run_id"],
        "bundle version/run id",
    )
    for key in ("suite_sha256", "source_head", "source_tree", "build_receipt_sha256"):
        require(bundle[key] == plan[key], "bundle source/build binding")
    require(
        bundle["plan_sha256"] == sha(b"val01.plan.v1\0" + canonical(plan)),
        "plan binding",
    )
    require(decode(read_file(root, "plan.json", MIB)) == plan, "retained plan mismatch")
    raw_evidence: dict[str, dict[str, typing.Any]] = {}
    paths: set[str] = {
        "result.json",
        "plan.json",
        *("inputs/" + row["path"] for row in plan["files"]),
    }
    hashes: set[str] = set()
    text_bytes = 0
    for entry in array(bundle["evidence"], 256):
        row = obj(entry, "id path bytes sha256 run_id cell_id nonce phase kind")
        evidence_id = ident(row["id"])
        path = relative(row["path"])
        require(
            evidence_id not in raw_evidence
            and path not in paths
            and row["sha256"] not in hashes
            and row["phase"] in PHASES
            and row["kind"] in {"host", "adb", "fixture"},
            "duplicate/invalid evidence",
        )
        raw = read_file(root, path, 8192 if row["kind"] == "fixture" else 256 * 1024)
        require(
            len(raw) == integer(row["bytes"], 1, 256 * 1024)
            and sha(raw) == digest(row["sha256"])
            and row["run_id"] == bundle["run_id"],
            "evidence hash/run binding",
        )
        envelope = decode(raw)
        if row["kind"] == "fixture":
            obj(
                envelope,
                "run_id cell_id nonce phase metric index role value unit conditions_sha256 artifact_id",
            )
        else:
            obj(
                envelope,
                "run_id cell_id nonce phase kind probe data stderr exit_code signal elapsed_ms artifact",
            )
            require(
                type(envelope["data"]) is str
                and type(envelope["stderr"]) is str
                and len(envelope["data"].encode()) <= 240 * 1024,
                "text output bound",
            )
            require(envelope["probe"] in PROBES, "unknown evidence probe")
            integer(envelope["elapsed_ms"], 0, 120000)
            require(
                (envelope["exit_code"] is None) != (envelope["signal"] is None),
                "process termination representation",
            )
            if envelope["exit_code"] is not None:
                integer(envelope["exit_code"], 0, 255)
            if envelope["signal"] is not None:
                integer(envelope["signal"], 1, 64)
            require(envelope["kind"] == row["kind"], "evidence kind binding")
        for key in ("run_id", "cell_id", "nonce", "phase"):
            require(envelope[key] == row[key], "phase/cell/nonce binding")
        text_bytes += len(raw)
        require(text_bytes <= 16 * MIB, "aggregate text cap")
        paths.add(path)
        hashes.add(row["sha256"])
        raw_evidence[evidence_id] = envelope
    artifacts: dict[str, dict[str, typing.Any]] = {}
    total_bytes = sum(row["bytes"] for row in plan["files"])
    for entry in array(bundle["artifacts"], 96 - len(plan["files"])):
        row = obj(entry, "path bytes sha256 file_id run_id cell_id nonce phase")
        path = relative(row["path"])
        require(
            path not in paths and row["run_id"] == bundle["run_id"],
            "streamed artifact identity",
        )
        original = one_file_by_id(plan, row["file_id"])
        require(
            original["role"] == "apk_signed"
            and row["bytes"] == original["bytes"]
            and row["sha256"] == original["sha256"],
            "binary stream declared binding",
        )
        raw = read_file(root, path, 64 * MIB)
        require(
            len(raw) == row["bytes"] and sha(raw) == row["sha256"],
            "retained binary stream missing/changed",
        )
        total_bytes += len(raw)
        require(total_bytes <= 256 * MIB, "streamed artifact aggregate cap")
        artifacts[path] = row
        paths.add(path)
    for row in raw_evidence.values():
        if row.get("artifact") is not None:
            require(
                row["artifact"]["path"] in artifacts
                and row["artifact"] == artifacts[row["artifact"]["path"]],
                "unretained binary evidence",
            )
            require(
                all(
                    row[key] == row["artifact"][key]
                    for key in ("run_id", "cell_id", "nonce", "phase")
                ),
                "binary phase binding",
            )
    results = array(bundle["results"], 8, 1)
    require(len(results) == len(plan["cells"]), "missing cell")
    by_cell = {row["cell_id"]: row for row in results}
    require(
        set(by_cell) == {cell["id"] for cell in plan["cells"]}
        and len(by_cell) == len(results),
        "duplicate/unplanned result",
    )
    used: set[str] = set()
    nonces: set[str] = set()
    android_needed = any(
        row["outcome"] in {"benign", "business_denial"} for row in results
    )
    preflight = (
        android_preflight(plan, files, root / "inputs")
        if android_needed is True
        else None
    )
    for cell in plan["cells"]:
        result = check_result(by_cell[cell["id"]], cell, raw_evidence)
        require(result["nonce"] not in nonces, "reused nonce")
        nonces.add(result["nonce"])
        for stage in PHASES:
            used.update(result[stage]["evidence_ids"])
        if result["outcome"] == "not_run":
            require(
                result == empty_result(cell, result["nonce"], result["reason"])
                and result["reason"]
                in {"facility_missing", "adapter_unavailable", "budget_exhausted"},
                "forged unrun result",
            )
            continue
        transcripts = {
            stage: [raw_evidence[ref] for ref in result[stage]["evidence_ids"]]
            for stage in PHASES
        }
        if cell["adapter"] == "host_c" and result["execution"]["state"] == "verified":
            expected = {
                "baseline": {
                    "nonce": result["nonce"],
                    "phase": "baseline",
                    "before": 0,
                    "after": 1,
                },
                "setup": {"nonce": result["nonce"], "phase": "setup", "info_status": 3},
                "execution": {
                    "nonce": result["nonce"],
                    "phase": "execution",
                    "api_status": 3,
                    "action": 0,
                    "info_status": 3,
                    "before": 0,
                    "after": 0,
                },
            }
            for stage, event in expected.items():
                require(
                    len(transcripts[stage]) == 1
                    and transcripts[stage][0]["probe"] == "host_event"
                    and transcripts[stage][0]["exit_code"] == 0
                    and canonical(decode(transcripts[stage][0]["data"].encode()))
                    == canonical(event),
                    "forged host phase",
                )
            host_file = [
                entry
                for entry in plan["files"]
                if entry["id"] in cell["artifact_ids"]
                and entry["role"] == "host_executable"
            ]
            require(len(host_file) == 1, "host artifact")
            static_host(files[host_file[0]["id"]])
            require(
                result["outcome"] == "error"
                and result["reason"]
                == (
                    "runtime_unavailable"
                    if result["cleanup"]["state"] == "verified"
                    else "cleanup_failed"
                )
                and result["operation"]
                == {
                    "state": "unknown",
                    "api_status": 3,
                    "action": 0,
                    "gate_reason": None,
                    "before": 0,
                    "after": 0,
                    "policy_sha256": None,
                    "config_sha256": None,
                    "evidence_ids": result["execution"]["evidence_ids"],
                },
                "startup error cannot become denial",
            )
            require(
                result["observation"]
                == {
                    "state": "unavailable",
                    "rule_id": None,
                    "rule_version": None,
                    "status": None,
                    "evidence_ids": [],
                },
                "invented host detection",
            )
            if result["cleanup"]["state"] == "verified":
                require(
                    len(transcripts["cleanup"]) == 1
                    and transcripts["cleanup"][0]["probe"] == "host_cleanup",
                    "missing host cleanup",
                )
                proof = decode(transcripts["cleanup"][0]["data"].encode())
                require(
                    proof
                    == {
                        "process_reaped": True,
                        "scratch_empty": True,
                        "artifact_sha256": host_file[0]["sha256"],
                    },
                    "host cleanup proof",
                )
        elif result["outcome"] in {"benign", "business_denial"}:
            if preflight is None:
                raise ValidationError("missing Android preflight")
            require(
                cell["adapter"] == "android_adb"
                and cell["context"] == "clean"
                and all(result[stage]["state"] == "verified" for stage in PHASES),
                "missing Android phases",
            )
            setup = {
                probe: [row for row in transcripts["setup"] if row["probe"] == probe]
                for probe in PROBES
            }
            props: dict[str, str] = {}
            for key in (
                "api",
                "os_version",
                "model",
                "abi",
                "emulator",
                "fingerprint",
                "pages",
            ):
                require(
                    len(setup["env_" + key]) == 1, "missing/duplicate environment probe"
                )
                props[key] = text(setup["env_" + key][0]["data"].strip())
            require(
                re.fullmatch(r"[0-9]{1,4}", props["api"]) is not None
                and re.fullmatch(r"[0-9]{4,5}", props["pages"]) is not None
                and props["emulator"] == "0",
                "environment probe value",
            )
            lab = lab_descriptor(
                decode(files[one_file(plan, "lab_descriptor")["id"]]),
                plan,
                preflight,
            )
            for stage in PHASES:
                for row in transcripts[stage]:
                    require(row["kind"] == "adb", "Android probe kind")
                    check_probe(
                        row["probe"],
                        row["data"].encode(),
                        row["stderr"].encode(),
                        row["exit_code"],
                        row["signal"],
                    )

            observed_environment: dict[str, typing.Any] = {
                "os": "android",
                "os_version": props["os_version"],
                "api": int(props["api"]),
                "model": props["model"],
                "abi": props["abi"],
                "page_size": int(props["pages"]),
                "facility": "physical",
                "device_id": sha(
                    b"val01.device.v1\0"
                    + (lab["serial"] + "\n" + props["fingerprint"]).encode()
                ),
                "channel": "preinstalled_lab",
            }
            require(
                result["environment"] == observed_environment
                and observed_environment["device_id"] == lab["device_id"]
                and observed_environment["api"] >= 31
                and observed_environment["abi"] in preflight["abis"],
                "forged environment",
            )
            require(len(setup["server_started"]) == 1, "missing server ownership")
            started = obj(
                decode(setup["server_started"][0]["data"].encode()),
                "pid endpoint device_restriction tool_sha256",
            )
            integer(started["pid"], 1)
            text(
                started["endpoint"],
                r"localfilesystem:/tmp/v01-[A-Za-z0-9_-]+/server\.sock",
            )
            require(
                started["device_restriction"] == "usb_only"
                and started["tool_sha256"]
                == one_file_by_id(plan, lab["adb_file_id"])["sha256"],
                "server tool/device restriction",
            )
            require(
                [row["probe"] for row in transcripts["setup"]]
                == [
                    "adb_help",
                    "server_started",
                    "get_state",
                    "env_api",
                    "env_os_version",
                    "env_model",
                    "env_abi",
                    "env_emulator",
                    "env_fingerprint",
                    "env_pages",
                    "package_path",
                    "apk_pre",
                    "xml_pre",
                    "force_stop_pre",
                    "process_pre",
                ],
                "missing/ordered setup prerequisites",
            )
            require(
                [row["probe"] for row in transcripts["cleanup"]]
                == [
                    "force_stop_post",
                    "remove_xml",
                    "xml_post",
                    "process_post",
                    "apk_post",
                    "server_stdout",
                    "server_stderr",
                    "server_cleanup",
                ],
                "missing/ordered cleanup prerequisites",
            )
            for stage in ("baseline", "execution"):
                sequence = [row["probe"] for row in transcripts[stage]]
                require(
                    len(sequence) >= 3
                    and sequence
                    == ["launch_" + stage]
                    + ["dump_" + stage, "ui_" + stage] * ((len(sequence) - 1) // 2),
                    "missing/ordered UI prerequisites",
                )
                views = [
                    row for row in transcripts[stage] if row["probe"] == "ui_" + stage
                ]
                require(
                    len(views) >= 1 and views[-1]["exit_code"] == 0, "missing UI proof"
                )
                decision = check_fixture(
                    fixture_xml(views[-1]["data"].encode()),
                    result["nonce"],
                    stage,
                    cell["scenario"],
                    preflight["policy_sha256"],
                    preflight["config_sha256"],
                )
                if stage == "execution":
                    require(
                        result["operation"]["before"] == decision["before"]
                        and result["operation"]["after"] == decision["after"]
                        and result["operation"]["api_status"] == decision["status"]
                        and result["operation"]["action"] == decision["action"]
                        and result["operation"]["gate_reason"] == decision["reason"]
                        and result["operation"]["policy_sha256"]
                        == decision["policy_sha256"]
                        and result["operation"]["config_sha256"]
                        == decision["config_sha256"],
                        "forged operation",
                    )
            for stage in ("setup", "cleanup"):
                for row in transcripts[stage]:
                    if row["probe"] in {"apk_pre", "apk_post"}:
                        require(
                            row["artifact"] is not None, "missing retained APK stream"
                        )
                    if row["probe"] == "server_cleanup":
                        require(
                            canonical(decode(row["data"].encode()))
                            == canonical(
                                {
                                    "server_reaped": True,
                                    "endpoint_removed": True,
                                    "client_fork_limit": 0,
                                    "pid": started["pid"],
                                    "endpoint": started["endpoint"],
                                }
                            ),
                            "unproved server cleanup",
                        )
            mismatch = cell["scenario"] == "android_policy_hash_mismatch"
            require(
                result["observation"]
                == {
                    "state": "unavailable" if mismatch is True else "absent",
                    "rule_id": decision["rule_id"],
                    "rule_version": decision["rule_version"],
                    "status": decision["rule_status"],
                    "evidence_ids": result["execution"]["evidence_ids"],
                },
                "invented Android observation",
            )
            require(
                result["outcome"]
                == ("business_denial" if mismatch is True else "benign")
                and result["operation"]["state"]
                == ("denied" if mismatch is True else "completed")
                and result["reason"]
                == ("policy_hash_mismatch" if mismatch is True else "none"),
                "derived Android outcome",
            )
        else:
            require(
                result["outcome"] in {"error", "crash"}
                and any(result[stage]["state"] == "failed" for stage in PHASES),
                "unproved failure",
            )
    measured = {key: row for key, row in raw_evidence.items() if "metric" in row}
    check_measurements(bundle["measurements"], measured, set(by_cell), set(files))
    measured_refs = {
        sample[role + "_evidence_id"]
        for pair in bundle["measurements"]
        for sample in pair["samples"]
        for role in ("baseline", "protected")
    }
    require(measured_refs == set(measured), "unreferenced measured evidence")
    for row in measured.values():
        require(
            row["cell_id"] in by_cell
            and row["nonce"] == by_cell[row["cell_id"]]["nonce"],
            "measured nonce binding",
        )
    used.update(measured_refs)
    require(used == set(raw_evidence), "unreferenced evidence")
    summary = obj(
        bundle["summary"],
        "planned by_outcome missing_cells conformance release_gate effectiveness_gate performance_gate",
    )
    integer(summary["planned"], 1, 8)
    for count in obj(summary["by_outcome"], " ".join(OUTCOMES)).values():
        integer(count, 0, 8)
    for missing_cell in array(summary["missing_cells"], 8):
        ident(missing_cell)
    require(
        bundle["summary"] == summarize(plan["cells"], results),
        "forged summary/denominator",
    )
    actual_paths: set[str] = set()
    for bundle_path in root.rglob("*"):
        mode = bundle_path.lstat().st_mode
        require(stat.S_ISLNK(mode) is False, "bundle link")
        if stat.S_ISDIR(mode) is False:
            actual_paths.add(bundle_path.relative_to(root).as_posix())
            require(mode & 0o077 == 0, "nonprivate bundle file")
        else:
            require(mode & 0o077 == 0, "nonprivate bundle directory")
    require(actual_paths == paths, "unreferenced bundle files")
    return bundle


def run_plan(
    plan: dict[str, typing.Any],
    inputs: pathlib.Path,
    output: pathlib.Path,
    lab_id: str | None = None,
) -> dict[str, typing.Any]:
    """Execute one validated plan in a new private directory, then independently verify."""
    check_plan(plan)
    files = checked_files(plan, inputs)
    git = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
    ]
    identity = command([*git, "rev-parse", "HEAD", "HEAD^{tree}"], pathlib.Path.cwd())
    status = command(
        [*git, "status", "--porcelain=v1", "--untracked-files=all"], pathlib.Path.cwd()
    )
    require(
        identity.returncode == 0
        and identity.reason == "none"
        and status.returncode == 0
        and status.reason == "none",
        "source identity unavailable",
    )
    source = identity.stdout.decode().splitlines()
    dirty = status.stdout
    require(
        source == [plan["source_head"], plan["source_tree"]] and dirty == b"",
        "source_mismatch",
    )
    require(output.exists() is False, "output already exists")
    output.mkdir(mode=0o700)
    for row in plan["files"]:
        write_file(
            output,
            "inputs/" + row["path"],
            files[row["id"]],
            row["role"] in {"host_executable", "tool"},
        )
    write_file(output, "plan.json", canonical(plan))
    recorder = Recorder(plan, output)
    recorder.commands = 2
    preflight: dict[str, typing.Any] | None = None
    lab: dict[str, typing.Any] | None = None
    if lab_id is not None:
        require(
            one_file_by_id(plan, ident(lab_id))["role"] == "lab_descriptor", "lab role"
        )
        preflight = android_preflight(plan, files, output / "inputs")
        lab = check_lab(decode(files[lab_id]), plan, files, preflight)
    results: list[dict[str, typing.Any]] = []
    device_stopped = False
    for cell in plan["cells"]:
        nonce = secrets.token_hex(16)
        recorder.cell_deadline = min(recorder.deadline, time.monotonic() + 120)
        if recorder.deadline - time.monotonic() < 25 or recorder.commands > 220:
            result = empty_result(cell, nonce, "budget_exhausted")
        elif cell["adapter"] == "host_c":
            result = host_run(recorder, cell, nonce, files)
        elif (
            cell["adapter"] == "ios_unavailable"
            or cell["context"] != "clean"
            or cell["facility"] == "emulator"
            or device_stopped is True
        ):
            result = empty_result(cell, nonce, "adapter_unavailable")
        elif lab is None or preflight is None:
            result = android_unavailable(cell, nonce)
        else:
            result = android_run(recorder, cell, nonce, lab, preflight)
            device_stopped = result["cleanup"]["state"] != "verified"
        checked_files(plan, output / "inputs")
        results.append(result)
    bundle = {
        "version": 1,
        "run_id": recorder.run_id,
        "plan_sha256": sha(b"val01.plan.v1\0" + canonical(plan)),
        **{
            key: plan[key]
            for key in (
                "suite_sha256",
                "source_head",
                "source_tree",
                "build_receipt_sha256",
            )
        },
        "results": results,
        "evidence": recorder.evidence,
        "artifacts": recorder.artifacts,
        "measurements": [],
        "summary": summarize(plan["cells"], results),
    }
    raw = canonical(bundle)
    require(len(raw) <= 2 * MIB, "bundle byte limit")
    write_file(output, "result.pending", raw)
    os.link(output / "result.pending", output / "result.json")
    (output / "result.pending").unlink()
    return verify_bundle(plan, output)


def main() -> int:
    """Expose only run/verify; invalid inputs never invoke an adapter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--plan", required=True, type=pathlib.Path)
    parser.add_argument("--inputs", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--bundle", type=pathlib.Path)
    parser.add_argument("--lab")
    args = parser.parse_args()
    try:
        plan = check_plan(decode(read_file(args.plan.parent, args.plan.name, MIB)))
        if args.mode == "run":
            require(
                args.inputs is not None
                and args.output is not None
                and args.bundle is None,
                "run arguments",
            )
            bundle = run_plan(plan, args.inputs, args.output, args.lab)
        else:
            require(
                args.bundle is not None
                and args.inputs is None
                and args.output is None
                and args.lab is None,
                "verify arguments",
            )
            bundle = verify_bundle(plan, args.bundle)
        print(json.dumps(bundle["summary"], sort_keys=True))
        return (
            0
            if bundle["summary"]["conformance"] == "pass"
            and bundle["summary"]["release_gate"] != "fail"
            else 1
        )
    except (
        ValidationError,
        UnicodeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as error:
        print("validation rejected: " + str(error)[:200], file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as error:
        print("validation I/O failure: " + type(error).__name__, file=sys.stderr)
        return 3


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--bounded-child":
        child_limits()
        if sys.argv[2] == "1":
            require(os.geteuid() != 0, "root clients cannot enforce no-fork")
            resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
        os.execvpe(sys.argv[3], sys.argv[3:], dict(os.environ))
    sys.exit(main())

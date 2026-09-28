"""Run trusted local/device-farm adapters and fail release gates on missing evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import typing
import uuid
import xml.etree.ElementTree as element_tree

from rasp_assurance import crashmaps

SCENARIOS = frozenset(
    {
        "baseline",
        "frida-fork",
        "hidden-root",
        "jailbreak",
        "attestation-spoof",
        "attestation-relay",
        "static-patch",
    }
)
REQUIRED = {
    "android": SCENARIOS - {"jailbreak"},
    "ios": SCENARIOS - {"hidden-root"},
}


def command(args: list[str], environment: dict[str, str], timeout: int) -> bytes:
    if (
        not isinstance(args, list)
        or not 1 <= len(args) <= 64
        or any(not isinstance(arg, str) or len(arg) > 4096 for arg in args)
    ):
        raise ValueError("adapter must be an argument list")
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError("adapter timeout must be 1..600 seconds")
    # Operators own adapter commands. Never use a shell or return their raw logs:
    # device logs may contain tokens. Bound output and terminate descendant processes.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            args,
            stdout=output,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if (
                    time.monotonic() >= deadline
                    or os.fstat(output.fileno()).st_size > 262144
                ):
                    raise ValueError("adapter timeout or output limit")
                time.sleep(0.02)
            if process.returncode != 0 or os.fstat(output.fileno()).st_size > 262144:
                raise ValueError("adapter failed")
            output.seek(0)
            return output.read(262144)
        finally:
            # Also reap orphaned adapter children even if the direct process exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def evaluate(value: dict[str, typing.Any], expected: dict[str, str]) -> bool:
    if not isinstance(value, dict) or any(
        value.get(key) != item for key, item in expected.items()
    ):
        raise ValueError("evidence is not bound to this run/device/build/scenario")
    if (
        value.get("fixtureVerified") is not True
        or value.get("baselineAllowed") is not True
    ):
        raise ValueError("fixture and legitimate positive control must be verified")
    if type(value.get("enforced")) is not bool:
        raise ValueError("enforcement result required")
    return (
        value["enforced"]
        if expected["scenario"] != "baseline"
        else value["enforced"] is False
    )


def run(configuration: dict[str, typing.Any]) -> dict[str, typing.Any]:
    platform, device, artifact = (
        configuration["platform"],
        configuration["device"],
        pathlib.Path(configuration["artifact"]),
    )
    if (
        platform not in REQUIRED
        or not isinstance(device, str)
        or not 1 <= len(device) <= 200
    ):
        raise ValueError("platform and device required")
    cases = configuration["cases"]
    if not isinstance(cases, list) or len(cases) > len(SCENARIOS):
        raise ValueError("bounded scenario list required")
    names = [case["scenario"] for case in cases]
    if len(set(names)) != len(names) or not set(names) <= SCENARIOS:
        raise ValueError("invalid or duplicate scenarios")
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    run_id = str(uuid.uuid4())
    results: list[dict[str, typing.Any]] = []
    for case in cases:
        expected = {
            "runId": run_id,
            "device": device,
            "artifactSha256": digest.hexdigest(),
            "scenario": case["scenario"],
        }
        environment = {
            name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ
        }
        environment["RASP_FARM_CONTEXT"] = json.dumps(expected)
        environment["RASP_FARM_ARTIFACT"] = str(artifact.resolve())
        result: dict[str, typing.Any] = {
            "scenario": case["scenario"],
            "status": "error",
        }
        timeout = case.get("timeoutSeconds", 120)
        try:
            if "prepare" in case:
                command(case["prepare"], environment, timeout)
            value = json.loads(command(case["probe"], environment, timeout))
            result["status"] = (
                "passed" if evaluate(value, expected) is True else "failed"
            )
        except (ValueError, OSError, TypeError, KeyError):
            result["status"] = "error"
        finally:
            if "cleanup" in case:
                try:
                    command(case["cleanup"], environment, timeout)
                except (ValueError, OSError, TypeError):
                    result["status"] = "error"
        results.append(result)
    for missing in sorted(REQUIRED[platform] - set(names)):
        results.append({"scenario": missing, "status": "not_run"})
    return {
        "schema": "rasp-farm-1",
        "runId": run_id,
        "device": device,
        "platform": platform,
        "artifactSha256": digest.hexdigest(),
        "passed": all(item["status"] == "passed" for item in results),
        "cases": results,
    }


def junit(report: dict[str, typing.Any]) -> str:
    suite = element_tree.Element(
        "testsuite", name="rasp-device-farm", tests=str(len(report["cases"]))
    )
    failures = 0
    for result in report["cases"]:
        case = element_tree.SubElement(
            suite, "testcase", name=result["scenario"], classname=report["platform"]
        )
        if result["status"] != "passed":
            failures += 1
            element_tree.SubElement(case, "failure", message=result["status"])
    suite.set("failures", str(failures))
    return element_tree.tostring(suite, encoding="unicode")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=pathlib.Path)
    parser.add_argument("--junit", type=pathlib.Path)
    args = parser.parse_args()
    try:
        report = run(json.loads(crashmaps.read_bounded(args.configuration, 262144)))
        if args.junit is not None:
            args.junit.write_text(junit(report))
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] is True else 1
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({"passed": False, "error": "invalid_farm_configuration"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Prepare genuine unsigned integration inputs offline; never execute ADB or sign/install."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import os
import pathlib
import subprocess
import sys
import typing
import zipfile

from validation import run


def dependency_manifest(snapshot: pathlib.Path) -> dict[str, typing.Any]:
    """Measure the installed production distributions and this process's real closure."""
    paths = {pathlib.Path(sys.executable).resolve(), snapshot.resolve()}
    distributions = []
    for name in ("rasp-packer", "lief", "cryptography"):
        distribution = importlib.metadata.distribution(name)
        distributions.append(
            {
                "name": name,
                "version": distribution.version,
                "wheel_id": "packer_wheel" if name == "rasp-packer" else None,
            }
        )
        entries = distribution.files
        if entries is None:
            raise run.ValidationError("missing installed distribution inventory")
        for entry in entries:
            paths.add(pathlib.Path(str(distribution.locate_file(entry))).resolve())
    for module in tuple(sys.modules.values()):
        namespace = vars(module) if module is not None else {}
        for key in ("__file__", "__cached__"):
            value = namespace.get(key)
            if value is not None:
                path = pathlib.Path(value).resolve()
                if path.is_file() is True:
                    paths.add(path)
    for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith("/"):
            paths.add(pathlib.Path(fields[5]).resolve())
    records = []
    for path in sorted(paths):
        data = run.read_file(path.parent, path.name, 64 * run.MIB)
        records.append({"path": str(path), "bytes": len(data), "sha256": run.sha(data)})
    manifest = {
        "version": 1,
        "python": str(pathlib.Path(sys.executable).resolve()),
        "prefix": sys.prefix,
        "files": records,
        "distributions": distributions,
    }
    run.dependency_bindings(manifest)
    return manifest


def prepare(args: argparse.Namespace) -> dict[str, typing.Any]:
    """Build the fixed fixture with the real SDK, pack it and verify the retained inventory."""
    root = pathlib.Path(__file__).resolve().parents[1]
    adb_data = run.read_file(args.adb.parent, args.adb.name, 64 * run.MIB)
    run.require(run.sha(adb_data) == run.digest(args.adb_sha256), "ADB digest mismatch")
    wheel_data = run.read_file(args.wheel.parent, args.wheel.name, 64 * run.MIB)
    bridge_data = run.read_file(args.bridge.parent, args.bridge.name, 64 * run.MIB)
    modules = {
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
    policy_path = root / "docs/fixtures/local-policy-android-v1.json"
    policy_data = run.read_file(policy_path.parent, policy_path.name, 2048)
    policy = modules["local_policy"].parse(policy_data)
    config = modules["runtime_config"].RuntimeConfig(
        build_id="val01", checks=("debugger", "identity"), local_policy=policy
    )
    resources = modules["android.resources"].load()
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    snapshot = output / "adb.snapshot"
    run.write_file(output, snapshot.name, adb_data)
    snapshot.chmod(0o400)
    run.write_file(output, "compile-bridge.jar", bridge_data)
    fixture = output / "fixture"
    environment = dict(
        os.environ,
        PYTHONDONTWRITEBYTECODE="1",
        PACKER_PYTHON=sys.executable,
        ANDROID_JAR=str(args.android_jar.absolute()),
        ANDROID_BUILD_TOOLS=str(args.build_tools.absolute()),
    )
    subprocess.run(
        [
            "/bin/bash",
            str(root / "validation/fixtures/android/build.sh"),
            str(fixture),
            str(output / "compile-bridge.jar"),
            str(policy_path),
        ],
        env=environment,
        check=True,
        timeout=120,
    )
    app = fixture / "protected-unsigned.apk"
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "rasp_packer",
            "pack",
            str(fixture / "host-unsigned.apk"),
            "--platform",
            "android",
            "--build-id",
            "val01",
            "--checks",
            "debugger",
            "--local-policy",
            str(policy_path),
            "--output",
            str(app),
        ],
        env=environment,
        check=True,
        timeout=120,
    )
    records: list[dict[str, typing.Any]] = []
    payloads: dict[str, bytes] = {}

    def add(file_id: str, role: str, data: bytes) -> str:
        run.require(
            len(records) < 96
            and len(data)
            <= (run.MIB if role == "dependency_manifest" else 64 * run.MIB),
            "preparation inventory limit",
        )
        run.require(
            sum(row["bytes"] for row in records) + len(data) <= 256 * run.MIB,
            "aggregate preparation limit",
        )
        run.write_file(output, file_id, data)
        records.append(
            {
                "id": file_id,
                "path": file_id,
                "role": role,
                "bytes": len(data),
                "sha256": run.sha(data),
            }
        )
        payloads[file_id] = data
        return file_id

    add("policy", "policy", policy_data)
    add("config", "config", config.to_json())
    add(
        "generated",
        "fixture_source",
        run.read_file(fixture, "ExpectedPolicy.java", 64 * 1024),
    )
    add("bridge", "bridge_jar", bridge_data)
    add("stub", "stub", resources.stub_dex)
    runtimes = []
    for index, (abi, pristine) in enumerate(sorted(resources.libraries.items())):
        runtimes.append(
            {
                "abi": abi,
                "pristine_file": add(f"pristine_{index}", "native_pristine", pristine),
                "injected_file": add(
                    f"injected_{index}",
                    "native_injected",
                    modules["android.runtime_library"].write_config(pristine, config),
                ),
                "capability_file": add(
                    f"cap_{index}", "capabilities", resources.manifests[abi]
                ),
                "support_file": add(
                    f"support_{index}",
                    "policy_support",
                    resources.policy_manifests[abi],
                ),
            }
        )
    add("apk", "apk_unsigned", run.read_file(app.parent, app.name, 64 * run.MIB))
    modules["archive_validation"].check(app)
    entries = []
    with zipfile.ZipFile(app) as archive:
        run.require(
            len(archive.infolist()) <= 96
            and sum(item.file_size for item in archive.infolist()) <= 256 * run.MIB
            and all(item.file_size <= 64 * run.MIB for item in archive.infolist()),
            "APK expansion cap",
        )
        for index, entry in enumerate(archive.infolist()):
            if entry.is_dir() is False:
                entries.append(
                    {
                        "name": entry.filename,
                        "file_id": add(
                            f"entry_{index}", "injected_entry", archive.read(entry)
                        ),
                    }
                )
    add(
        "injection",
        "injection_manifest",
        run.canonical(
            {
                "version": 1,
                "entries": entries,
                "runtimes": runtimes,
                "stub_file": "stub",
                "bridge_file": "bridge",
                "compiled_policy_sha256": policy.sha256,
                "compiled_expectation_file": "generated",
                "build_id": "val01",
                "checks": ["debugger", "identity"],
                "policy_file": "policy",
            }
        ),
    )
    add("packer_wheel", "wheel", wheel_data)
    manifest = dependency_manifest(snapshot)
    add("dependencies", "dependency_manifest", run.canonical(manifest))
    verified = run.android_preflight(
        {"files": records}, payloads, output, unsigned_preparation=True
    )
    report = {
        key: value
        for key, value in verified.items()
        if key not in {"bindings", "dependency_manifest"}
    }
    report.update(
        version=1,
        input_files=records,
        unsigned_preparation_only=True,
        actual_device_execution="NOT_RUN",
        signing="NOT_RUN",
        adb_invocations=0,
        adb_snapshot={
            "path": snapshot.name,
            "bytes": len(adb_data),
            "sha256": run.sha(adb_data),
        },
    )
    run.write_file(output, "result.json", run.canonical(report))
    return report


def main() -> int:
    """Require explicit genuine artifacts and a fresh destination; do no discovery."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wheel", "bridge", "android-jar", "build-tools", "adb", "output"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    parser.add_argument("--adb-sha256", required=True)
    args = parser.parse_args()
    try:
        report = prepare(args)
        print(
            run.canonical(
                {key: value for key, value in report.items() if key != "input_files"}
            ).decode()
        )
        return 0
    except (
        run.ValidationError,
        OSError,
        ValueError,
        ImportError,
        subprocess.SubprocessError,
    ) as error:
        print("preparation rejected: " + str(error)[:200], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

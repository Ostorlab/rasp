"""Retain two validated pristine iPhoneOS Release installs, never an installed IPA.

Run only after the Apple workflow's build/consumer gates. The flat iPhoneOS
framework layout is explicit: versioned macOS frameworks and all symlinks are
rejected. No build output, source input or installed framework is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import typing

PL05_COMMIT = "1197b25162eadc202799abfe16008bef390e3482"
PL05_TREE = "b15595265d8d907439227848e064f8f66fc89844"
FRAMEWORK = pathlib.Path("rasp_packer/ios/resources/RaspRuntime.framework")
FILE_LIMITS = {
    "RaspRuntime": 64 * 1024 * 1024,
    "RaspRuntime.capabilities.json": 1024 * 1024,
    "RaspRuntime.local-policy.json": 4096,
    "Info.plist": 65536,
    "Headers/ios_capture.h": 1024 * 1024,
    "Headers/local_policy_host.h": 1024 * 1024,
    "Modules/module.modulemap": 65536,
}
PROFILE = '{"host":"collector.example","mode":"system","pins":null,"port":443,"validity":null,"version":1}'
SETTINGS = json.dumps(
    [
        {
            "name": "RASP_REPORTING_ENDPOINT",
            "value": "https://collector.example/apis/graphql",
        },
        {"name": "RASP_REPORTING_SECURITY_PROFILE", "value": PROFILE},
    ]
)


def run(command: list[str], cwd: pathlib.Path) -> str:
    """Run a fixed read-only probe; no shell, environment dump or build log export."""
    result = subprocess.run(
        command, cwd=cwd, check=True, capture_output=True, timeout=120
    )
    if len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError("probe output exceeds bound")
    return result.stdout.decode("utf-8").strip()


def digest(data: bytes) -> dict[str, typing.Any]:
    """Describe exact bytes, not configured descendants."""
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def source_identity(
    repo: pathlib.Path, revision: str = "HEAD"
) -> dict[str, typing.Any]:
    """Pin every tracked byte and mode; reject modified/missing files and gitlinks."""
    commit = run(["git", "rev-parse", f"{revision}^{{commit}}"], repo)
    tree = run(["git", "rev-parse", f"{commit}^{{tree}}"], repo)
    entries = subprocess.check_output(
        ["git", "ls-tree", "-rz", commit], cwd=repo
    ).split(b"\0")
    if len(entries) > 10001:
        raise ValueError("source file count exceeds bound")
    files: dict[str, typing.Any] = {}
    for entry in entries:
        if entry == b"":
            continue
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        name = raw_name.decode("utf-8")
        relative = pathlib.PurePosixPath(name)
        if kind != "blob" or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsupported source entry")
        path = repo / name
        if mode == "120000":
            data = os.fsencode(os.readlink(path))
        else:
            if (
                path.is_symlink()
                or path.is_file() is False
                or path.stat().st_size > 128 * 1024 * 1024
            ):
                raise ValueError(f"invalid tracked source: {name}")
            data = path.read_bytes()
            executable = path.stat().st_mode & 0o111 != 0
            if executable != (mode == "100755"):
                raise ValueError(f"modified source mode: {name}")
        observed = (
            subprocess.check_output(
                ["git", "hash-object", "--stdin"], input=data, cwd=repo
            )
            .decode()
            .strip()
        )
        if observed != blob:
            raise ValueError(f"modified source bytes: {name}")
        files[name] = {**digest(data), "git_mode": mode, "git_blob": blob}
    parents = [
        line[7:]
        for line in run(["git", "cat-file", "-p", commit], repo)
        .split("\n\n", 1)[0]
        .splitlines()
        if line.startswith("parent ")
    ]
    return {"commit": commit, "tree": tree, "parents": parents, "tracked_files": files}


def source_mapping(
    repo: pathlib.Path, actual: dict[str, typing.Any], requested: str
) -> dict[str, typing.Any]:
    """Record merge/head differences explicitly; depth two supplies merge parents."""
    if re.fullmatch(r"[0-9a-f]{40}", requested) is None:
        raise ValueError("invalid requested source commit")
    requested_tree = run(["git", "rev-parse", f"{requested}^{{tree}}"], repo)
    if requested != actual["commit"] and requested not in actual["parents"]:
        raise ValueError("requested head is neither checkout nor a direct merge parent")
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", requested, actual["commit"]], cwd=repo
    )
    return {
        "requested_head": requested,
        "requested_head_tree": requested_tree,
        "checkout_is_requested_head": actual["commit"] == requested,
        "trees_equal": actual["tree"] == requested_tree,
        "changed_paths_from_requested_head": [
            name.decode() for name in changed.split(b"\0") if name != b""
        ],
        "interpretation": "Artifacts belong to the actual checkout tree; PR head equality is not assumed.",
    }


def read_framework(framework: pathlib.Path) -> dict[str, tuple[bytes, int]]:
    """Snapshot exactly the supported flat device framework, without following links."""
    if ".." in framework.parts or any(
        path.is_symlink() for path in (framework, *framework.parents)
    ):
        raise ValueError("symlink in framework path")
    if framework.is_dir() is False:
        raise ValueError("missing framework")
    files: dict[str, tuple[bytes, int]] = {}
    for directory, directories, names in os.walk(framework, followlinks=False):
        for name in directories + names:
            path = pathlib.Path(directory) / name
            relative = path.relative_to(framework).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                if relative not in ("Headers", "Modules"):
                    raise ValueError(f"unexpected framework directory: {relative}")
                continue
            if stat.S_ISREG(mode) is False or relative not in FILE_LIMITS:
                raise ValueError(f"unexpected framework entry: {relative}")
            if path.stat().st_size > FILE_LIMITS[relative]:
                raise ValueError(f"framework file exceeds bound: {relative}")
            data = path.read_bytes()
            if len(data) == 0 or len(data) > FILE_LIMITS[relative]:
                raise ValueError(f"invalid framework size: {relative}")
            files[relative] = (data, stat.S_IMODE(mode))
    if set(files) != set(FILE_LIMITS):
        raise ValueError("missing framework files")
    return files


def build_configuration(
    build: pathlib.Path, plugins: pathlib.Path | None
) -> dict[str, str]:
    """Retain a whitelist, never the entire potentially sensitive CMake cache."""
    expected = {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_SYSTEM_NAME": "iOS",
        "CMAKE_OSX_ARCHITECTURES": "arm64",
        "CMAKE_OSX_DEPLOYMENT_TARGET": "12.0",
        "RASP_OBFUSCATE_IOS": "ON",
        "RASP_LOGGING": "OFF",
        "RASP_PLUGINS": ""
        if plugins is None
        else f"{plugins}/plugins/reporting;{plugins}/plugins/dns_reporting",
    }
    if plugins is not None:
        expected.update(
            {
                "RASP_REPORTING_ENDPOINT": "https://collector.example/apis/graphql",
                "RASP_REPORTING_SECURITY_PROFILE": PROFILE,
                "RASP_DNS_REPORTING_ZONE": "r.example",
            }
        )
    allowed = set(expected) | {
        "CMAKE_OSX_SYSROOT",
        "CMAKE_C_COMPILER",
        "CMAKE_CXX_COMPILER",
        "CMAKE_OBJCXX_COMPILER",
    }
    values = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        match = re.fullmatch(r"([^#/:][^:]*):[^=]+=(.*)", line)
        if match is not None and match[1] in allowed:
            values[match[1]] = match[2]
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValueError(f"unexpected build configuration: {key}")
    if "iphoneos" not in values.get("CMAKE_OSX_SYSROOT", "").lower():
        raise ValueError("not an iPhoneOS build")
    return values


def export_bundle(
    output: pathlib.Path,
    frameworks: dict[str, pathlib.Path],
    provenance: dict[str, typing.Any],
    validated: dict[str, dict[str, tuple[bytes, int]]] | None = None,
) -> None:
    """Export already validated snapshots with bound sidecar metadata and exact hashes.

    This checks byte/sidecar consistency, not Mach-O validity. Apple checks and
    production catalogue/policy/security validation are required by main/workflow.
    """
    if set(frameworks) != {"ordinary-release", "pl05-release"}:
        raise ValueError("exactly two classified Release frameworks are required")
    if (
        output.is_absolute() is False
        or ".." in output.parts
        or any(path.is_symlink() for path in output.parents)
        or output.exists()
        or output.is_symlink()
        or any(
            output == path or output.is_relative_to(path)
            for path in frameworks.values()
        )
    ):
        raise ValueError("output must be fresh and outside source frameworks")
    snapshots = {label: read_framework(path) for label, path in frameworks.items()}
    if validated is not None and snapshots != validated:
        raise ValueError("framework changed after production validation")
    manifest: dict[str, typing.Any] = {
        "schema_version": 1,
        "classification": "pristine-installed-iphoneos-release-frameworks; NOT installed IPA or device execution",
        "target": {
            "platform": "ios",
            "abi": "arm64",
            "minimum_os": "12.0",
            "configuration": "Release",
        },
        "provenance": provenance,
        "frameworks": {},
    }
    for label, files in snapshots.items():
        binary_hash = digest(files["RaspRuntime"][0])["sha256"]
        capability = json.loads(files["RaspRuntime.capabilities.json"][0])
        policy = json.loads(files["RaspRuntime.local-policy.json"][0])
        for document in (capability, policy):
            if any(
                document.get(key) != value
                for key, value in {
                    "artifact_sha256": binary_hash,
                    "platform": "ios",
                    "abi": "arm64",
                    "minimum_os": "12.0",
                }.items()
            ):
                raise ValueError("sidecar target/artifact mismatch")
        if capability["catalogue_id"] != policy["catalogue_id"]:
            raise ValueError("sidecar catalogue mismatch")
        manifest["frameworks"][label] = {
            "installed_source": str(frameworks[label]),
            "capability": {
                key: value for key, value in capability.items() if key != "catalogue"
            },
            "catalogue_schema": capability["catalogue"]["schema_version"],
            "catalogue_revision": capability["catalogue"]["revision"],
            "policy_support": policy,
            "files": {
                f"{label}/RaspRuntime.framework/{name}": {**digest(data), "mode": mode}
                for name, (data, mode) in files.items()
            },
        }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if len(manifest_bytes) > 8 * 1024 * 1024:
        raise ValueError("manifest exceeds bound")
    # Recheck all source bytes/modes before writing; no copies from a changed install.
    if any(
        read_framework(frameworks[label]) != files for label, files in snapshots.items()
    ):
        raise ValueError("framework changed during export")
    output.mkdir(parents=True)
    archive = output / "apple-release-frameworks.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as bundle:
        for label, files in sorted(snapshots.items()):
            for name, (data, mode) in sorted(files.items()):
                member = tarfile.TarInfo(f"{label}/RaspRuntime.framework/{name}")
                member.size, member.mode = len(data), mode
                bundle.addfile(member, io.BytesIO(data))
        member = tarfile.TarInfo("manifest.json")
        member.size, member.mode = len(manifest_bytes), 0o644
        bundle.addfile(member, io.BytesIO(manifest_bytes))
    with archive.open("rb") as stream:
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / "apple-release-frameworks.tar.sha256").write_text(
        f"{archive_hash}  {archive.name}\n"
    )


def main() -> None:
    """Revalidate actual installed files using existing production consumers, then export."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", required=True, type=pathlib.Path)
    parser.add_argument("--requested-head", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    args.runner_temp = args.runner_temp.resolve(strict=True)
    repo = pathlib.Path(__file__).resolve().parents[2]
    runtime = repo / "runtime"
    plugins = runtime / "build/rt19-plugin-sources"
    source = source_identity(repo)
    plugin_source = source_identity(plugins)
    if (plugin_source["commit"], plugin_source["tree"]) != (PL05_COMMIT, PL05_TREE):
        raise ValueError("PL05 source pin mismatch")
    provenance: dict[str, typing.Any] = {
        "runtime_source": source,
        "source_mapping": source_mapping(repo, source, args.requested_head),
        "pl05_source": plugin_source,
        "ci_run": {"run_id": args.run_id, "run_attempt": args.run_attempt},
        "toolchain": {
            name: run(command, runtime)
            for name, command in {
                "xcode": ["xcodebuild", "-version"],
                "sdk_version": ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"],
                "sdk_build": ["xcrun", "--sdk", "iphoneos", "--show-sdk-build-version"],
                "compiler": ["xcrun", "--sdk", "iphoneos", "clang++", "--version"],
                "cmake": ["cmake", "--version"],
            }.items()
        },
        "builds": {},
    }
    frameworks = {}
    validated = {}
    for label, stage, build, selection in (
        ("ordinary-release", "runtime-release", "ios", None),
        ("pl05-release", "ios-provenance-pl05", "ios-provenance-pl05", plugins),
    ):
        installed = args.runner_temp / stage / FRAMEWORK
        built = runtime / "build" / build / "ios/RaspRuntime.framework"
        before = read_framework(installed)
        built_files = read_framework(built)
        if any(data != built_files[name][0] for name, (data, _) in before.items()):
            raise ValueError(
                "installed framework differs from built pristine framework"
            )
        binary = installed / "RaspRuntime"
        configuration = build_configuration(runtime / "build" / build, selection)
        for tool in ("capabilities.py", "local_policy_support.py"):
            run(
                [
                    sys.executable,
                    str(runtime / "tools" / tool),
                    "verify",
                    str(binary),
                    "ios",
                    "arm64",
                    "12.0",
                ],
                runtime,
            )
        run(
            [
                sys.executable,
                str(runtime / "tools/verify_packaging.py"),
                str(binary),
                "ios",
                "arm64",
            ],
            runtime,
        )
        security = plugins / "scripts/publish_packer"
        run(
            [
                sys.executable,
                str(security / "security.py"),
                "verify",
                str(binary),
                "ios",
                "[]" if selection is None else SETTINGS,
            ],
            runtime,
        )
        marker = (
            None
            if selection is None
            else json.loads(
                run(
                    [
                        sys.executable,
                        "-c",
                        "import pathlib,security,sys; print(security.read_marker(pathlib.Path(sys.argv[1]).read_bytes()))",
                        str(binary),
                    ],
                    security,
                )
            )
        )
        if before != read_framework(installed):
            raise ValueError("installed framework changed during validation")
        frameworks[label] = installed
        validated[label] = before
        provenance["builds"][label] = {
            "cmake": configuration,
            "reporting_security_marker": marker,
            "validation": "production capability/policy/security validators and staged-byte config consumer; prior Apple workflow gates required",
        }
    export_bundle(
        args.runner_temp / "rt19-apple-artifacts", frameworks, provenance, validated
    )


if __name__ == "__main__":
    main()

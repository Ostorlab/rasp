"""Synthetic exporter boundary tests: these bytes are NOT Apple build evidence."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tarfile

import apple_artifacts
import pytest


@pytest.fixture
def frameworks(tmp_path: pathlib.Path) -> dict[str, pathlib.Path]:
    """Use explicit synthetic sidecars, without claiming a valid Mach-O or catalogue."""
    result = {}
    for label in ("ordinary-release", "pl05-release"):
        root = tmp_path / label / "RaspRuntime.framework"
        for name in apple_artifacts.FILE_LIMITS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic-export-test-only")
        binary = root / "RaspRuntime"
        binary.chmod(0o755)
        common = {
            "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "platform": "ios",
            "abi": "arm64",
            "minimum_os": "12.0",
            "catalogue_id": "synthetic-not-registered",
        }
        (root / "RaspRuntime.capabilities.json").write_text(
            json.dumps({**common, "catalogue": {"schema_version": 1, "revision": 10}})
        )
        (root / "RaspRuntime.local-policy.json").write_text(
            json.dumps({**common, "selector_table_sha256": "synthetic"})
        )
        result[label] = root
    return result


def testExport_whenInputsAreReadOnly_preservesBytesModesTimesAndVerifiableArchive(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    before = {}
    for root in frameworks.values():
        for path in root.rglob("*"):
            if path.is_file():
                path.chmod(0o555 if path.name == "RaspRuntime" else 0o444)
                before[path] = (
                    path.read_bytes(),
                    path.stat().st_mode,
                    path.stat().st_mtime_ns,
                )
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        root.chmod(0o555)
    output = tmp_path / "export"
    apple_artifacts.export_bundle(
        output, frameworks, {"classification": "synthetic-only"}
    )
    archive = output / "apple-release-frameworks.tar"
    assert (
        (output / "apple-release-frameworks.tar.sha256").read_text()
        == f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    )
    with tarfile.open(archive) as bundle:
        assert len(bundle.getmembers()) == 15
        assert all(member.isfile() for member in bundle)
        manifest_stream = bundle.extractfile("manifest.json")
        assert manifest_stream is not None
        manifest = json.load(manifest_stream)
        for framework in manifest["frameworks"].values():
            for name, record in framework["files"].items():
                member = bundle.getmember(name)
                stream = bundle.extractfile(member)
                assert stream is not None
                data = stream.read()
                assert apple_artifacts.digest(data) == {
                    key: record[key] for key in ("bytes", "sha256")
                }
                assert member.mode == record["mode"]
        assert manifest["classification"].endswith(
            "NOT installed IPA or device execution"
        )
    assert all(
        (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) == original
        for path, original in before.items()
    )


@pytest.mark.parametrize("name", list(apple_artifacts.FILE_LIMITS))
def testExport_whenRequiredFileMissing_failsWithoutOutput(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path, name: str
) -> None:
    (frameworks["ordinary-release"] / name).unlink()
    with pytest.raises(ValueError, match="missing framework files"):
        apple_artifacts.export_bundle(tmp_path / "export", frameworks, {})
    assert (tmp_path / "export").exists() is False


@pytest.mark.parametrize(
    "change",
    [
        "binary",
        "target",
        "catalogue",
        "size",
        "unexpected",
        "directory",
        "symlink",
        "fifo",
    ],
)
def testExport_whenInstallUnexpectedOrMismatched_refusesBundle(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path, change: str
) -> None:
    root = frameworks["pl05-release"]
    if change == "binary":
        (root / "RaspRuntime").write_bytes(b"changed")
    elif change in ("target", "catalogue"):
        path = root / "RaspRuntime.local-policy.json"
        document = json.loads(path.read_bytes())
        document["abi" if change == "target" else "catalogue_id"] = "wrong"
        path.write_text(json.dumps(document))
    elif change == "size":
        (root / "RaspRuntime.local-policy.json").write_bytes(b"x" * 4097)
    elif change == "unexpected":
        (root / ".secret").write_text("must not export")
    elif change == "directory":
        (root / "Versions").mkdir()
    elif change == "symlink":
        (root / "Info.plist").unlink()
        (root / "Info.plist").symlink_to(tmp_path / "outside")
    else:
        (root / "Info.plist").unlink()
        os.mkfifo(root / "Info.plist")
    with pytest.raises(ValueError, match=r"sidecar|framework"):
        apple_artifacts.export_bundle(tmp_path / "export", frameworks, {})
    assert (tmp_path / "export").exists() is False


def testExport_whenFrameworkRootOrParentIsSymlink_refusesEvenInTreeTarget(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    link = tmp_path / "link"
    link.symlink_to(frameworks["ordinary-release"].parent, target_is_directory=True)
    frameworks["ordinary-release"] = link / "RaspRuntime.framework"
    with pytest.raises(ValueError, match="symlink"):
        apple_artifacts.export_bundle(tmp_path / "export", frameworks, {})


def testExport_whenTraversalOrReusedOutput_refuses(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    with pytest.raises(ValueError, match="outside"):
        apple_artifacts.export_bundle(
            frameworks["ordinary-release"] / "export", frameworks, {}
        )
    with pytest.raises(ValueError, match="outside"):
        apple_artifacts.export_bundle(tmp_path / ".." / "escape", frameworks, {})
    with pytest.raises(ValueError, match="outside"):
        apple_artifacts.export_bundle(tmp_path, frameworks, {})
    frameworks["ordinary-release"] /= ".."
    with pytest.raises(ValueError, match="symlink"):
        apple_artifacts.export_bundle(tmp_path / "export", frameworks, {})


@pytest.fixture
def source_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "synthetic@example.invalid"],
        ["git", "config", "user.name", "Exporter test"],
    ):
        subprocess.run(command, cwd=repo, check=True)
    (repo / "source.txt").write_text("original\n")
    (repo / "link").symlink_to("source.txt")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "synthetic source"], cwd=repo, check=True)
    return repo


@pytest.mark.parametrize("change", ["bytes", "mode", "missing", "symlink"])
def testSource_whenTrackedWorktreeDiffers_rejectsFalseAssociation(
    source_repo: pathlib.Path, change: str
) -> None:
    path = source_repo / "source.txt"
    if change == "bytes":
        path.write_text("modified")
    elif change == "mode":
        path.chmod(0o755)
    elif change == "missing":
        path.unlink()
    else:
        (source_repo / "link").unlink()
        (source_repo / "link").symlink_to("elsewhere")
    with pytest.raises((ValueError, FileNotFoundError)):
        apple_artifacts.source_identity(source_repo)


def testMapping_whenMergeContainsHeadAndDifferentBase_recordsActualTreeDifference(
    source_repo: pathlib.Path,
) -> None:
    head = apple_artifacts.source_identity(source_repo)
    # A real synthetic Git merge object: deliberately different tree, honest parent association.
    (source_repo / "base-only.txt").write_text("different merged source")
    subprocess.run(["git", "add", "."], cwd=source_repo, check=True)
    tree = apple_artifacts.run(["git", "write-tree"], source_repo)
    base = apple_artifacts.run(
        ["git", "commit-tree", tree, "-p", head["commit"], "-m", "synthetic base"],
        source_repo,
    )
    merge = apple_artifacts.run(
        [
            "git",
            "commit-tree",
            tree,
            "-p",
            head["commit"],
            "-p",
            base,
            "-m",
            "synthetic CI merge",
        ],
        source_repo,
    )
    subprocess.run(["git", "update-ref", "HEAD", merge], cwd=source_repo, check=True)
    actual = apple_artifacts.source_identity(source_repo)
    assert len(actual["parents"]) == 2
    unrelated = apple_artifacts.run(
        ["git", "commit-tree", tree, "-m", "unrelated source"], source_repo
    )
    with pytest.raises(ValueError, match="neither checkout"):
        apple_artifacts.source_mapping(source_repo, actual, unrelated)
    mapping = apple_artifacts.source_mapping(source_repo, actual, head["commit"])
    assert mapping["trees_equal"] is False
    assert mapping["checkout_is_requested_head"] is False
    assert mapping["changed_paths_from_requested_head"] == ["base-only.txt"]
    assert (
        apple_artifacts.source_mapping(source_repo, actual, actual["commit"])[
            "trees_equal"
        ]
        is True
    )
    with pytest.raises(ValueError, match="invalid requested"):
        apple_artifacts.source_mapping(source_repo, actual, "HEAD; no shell")


def testBuild_whenCacheHasUnexpectedSelectionOrTarget_refusesAndExcludesSecrets(
    tmp_path: pathlib.Path,
) -> None:
    values = {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_SYSTEM_NAME": "iOS",
        "CMAKE_OSX_ARCHITECTURES": "arm64",
        "CMAKE_OSX_DEPLOYMENT_TARGET": "12.0",
        "RASP_OBFUSCATE_IOS": "ON",
        "RASP_LOGGING": "OFF",
        "RASP_PLUGINS": "",
        "CMAKE_OSX_SYSROOT": "/Xcode/SDKs/iPhoneOS27.sdk",
        "SECRET": "not retained",
    }
    cache = tmp_path / "CMakeCache.txt"
    cache.write_text(
        "\n".join(f"{key}:STRING={value}" for key, value in values.items())
    )
    assert "SECRET" not in apple_artifacts.build_configuration(tmp_path, None)
    values["CMAKE_OSX_DEPLOYMENT_TARGET"] = "13.0"
    cache.write_text(
        "\n".join(f"{key}:STRING={value}" for key, value in values.items())
    )
    with pytest.raises(ValueError, match="configuration"):
        apple_artifacts.build_configuration(tmp_path, None)


def testExport_whenInstallChangesAfterValidation_refusesUnvalidatedBytes(
    frameworks: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    validated = {
        label: apple_artifacts.read_framework(path)
        for label, path in frameworks.items()
    }
    (frameworks["pl05-release"] / "Info.plist").write_bytes(b"changed after validators")
    with pytest.raises(ValueError, match="after production validation"):
        apple_artifacts.export_bundle(tmp_path / "export", frameworks, {}, validated)
    assert (tmp_path / "export").exists() is False

"""Actual frozen-source integrity tests; no Apple build or native execution claim."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import tarfile
import typing

import pl05_snapshot
import pytest


@pytest.fixture
def snapshot(tmp_path: pathlib.Path) -> pathlib.Path:
    destination = tmp_path / "snapshot"
    shutil.copytree(pl05_snapshot.SNAPSHOT, destination)
    return destination


def replace_archive(
    snapshot: pathlib.Path, data: bytes, inventory: dict[str, typing.Any] | None = None
) -> None:
    """Update container SHA256 so refusal tests reach deeper Git/path boundaries."""
    document = (
        json.loads((snapshot / "inventory.json").read_bytes())
        if inventory is None
        else inventory
    )
    document["archive"] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    (snapshot / "inventory.json").write_text(json.dumps(document))
    (snapshot / "source.tar").write_bytes(data)


def altered_tar(change: str) -> bytes:
    """Deliberately encode malformed/noncanonical tar variants, not fake source pins."""
    output = io.BytesIO()
    with (
        tarfile.open(pl05_snapshot.SNAPSHOT / "source.tar") as source,
        tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as target,
    ):
        for index, member in enumerate(source):
            stream = source.extractfile(member)
            assert stream is not None
            with stream:
                data = stream.read()
            original = copy.copy(member)
            if index == 0:
                if change in (
                    "../escape",
                    "/absolute",
                    "a//b",
                    "a/./b",
                    "a/../b",
                    "a\\b",
                    ".git/config",
                    "unexpected",
                ):
                    member.name = change
                elif change in ("symlink", "hardlink", "directory", "fifo"):
                    member.type = {
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "directory": tarfile.DIRTYPE,
                        "fifo": tarfile.FIFOTYPE,
                    }[change]
                    member.linkname = (
                        "../../outside" if change in ("symlink", "hardlink") else ""
                    )
                    member.size = 0
                    data = b""
                elif change == "mode":
                    member.mode = 0o777
                elif change == "body":
                    data = bytes([data[0] ^ 1]) + data[1:]
                elif change == "owner":
                    member.uid = 501
                elif change == "time":
                    member.mtime = 123
            target.addfile(member, io.BytesIO(data))
            if index == 0 and change == "duplicate":
                original_stream = source.extractfile(original)
                assert original_stream is not None
                with original_stream:
                    target.addfile(original, io.BytesIO(original_stream.read()))
    return output.getvalue()


def testSnapshot_whenGenuineFrozenSource_matchesPinnedObjectsAndExtractsExactFiles(
    tmp_path: pathlib.Path,
) -> None:
    destination = tmp_path / "extracted"
    identity = pl05_snapshot.extract_source(destination)
    assert identity["kind"] == "frozen_verified_source"
    assert identity["commit"] == pl05_snapshot.COMMIT
    assert identity["tree"] == pl05_snapshot.TREE
    assert len(identity["tracked_files"]) == 215
    assert (destination / ".git").exists() is False
    assert pl05_snapshot.verified_source(destination) == identity
    for name, record in identity["tracked_files"].items():
        path = destination / name
        assert pl05_snapshot.git_hash("blob", path.read_bytes()) == record["git_blob"]
        assert path.stat().st_mode & 0o7777 == int(record["git_mode"], 8) & 0o777


@pytest.mark.parametrize(
    "change",
    [
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        ".git/config",
        "unexpected",
        "symlink",
        "hardlink",
        "directory",
        "fifo",
        "mode",
        "body",
        "owner",
        "time",
        "duplicate",
    ],
)
def testSnapshot_whenArchiveUnsafeOrMismatched_refusesBeforeCreatingDestination(
    snapshot: pathlib.Path, tmp_path: pathlib.Path, change: str
) -> None:
    replace_archive(snapshot, altered_tar(change))
    with pytest.raises(ValueError, match=r"archive|SHA256"):
        pl05_snapshot.extract_source(tmp_path / "output", snapshot)
    assert (tmp_path / "output").exists() is False
    assert (tmp_path / "escape").exists() is False


@pytest.mark.parametrize(
    "change", ["body-cut", "padding-cut", "append", "hash", "bounds", "gzip"]
)
def testSnapshot_whenContainerCorruptedOrUnbounded_failsWholeArchiveValidation(
    snapshot: pathlib.Path, tmp_path: pathlib.Path, change: str
) -> None:
    data = (snapshot / "source.tar").read_bytes()
    if change == "body-cut":
        data = data[:513]
    elif change == "padding-cut":
        data = data[:-1]
    elif change == "append":
        data += b"unreviewed bytes"
    elif change == "hash":
        (snapshot / "source.tar").write_bytes(data[:-1] + b"x")
    elif change == "bounds":
        data = b"x" * (pl05_snapshot.MAX_ARCHIVE + 1)
    else:
        data = b"\x1f\x8b\x08\x00" + data
    if change != "hash":
        replace_archive(snapshot, data)
    with pytest.raises(ValueError, match=r"archive|SHA256|bound"):
        pl05_snapshot.extract_source(tmp_path / "output", snapshot)
    assert (tmp_path / "output").exists() is False


@pytest.mark.parametrize(
    "change",
    [
        "commit-pin",
        "tree-pin",
        "commit-object",
        "commit-tree",
        "source-and-inventory",
        "mode-and-inventory",
        "blob",
        "size",
        "duplicate-json",
        "extra-field",
    ],
)
def testSnapshot_whenMetadataOrSourceRewritten_cannotForgePinnedIdentity(
    snapshot: pathlib.Path, tmp_path: pathlib.Path, change: str
) -> None:
    path = snapshot / "inventory.json"
    document = json.loads(path.read_bytes())
    if change in ("commit-pin", "tree-pin"):
        document["commit" if change == "commit-pin" else "tree"] = "0" * 40
    elif change in ("commit-object", "commit-tree"):
        commit_path = snapshot / "commit.raw"
        raw = commit_path.read_bytes()
        raw = (
            raw + b"changed"
            if change == "commit-object"
            else raw.replace(pl05_snapshot.TREE.encode(), b"0" * 40)
        )
        commit_path.write_bytes(raw)
        document["commit_object"] = {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    elif change in ("source-and-inventory", "mode-and-inventory"):
        _, files = pl05_snapshot.read_snapshot(snapshot)
        name = next(iter(files))
        data, mode = files[name]
        if change == "source-and-inventory":
            data += b"forged source"
        else:
            mode = 0o755 if mode == 0o644 else 0o644
        files[name] = (data, mode)
        document["files"][name] = {
            "git_mode": f"100{mode:o}",
            "git_blob": pl05_snapshot.git_hash("blob", data),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        replace_archive(snapshot, pl05_snapshot.archive_bytes(files), document)
        document = json.loads(path.read_bytes())
    elif change in ("blob", "size"):
        first = document["files"][next(iter(document["files"]))]
        first["git_blob" if change == "blob" else "bytes"] = (
            "0" * 40 if change == "blob" else pl05_snapshot.MAX_FILE + 1
        )
    elif change == "extra-field":
        document["unreviewed"] = "not accepted"
    path.write_text(json.dumps(document))
    if change == "duplicate-json":
        path.write_text(
            path.read_text().replace(
                '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
            )
        )
    with pytest.raises(ValueError, match=r"pin|tree|blob|inventory|duplicate"):
        pl05_snapshot.extract_source(tmp_path / "output", snapshot)
    assert (tmp_path / "output").exists() is False


@pytest.mark.parametrize(
    "change", ["body", "mode", "missing", "extra", "directory", "symlink", "root-link"]
)
def testExtractedSource_whenChangedOrUnexpected_exporterRefuses(
    snapshot: pathlib.Path, tmp_path: pathlib.Path, change: str
) -> None:
    destination = tmp_path / "output"
    pl05_snapshot.extract_source(destination, snapshot)
    path = destination / "README.md"
    if change == "body":
        path.write_bytes(path.read_bytes() + b"x")
    elif change == "mode":
        path.chmod(0o777)
    elif change == "missing":
        path.unlink()
    elif change == "extra":
        (destination / "unreviewed").write_text("x")
    elif change == "directory":
        (destination / "unreviewed").mkdir()
    elif change == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "outside")
    else:
        link = tmp_path / "link"
        link.symlink_to(destination, target_is_directory=True)
        destination = link
    with pytest.raises(ValueError, match=r"source|directory"):
        pl05_snapshot.verified_source(destination, snapshot)


def testExtract_whenDestinationExistsOrAliases_refusesOverwrite(
    tmp_path: pathlib.Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "sentinel"
    sentinel.write_bytes(b"preserve")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "absent", target_is_directory=True)
    for destination in (existing, link, existing / ".." / "escape"):
        with pytest.raises(ValueError, match="fresh"):
            pl05_snapshot.extract_source(destination)
    assert sentinel.read_bytes() == b"preserve"
    assert (tmp_path / "absent").exists() is False


def testGitTree_whenDirectoryPrefixOrderingAndExecutableMode_matchesRealGit(
    tmp_path: pathlib.Path,
) -> None:
    files = {
        "a.c": (b"source", 0o644),
        "a/z": (b"nested", 0o755),
        "a0": (b"last", 0o644),
        "a/nested/y": (b"deep", 0o644),
    }
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, (data, mode) in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    expected = (
        subprocess.check_output(["git", "write-tree"], cwd=tmp_path).decode().strip()
    )
    assert pl05_snapshot.tree_hash(files) == expected


def testSnapshot_whenCurrentPinAssigned_matchesReviewedFinalDependency() -> None:
    assert pl05_snapshot.COMMIT == "eb7e4306eeaf449031822910c73e1ecc9d0a34f2"
    assert pl05_snapshot.TREE == "8e91681d074a16e4e1c444f1e88e2d244db4474e"
    assert pl05_snapshot.FILE_COUNT == 215


def testSnapshot_whenPrevious1197PinRequested_refusesHistoricalFallback(
    snapshot: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    path = snapshot / "inventory.json"
    document = json.loads(path.read_bytes())
    document["commit"] = "1197b25162eadc202799abfe16008bef390e3482"
    document["tree"] = "b15595265d8d907439227848e064f8f66fc89844"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="pin"):
        pl05_snapshot.extract_source(tmp_path / "output", snapshot)
    assert (tmp_path / "output").exists() is False

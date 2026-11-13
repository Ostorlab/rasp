"""Verify the exact frozen PL05 Git tree before using or extracting its source.

No Git checkout, remote fetch, credential, history, build dependency download or
native execution is involved. The raw pinned commit authenticates the tree; Git
blob/tree encodings are reconstructed from all 215 regular source files.
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
import tarfile
import typing

COMMIT = "eb7e4306eeaf449031822910c73e1ecc9d0a34f2"
TREE = "8e91681d074a16e4e1c444f1e88e2d244db4474e"
FILE_COUNT = 215
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
SNAPSHOT = pathlib.Path(__file__).resolve().parents[1] / "tests/provenance/pl05"


def git_hash(kind: str, data: bytes) -> str:
    """Hash the exact Git object header plus payload (Git SHA1 identity)."""
    return hashlib.sha1(f"{kind} {len(data)}\0".encode("ascii") + data).hexdigest()


def tree_hash(files: dict[str, tuple[bytes, int]]) -> str:
    """Reconstruct Git tree objects with Git's directory-aware byte ordering."""
    entries = {}
    directories: dict[str, dict[str, tuple[bytes, int]]] = {}
    for path, (data, mode) in files.items():
        name, separator, rest = path.partition("/")
        if separator == "":
            entries[name] = (f"100{mode:o}", git_hash("blob", data))
        else:
            directories.setdefault(name, {})[rest] = (data, mode)
    if set(entries).intersection(directories) != set():
        raise ValueError("source file/directory collision")
    for name, children in directories.items():
        entries[name] = ("40000", tree_hash(children))
    payload = bytearray()
    for name in sorted(
        entries,
        key=lambda name: (
            name.encode("ascii") + (b"/" if entries[name][0] == "40000" else b"")
        ),
    ):
        git_mode, object_hash = entries[name]
        payload.extend(
            git_mode.encode("ascii")
            + b" "
            + name.encode("ascii")
            + b"\0"
            + bytes.fromhex(object_hash)
        )
    return git_hash("tree", bytes(payload))


def archive_bytes(files: dict[str, tuple[bytes, int]]) -> bytes:
    """Canonical USTAR: sorted regular files, exact modes, zero owner/time fields."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), mode
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def read_bounded(path: pathlib.Path, limit: int) -> bytes:
    """Read only finite regular inputs; reject aliases and special files."""
    if (
        any(part.is_symlink() for part in (path, *path.parents))
        or path.is_file() is False
    ):
        raise ValueError("snapshot input must be a regular non-symlink file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("snapshot input exceeds bound")
    return data


def json_object(pairs: list[tuple[str, typing.Any]]) -> dict[str, typing.Any]:
    """Refuse ambiguous inventory keys at every nesting level."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory key")
        result[key] = value
    return result


def verify_digest(data: bytes, record: typing.Any) -> None:
    """Verify explicit byte length and independent SHA256 integrity."""
    if (
        type(record) is not dict
        or set(record) != {"bytes", "sha256"}
        or type(record["bytes"]) is not int
        or record["bytes"] != len(data)
        or record["sha256"] != hashlib.sha256(data).hexdigest()
    ):
        raise ValueError("snapshot size/SHA256 mismatch")


def valid_path(name: str) -> bool:
    """Only canonical bounded relative paths from this source tree are supported."""
    return (
        len(name) <= 240
        and len(name.split("/")) <= 16
        and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name) is not None
        and all(part not in (".", "..", ".git") for part in name.split("/"))
    )


def read_snapshot(
    directory: pathlib.Path = SNAPSHOT,
) -> tuple[dict[str, typing.Any], dict[str, tuple[bytes, int]]]:
    """Validate the whole archive and pinned commit/tree before any extraction."""
    document = json.loads(
        read_bounded(directory / "inventory.json", 256 * 1024),
        object_pairs_hook=json_object,
    )
    if (
        type(document) is not dict
        or set(document)
        != {"schema_version", "commit", "tree", "commit_object", "archive", "files"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["commit"] != COMMIT
        or document["tree"] != TREE
        or type(document["files"]) is not dict
        or len(document["files"]) != FILE_COUNT
    ):
        raise ValueError("snapshot inventory/pin mismatch")
    commit = read_bounded(directory / "commit.raw", 4096)
    verify_digest(commit, document["commit_object"])
    if git_hash("commit", commit) != COMMIT or commit.splitlines()[
        0
    ] != f"tree {TREE}".encode("ascii"):
        raise ValueError("pinned Git commit/tree mismatch")
    archive = read_bounded(directory / "source.tar", MAX_ARCHIVE)
    verify_digest(archive, document["archive"])
    inventory = document["files"]
    for name, record in inventory.items():
        if (
            valid_path(name) is False
            or type(record) is not dict
            or set(record) != {"git_mode", "git_blob", "bytes", "sha256"}
            or record["git_mode"] not in ("100644", "100755")
            or type(record["bytes"]) is not int
            or not 0 <= record["bytes"] <= MAX_FILE
        ):
            raise ValueError("invalid source inventory path/mode/size")
    files: dict[str, tuple[bytes, int]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for member in bundle:
                name = member.name
                if (
                    len(files) >= FILE_COUNT
                    or valid_path(name) is False
                    or name not in inventory
                    or name in files
                    or member.type != tarfile.REGTYPE
                    or member.linkname != ""
                    or member.pax_headers != {}
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                ):
                    raise ValueError("unexpected archive path/type/duplicate/metadata")
                expected = inventory[name]
                mode = int(expected["git_mode"], 8) & 0o777
                if member.mode != mode or member.size != expected["bytes"]:
                    raise ValueError("archive mode/size mismatch")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError("missing archive file body")
                with stream:
                    data = stream.read(MAX_FILE + 1)
                verify_digest(data, {key: expected[key] for key in ("bytes", "sha256")})
                if git_hash("blob", data) != expected["git_blob"]:
                    raise ValueError("Git source blob mismatch")
                files[name] = (data, mode)
    except tarfile.TarError as error:
        raise ValueError("malformed/truncated source archive") from error
    if set(files) != set(inventory):
        raise ValueError("incomplete source archive")
    if tree_hash(files) != TREE:
        raise ValueError("pinned Git source tree mismatch")
    # Also rejects truncation at end markers, concatenation, hidden extension
    # headers, alternate encodings and ignored trailing garbage/extra archives.
    if archive != archive_bytes(files):
        raise ValueError("noncanonical/truncated source archive")
    identity = {
        "kind": "frozen_verified_source",
        "snapshot_directory": str(directory),
        "commit": COMMIT,
        "tree": TREE,
        "commit_object": document["commit_object"],
        "archive": document["archive"],
        "tracked_files": inventory,
        "verification": "exact Git commit/blob/tree encoding plus SHA256 inventory; no Git checkout",
    }
    return identity, files


def verify_directory(
    destination: pathlib.Path, files: dict[str, tuple[bytes, int]]
) -> None:
    """Refuse modified or extra extracted source, including empty directories/links."""
    if (
        ".." in destination.parts
        or any(path.is_symlink() for path in (destination, *destination.parents))
        or destination.is_dir() is False
    ):
        raise ValueError("invalid extracted source directory")
    allowed_directories = {
        str(parent)
        for name in files
        for parent in pathlib.PurePosixPath(name).parents
        if str(parent) != "."
    }
    seen = set()
    for directory, directories, names in os.walk(destination, followlinks=False):
        for name in directories + names:
            path = pathlib.Path(directory) / name
            relative = path.relative_to(destination).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                if relative not in allowed_directories:
                    raise ValueError("unexpected extracted directory")
                continue
            if stat.S_ISREG(mode) is False or relative not in files:
                raise ValueError("unexpected extracted source entry")
            data, expected_mode = files[relative]
            if (
                stat.S_IMODE(mode) != expected_mode
                or read_bounded(path, MAX_FILE) != data
            ):
                raise ValueError("changed extracted source bytes/mode")
            seen.add(relative)
    if seen != set(files):
        raise ValueError("missing extracted source")


def verified_source(
    destination: pathlib.Path, directory: pathlib.Path = SNAPSHOT
) -> dict[str, typing.Any]:
    """Exporter provenance for frozen verified source, never a fabricated checkout."""
    identity, files = read_snapshot(directory)
    verify_directory(destination, files)
    return identity


def extract_source(
    destination: pathlib.Path, directory: pathlib.Path = SNAPSHOT
) -> dict[str, typing.Any]:
    """Validate everything first, then exclusively create a fresh source-only tree."""
    identity, files = read_snapshot(directory)
    if (
        destination.is_absolute() is False
        or ".." in destination.parts
        or destination.exists()
        or any(path.is_symlink() for path in (destination, *destination.parents))
    ):
        raise ValueError("extraction requires a fresh non-symlink destination")
    destination.mkdir(parents=True, mode=0o755)
    for name, (data, mode) in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(mode)
    verify_directory(destination, files)
    return identity


def main() -> None:
    """The workflow may extract only to this known ignored runtime build path."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args()
    if args.extract is True:
        identity = extract_source(
            pathlib.Path(__file__).resolve().parents[1] / "build/rt19-plugin-sources"
        )
    else:
        identity, _ = read_snapshot()
    print(
        json.dumps(
            {key: value for key, value in identity.items() if key != "tracked_files"},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

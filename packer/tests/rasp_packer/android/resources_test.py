"""Tests of the runtime-artifact loader."""

import pathlib

import pytest

from rasp_packer import errors
from rasp_packer.android import resources


def _write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def testLoadFrom_whenArtifactsPresent_readsStubAndLibraries(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / "stub.dex", b"stub")
    _write(tmp_path / "lib" / "arm64-v8a" / "librasp.so", b"arm64")
    _write(tmp_path / "lib" / "x86_64" / "librasp.so", b"x86")
    artifacts = resources.load_from(tmp_path)
    assert artifacts.stub_dex == b"stub"
    assert dict(artifacts.libraries) == {"arm64-v8a": b"arm64", "x86_64": b"x86"}


def testLoadFrom_whenStubMissing_raisesMissingRuntimeArtifactError(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / "lib" / "arm64-v8a" / "librasp.so", b"arm64")
    with pytest.raises(errors.MissingRuntimeArtifactError):
        resources.load_from(tmp_path)


def testLoadFrom_whenLibrariesMissing_raisesMissingRuntimeArtifactError(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / "stub.dex", b"stub")
    with pytest.raises(errors.MissingRuntimeArtifactError):
        resources.load_from(tmp_path)


def testLoadFrom_whenAnAbiFolderHasNoLibrary_raisesMissingRuntimeArtifactError(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / "stub.dex", b"stub")
    _write(tmp_path / "lib" / "arm64-v8a" / "librasp.so", b"arm64")
    (tmp_path / "lib" / "x86_64").mkdir(parents=True)

    with pytest.raises(errors.MissingRuntimeArtifactError, match="x86_64"):
        resources.load_from(tmp_path)

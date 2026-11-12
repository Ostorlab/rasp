"""Tests of the runtime-artifact loader."""

import pathlib

import pytest

from rasp_packer import capabilities
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


def testBindings_whenMixedLegacyAndKnownArtifacts_returnsUnknown() -> None:
    artifacts = resources.Artifacts(
        stub_dex=b"stub",
        libraries={"arm64-v8a": b"arm", "x86": b"x86"},
        manifests={
            "arm64-v8a": capabilities.emit(b"arm", "android", "arm64-v8a", "31")
        },
    )
    assert resources.bindings(artifacts, ["arm64-v8a", "x86"]) is None


def testBindings_whenNoSelectedArtifacts_returnsUnknown() -> None:
    assert (
        resources.bindings(resources.Artifacts(stub_dex=b"", libraries={}), []) is None
    )


@pytest.mark.parametrize("stale_sidecar", [False, True])
def testLoadFrom_whenOtherAbiIsLegacyOrCorrupt_preservesDistributionValidation(
    tmp_path: pathlib.Path, stale_sidecar: bool
) -> None:
    _write(tmp_path / "stub.dex", b"stub")
    arm = tmp_path / "lib" / "arm64-v8a" / "librasp.so"
    x86 = tmp_path / "lib" / "x86" / "librasp.so"
    _write(arm, b"arm64")
    _write(x86, b"x86")
    arm_sidecar = capabilities.emit(b"arm64", "android", "arm64-v8a", "31")
    _write(arm.with_name("librasp.so.capabilities.json"), arm_sidecar)
    if stale_sidecar is True:
        _write(
            x86.with_name("librasp.so.capabilities.json"),
            capabilities.emit(b"stale x86 bytes", "android", "x86", "31"),
        )
        with pytest.raises(errors.InvalidRuntimeError):
            resources.load_from(tmp_path)
    else:
        artifacts = resources.load_from(tmp_path)
        assert resources.bindings(artifacts, ["arm64-v8a"]) == (
            capabilities.bind(b"arm64", arm_sidecar, "android", "arm64-v8a"),
        )
        assert resources.bindings(artifacts, ["arm64-v8a", "x86"]) is None

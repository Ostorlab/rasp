"""Tests of packing an IPA."""

import collections.abc
import pathlib
import stat
import zipfile

import lief
import pytest

from rasp_packer import capabilities
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import runtime_config
from rasp_packer.ios import macho
from rasp_packer.ios import packer
from rasp_packer.ios import runtime_binary
from tests.rasp_packer import conftest

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1", checks=("identity",))
_APP = "Payload/Demo.app"
_FRAMEWORK = f"{_APP}/Frameworks/RaspRuntime.framework"


def _pack(
    app: pathlib.Path, runtime: pathlib.Path, output: pathlib.Path
) -> zipfile.ZipFile:
    """Packs the app with the test config and opens the protected IPA."""
    packer.pack(app=app, output=output, runtime=runtime, config=_CONFIG)
    return zipfile.ZipFile(output)


def testPack_whenValidIpa_makesTheExecutableLoadTheRuntime(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        executable = tmp_path / "Demo"
        executable.write_bytes(archive.read(f"{_APP}/Demo"))
        mode = stat.S_IMODE(archive.getinfo(f"{_APP}/Demo").external_attr >> 16)

    fat = lief.MachO.parse(str(executable))
    assert fat is not None
    binary = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert binary is not None
    assert macho.RUNTIME_INSTALL_NAME in [library.name for library in binary.libraries]
    assert mode == 0o755


def testPack_whenValidIpa_embedsTheRuntimeWithTheConfig(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        binary = archive.read(f"{_FRAMEWORK}/RaspRuntime")
        names = archive.namelist()

    shipped = (runtime / "RaspRuntime").read_bytes()
    assert binary == runtime_binary.write_config(shipped, _CONFIG)
    assert runtime_binary.read_config(binary) == [_CONFIG.to_json()]
    assert f"{_FRAMEWORK}/config.json" not in names


def testPack_whenValidIpa_returnsTheAppIdentity(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    app_identity = packer.pack(
        app=ipa_file, output=tmp_path / "out.ipa", runtime=runtime, config=_CONFIG
    )

    assert app_identity == identity.AppIdentity(
        package_name=conftest.PACKAGE_NAME, version=conftest.VERSION
    )


def testPack_whenAppWasSigned_removesItsSignature(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        names = archive.namelist()

    assert all("_CodeSignature" not in name for name in names)


def testPack_whenAppEmbedsTheRuntimeAlready_raisesAlreadyProtectedError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    app = make_ipa(extra_entries={f"{_FRAMEWORK}/RaspRuntime": b""})

    with pytest.raises(errors.AlreadyProtectedError):
        packer.pack(
            app=app, output=tmp_path / "out.ipa", runtime=runtime, config=_CONFIG
        )


@pytest.mark.parametrize("missing", ["RaspRuntime", "Info.plist"])
def testPack_whenRuntimeIsIncomplete_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path, missing: str
) -> None:
    (runtime / missing).unlink()

    with pytest.raises(errors.InvalidRuntimeError, match=missing):
        packer.pack(
            app=ipa_file,
            output=tmp_path / "out.ipa",
            runtime=runtime,
            config=_CONFIG,
        )


def testPack_whenRuntimeIsNotTheFramework_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        packer.pack(
            app=ipa_file,
            output=tmp_path / "out.ipa",
            runtime=tmp_path,
            config=_CONFIG,
        )


def testPack_whenBoundRuntime_returnsActualBindingAndEffectiveGroups(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    binary = runtime / "RaspRuntime"
    sidecar = capabilities.emit(binary.read_bytes(), "ios", "arm64", "12.0")
    binary.with_name(binary.name + capabilities.SIDECAR_SUFFIX).write_bytes(sidecar)
    result = packer.pack(
        app=ipa_file, output=tmp_path / "bound.ipa", runtime=runtime, config=_CONFIG
    )
    assert result.bindings == (
        capabilities.bind(binary.read_bytes(), sidecar, "ios", "arm64"),
    )
    assert result.effective_checks == ("identity",)
    assert result.package_name == conftest.PACKAGE_NAME
    assert result.version == conftest.VERSION
    expected_identity = identity.AppIdentity(
        package_name=conftest.PACKAGE_NAME, version=conftest.VERSION
    )
    assert result == expected_identity
    assert hash(result) == hash(expected_identity)
    assert (
        binary.with_name(binary.name + capabilities.SIDECAR_SUFFIX).read_bytes()
        == sidecar
    )
    with zipfile.ZipFile(tmp_path / "bound.ipa") as archive:
        assert (
            f"{_FRAMEWORK}/RaspRuntime{capabilities.SIDECAR_SUFFIX}"
            not in archive.namelist()
        )


def testPack_whenBoundRuntimeChanged_rejectsBeforeWritingOutput(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    binary = runtime / "RaspRuntime"
    binary.with_name(binary.name + capabilities.SIDECAR_SUFFIX).write_bytes(
        capabilities.emit(binary.read_bytes(), "ios", "arm64", "12.0")
    )
    binary.write_bytes(binary.read_bytes() + b"changed")
    output = tmp_path / "bad.ipa"
    with pytest.raises(errors.InvalidRuntimeError, match="digest"):
        packer.pack(app=ipa_file, output=output, runtime=runtime, config=_CONFIG)
    assert output.exists() is False

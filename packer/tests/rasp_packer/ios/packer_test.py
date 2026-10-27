"""Tests of packing an IPA."""

import collections.abc
import pathlib
import plistlib
import stat
import zipfile

import lief
import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import plugin_configs
from rasp_packer.ios import macho
from rasp_packer.ios import packer
from tests.rasp_packer import conftest

_BUILD_ID = "build-1"
_APP = "Payload/Demo.app"
_FRAMEWORK = f"{_APP}/Frameworks/RaspRuntime.framework"


def _pack(
    app: pathlib.Path, runtime: pathlib.Path, output: pathlib.Path
) -> zipfile.ZipFile:
    """Packs the app with the test build id and opens the protected IPA."""
    packer.pack(app=app, output=output, runtime=runtime, build_id=_BUILD_ID)
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


def testPack_whenValidIpa_embedsTheRuntimeWithTheBuildId(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        binary = archive.read(f"{_FRAMEWORK}/RaspRuntime")
        info = plistlib.loads(archive.read(f"{_FRAMEWORK}/Info.plist"))

    assert binary == b"runtime binary"
    assert info[packer.RASP_BUILD_ID_KEY] == _BUILD_ID


def testPack_whenValidIpa_returnsTheAppIdentity(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    app_identity = packer.pack(
        app=ipa_file, output=tmp_path / "out.ipa", runtime=runtime, build_id=_BUILD_ID
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
            app=app, output=tmp_path / "out.ipa", runtime=runtime, build_id=_BUILD_ID
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
            build_id=_BUILD_ID,
        )


def testPack_whenRuntimeIsNotTheFramework_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        packer.pack(
            app=ipa_file,
            output=tmp_path / "out.ipa",
            runtime=tmp_path,
            build_id=_BUILD_ID,
        )


def testPack_whenPluginConfigsAreGiven_writesEachIntoTheRuntime(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    packer.pack(
        app=ipa_file,
        output=tmp_path / "out.ipa",
        runtime=runtime,
        build_id=_BUILD_ID,
        plugin_configs=[
            plugin_configs.PluginConfig(name="zeta", data=b"z=1"),
            plugin_configs.PluginConfig(name="alpha", data=b""),
        ],
    )

    with zipfile.ZipFile(tmp_path / "out.ipa") as archive:
        zeta = archive.read(f"{_FRAMEWORK}/plugin-config/zeta")
        alpha = archive.read(f"{_FRAMEWORK}/plugin-config/alpha")

    assert zeta == b"z=1"
    assert alpha == b""


def testPack_whenNoPluginConfigIsGiven_writesNone(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        names = archive.namelist()

    assert all("plugin-config" not in name for name in names)

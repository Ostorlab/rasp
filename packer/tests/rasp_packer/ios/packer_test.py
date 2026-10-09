"""Tests of packing an IPA."""

import collections.abc
import pathlib
import plistlib
import stat
import uuid
import zipfile

import lief
import pytest

from rasp_packer import build
from rasp_packer import errors
from rasp_packer.ios import macho
from rasp_packer.ios import packer

_BUILD = build.Build(
    rasp_app_id=uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90"), build_id="build-1"
)
_APP = "Payload/Demo.app"
_FRAMEWORK = f"{_APP}/Frameworks/RaspRuntime.framework"


def _pack(
    app: pathlib.Path, runtime: pathlib.Path, output: pathlib.Path
) -> zipfile.ZipFile:
    packer.pack(app=app, output=output, runtime=runtime, build=_BUILD)
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


def testPack_whenValidIpa_embedsTheRuntimeWithTheBuildIdentity(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        binary = archive.read(f"{_FRAMEWORK}/RaspRuntime")
        info = plistlib.loads(archive.read(f"{_FRAMEWORK}/Info.plist"))

    assert binary == b"runtime binary"
    assert info[packer.RASP_APP_ID_KEY] == str(_BUILD.rasp_app_id)
    assert info[packer.RASP_BUILD_ID_KEY] == _BUILD.build_id


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
        packer.pack(app=app, output=tmp_path / "out.ipa", runtime=runtime, build=_BUILD)


@pytest.mark.parametrize("missing", ["RaspRuntime", "Info.plist"])
def testPack_whenRuntimeIsIncomplete_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path, missing: str
) -> None:
    (runtime / missing).unlink()

    with pytest.raises(errors.InvalidRuntimeError, match=missing):
        packer.pack(
            app=ipa_file, output=tmp_path / "out.ipa", runtime=runtime, build=_BUILD
        )


def testPack_whenRuntimeIsNotTheFramework_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        packer.pack(
            app=ipa_file, output=tmp_path / "out.ipa", runtime=tmp_path, build=_BUILD
        )

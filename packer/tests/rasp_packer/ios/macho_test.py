"""Tests of adding the runtime to a Mach-O executable."""

import pathlib

import lief
import pytest

from rasp_packer import errors
from rasp_packer.ios import macho


def _arm64_slice(path: pathlib.Path) -> lief.MachO.Binary:
    fat = lief.MachO.parse(str(path))
    assert fat is not None
    binary = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert binary is not None
    return binary


def testAddRuntime_whenArm64Executable_loadsTheRuntime(
    executable: pathlib.Path,
) -> None:
    macho.add_runtime(executable)

    binary = _arm64_slice(executable)
    assert macho.RUNTIME_INSTALL_NAME in [library.name for library in binary.libraries]


def testAddRuntime_whenNoFrameworksRpath_addsIt(executable: pathlib.Path) -> None:
    macho.add_runtime(executable)

    binary = _arm64_slice(executable)
    assert [rpath.path for rpath in binary.rpaths] == [macho.FRAMEWORKS_RPATH]


def testAddRuntime_whenFrameworksRpathPresent_keepsASingleOne(
    executable: pathlib.Path,
) -> None:
    binary = _arm64_slice(executable)
    rpath = lief.MachO.RPathCommand.create(macho.FRAMEWORKS_RPATH)
    assert rpath is not None
    binary.add(rpath)
    binary.write(str(executable))

    macho.add_runtime(executable)

    patched = _arm64_slice(executable)
    assert [rpath.path for rpath in patched.rpaths] == [macho.FRAMEWORKS_RPATH]


def testAddRuntime_whenSigned_removesTheSignature(
    signed_executable: pathlib.Path,
) -> None:
    macho.add_runtime(signed_executable)

    binary = _arm64_slice(signed_executable)
    assert binary.has_code_signature is False


def testAddRuntime_whenAlreadyLoadsTheRuntime_raisesAlreadyProtectedError(
    executable: pathlib.Path,
) -> None:
    macho.add_runtime(executable)

    with pytest.raises(errors.AlreadyProtectedError):
        macho.add_runtime(executable)


def testAddRuntime_whenEncrypted_raisesUnsupportedBinaryError(
    executable: pathlib.Path,
) -> None:
    binary = _arm64_slice(executable)
    encryption = binary.encryption_info
    assert encryption is not None
    encryption.crypt_id = 1
    binary.write(str(executable))

    with pytest.raises(errors.UnsupportedBinaryError, match="encrypted"):
        macho.add_runtime(executable)


def testAddRuntime_whenNoArm64Slice_raisesUnsupportedBinaryError(
    executable: pathlib.Path,
) -> None:
    binary = _arm64_slice(executable)
    binary.header.cpu_type = lief.MachO.Header.CPU_TYPE.X86_64
    binary.write(str(executable))

    with pytest.raises(errors.UnsupportedBinaryError, match="no arm64 slice"):
        macho.add_runtime(executable)


def testAddRuntime_whenNotAMachO_raisesUnsupportedBinaryError(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "Demo"
    path.write_bytes(b"not a mach-o")

    with pytest.raises(errors.UnsupportedBinaryError, match="not a Mach-O"):
        macho.add_runtime(path)


def testAddRuntime_whenNoRoomForTheLoadCommands_raisesAndLeavesTheFileUnchanged(
    executable: pathlib.Path,
) -> None:
    binary = _arm64_slice(executable)
    filler = lief.MachO.RPathCommand.create(
        "@loader_path/" + "x" * (binary.available_command_space - 64)
    )
    assert filler is not None
    binary.add(filler)
    binary.write(str(executable))
    before = executable.read_bytes()

    with pytest.raises(errors.HeaderPaddingError):
        macho.add_runtime(executable)

    assert executable.read_bytes() == before

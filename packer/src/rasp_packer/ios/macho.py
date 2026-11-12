"""Adding the runtime to the app's Mach-O executable.

The packer adds an `LC_LOAD_DYLIB` load command for the runtime framework to every arm64 slice of
the main executable, and an `LC_RPATH` of `@executable_path/Frameworks` when the slice has none, so
dyld loads the framework when the app starts. The change makes the code signature invalid, so the
signature is removed: the customer signs the app again.

The new load commands must fit in the free space between the existing load commands and the first
section. If they do not, LIEF would move the file content, which breaks arm64 references, so the
packer refuses instead.
"""

import pathlib

import lief

from rasp_packer import errors

RUNTIME_FRAMEWORK = "RaspRuntime.framework"
RUNTIME_BINARY = "RaspRuntime"
RUNTIME_ABI = "arm64"
"""Expected runtime ABI: add_runtime instruments only ARM64 slices, independently of sidecar claims."""
RUNTIME_INSTALL_NAME = f"@rpath/{RUNTIME_FRAMEWORK}/{RUNTIME_BINARY}"
FRAMEWORKS_RPATH = "@executable_path/Frameworks"


def add_runtime(executable: pathlib.Path) -> None:
    """Makes the executable load the runtime, and removes its code signature.

    The file is rewritten in place only when every slice is arm64 and can take the change.

    Args:
        executable: The app's main executable.

    Raises:
        UnsupportedBinaryError: The file is not a Mach-O, has a non-arm64 slice, or has an encrypted
            slice.
        AlreadyProtectedError: The executable already loads the runtime.
        HeaderPaddingError: The new load commands do not fit in a slice.
    """
    fat = lief.MachO.parse(str(executable))
    if fat is None or fat.size == 0:
        raise errors.UnsupportedBinaryError(
            f"{executable.name} is not a Mach-O executable"
        )
    slices = [
        binary
        for binary in fat
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64
    ]
    if len(slices) == 0:
        raise errors.UnsupportedBinaryError(f"{executable.name} has no arm64 slice")
    if len(slices) != fat.size:
        raise errors.UnsupportedBinaryError(
            f"{executable.name} has an unsupported Mach-O architecture: only arm64 slices are supported"
        )
    for binary in slices:
        _check(binary)
    for binary in fat:
        if binary.has_code_signature is True:
            binary.remove_signature()
    for binary in slices:
        _add_load_commands(binary)
    fat.write(str(executable))


def _check(binary: lief.MachO.Binary) -> None:
    encryption = binary.encryption_info
    if encryption is not None and encryption.crypt_id != 0:
        raise errors.UnsupportedBinaryError(
            "the executable is encrypted: an App Store build cannot be packed"
        )
    if any(library.name == RUNTIME_INSTALL_NAME for library in binary.libraries):
        raise errors.AlreadyProtectedError("the executable already loads the runtime")


def _add_load_commands(binary: lief.MachO.Binary) -> None:
    commands: list[lief.MachO.LoadCommand] = [
        lief.MachO.DylibCommand.load_dylib(RUNTIME_INSTALL_NAME)
    ]
    if all(rpath.path != FRAMEWORKS_RPATH for rpath in binary.rpaths):
        rpath = lief.MachO.RPathCommand.create(FRAMEWORKS_RPATH)
        if rpath is None:
            raise errors.UnsupportedBinaryError(
                f"LIEF could not create the {FRAMEWORKS_RPATH} rpath"
            )
        commands.append(rpath)
    needed = sum(command.size for command in commands)
    if needed > binary.available_command_space:
        raise errors.HeaderPaddingError(
            f"the load commands need {needed} bytes and the executable has {binary.available_command_space} free"
        )
    for command in commands:
        binary.add(command)

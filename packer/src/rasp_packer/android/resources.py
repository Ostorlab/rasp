"""Locates the prebuilt artifacts the Android packer injects into an app.

Two artifacts come from the runtime build, not from the packer:

- the stub dex: the small, generic component factory the manifest points to. It
  declares the class named by STUB_FACTORY_CLASS.
- the native runtime library, one per ABI. The stub loads it with
  System.loadLibrary, so each file is named RUNTIME_LIBRARY.

They live under this package's resources directory: the stub dex at
``resources/stub.dex`` and each library at ``resources/lib/<abi>/librasp.so``.
The release workflow copies them there from the runtime build. A checkout
without them, such as ``main``, has none, so load raises
MissingRuntimeArtifactError naming the path it looked in.
"""

import collections.abc
import contextlib
import dataclasses
import importlib.resources
import os
import pathlib

from rasp_packer import errors

STUB_FACTORY_CLASS = "co.ostorlab.rasp.RaspStub"
RUNTIME_LIBRARY = "librasp.so"

_STUB_DEX = "stub.dex"
_LIBRARY_DIRECTORY = "lib"
_SPLIT_DEX_TOOL = "split-dex"


@contextlib.contextmanager
def split_dex_tool() -> collections.abc.Iterator[pathlib.Path]:
    """Yields the path of the on-demand packer's bundled split-dex tool.

    The prebuilt tool ships inside the packer, next to the stub dex and the runtime libraries, the
    same way: the release build places it at ``resources/split-dex``, and a checkout without it, such
    as ``main``, has none. The path is valid only inside the ``with`` block.

    Yields:
        The path of the split-dex executable.

    Raises:
        MissingPackerToolError: The tool is not bundled in this build.
    """
    resource = (
        importlib.resources.files("rasp_packer.android") / "resources" / _SPLIT_DEX_TOOL
    )
    with importlib.resources.as_file(resource) as path:
        if path.is_file() is False:
            raise errors.MissingPackerToolError(f"split-dex tool not found at {path}")
        if os.access(path, os.X_OK) is False:
            path.chmod(0o755)
        yield path


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Artifacts:
    """The prebuilt files the packer adds to an app.

    Attributes:
        stub_dex: The stub loader dex, used as the app's classes.dex.
        libraries: The native runtime library bytes, keyed by ABI.
    """

    stub_dex: bytes
    libraries: collections.abc.Mapping[str, bytes]


def load() -> Artifacts:
    """Loads the prebuilt artifacts from the package resources.

    Returns:
        The stub dex and the native libraries.

    Raises:
        MissingRuntimeArtifactError: The stub dex or the libraries are absent.
    """
    package = importlib.resources.files("rasp_packer.android")
    with importlib.resources.as_file(package) as base:
        return load_from(base / "resources")


def load_from(root: pathlib.Path) -> Artifacts:
    """Loads the prebuilt artifacts from a resources directory.

    The ABIs are not a fixed list: each folder under ``lib/`` is one ABI, and
    must hold the runtime library.

    Args:
        root: The resources directory, holding ``stub.dex`` and ``lib/<abi>/librasp.so``.

    Returns:
        The stub dex and the native libraries.

    Raises:
        MissingRuntimeArtifactError: The stub dex is absent, there is no ABI,
            or an ABI folder has no runtime library.
    """
    stub = root / _STUB_DEX
    if stub.is_file() is False:
        raise errors.MissingRuntimeArtifactError(f"stub dex not found at {stub}")
    library_root = root / _LIBRARY_DIRECTORY
    abis: list[pathlib.Path] = []
    if library_root.is_dir() is True:
        abis = sorted(path for path in library_root.iterdir() if path.is_dir() is True)
    if len(abis) == 0:
        raise errors.MissingRuntimeArtifactError(
            f"no {RUNTIME_LIBRARY} found under {library_root}"
        )
    libraries: dict[str, bytes] = {}
    for abi in abis:
        library = abi / RUNTIME_LIBRARY
        if library.is_file() is False:
            raise errors.MissingRuntimeArtifactError(f"{library} not found")
        libraries[abi.name] = library.read_bytes()
    return Artifacts(stub_dex=stub.read_bytes(), libraries=libraries)

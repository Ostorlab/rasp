"""Locates the prebuilt artifacts the Android packer injects into an app.

Two artifacts come from the runtime build, not from the packer:

- the stub dex: the small, generic loader the manifest points to. It declares
  the class named by STUB_APPLICATION_CLASS.
- the native runtime library, one per ABI. The stub loads it with
  System.loadLibrary, so each file is named RUNTIME_LIBRARY.

They live under this package's resources directory: the stub dex at
``resources/stub.dex`` and each library at ``resources/lib/<abi>/librasp.so``.
The runtime build writes them there. Until it does, load raises
MissingRuntimeArtifactError naming the path it looked in.
"""

import collections.abc
import dataclasses
import importlib.resources
import pathlib

from rasp_packer import errors

STUB_APPLICATION_CLASS = "co.ostorlab.rasp.RaspStub"
RUNTIME_LIBRARY = "librasp.so"

_STUB_DEX = "stub.dex"
_LIBRARY_DIRECTORY = "lib"


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
        return _load_from(base / "resources")


def _load_from(root: pathlib.Path) -> Artifacts:
    """Loads the prebuilt artifacts from the resources directory `root`."""
    stub = root / _STUB_DEX
    if not stub.is_file():
        raise errors.MissingRuntimeArtifactError(
            f"stub dex not found at {stub}; build the runtime stub first"
        )
    libraries: dict[str, bytes] = {}
    library_root = root / _LIBRARY_DIRECTORY
    if library_root.is_dir():
        for abi in sorted(library_root.iterdir()):
            library = abi / RUNTIME_LIBRARY
            if library.is_file():
                libraries[abi.name] = library.read_bytes()
    if len(libraries) == 0:
        raise errors.MissingRuntimeArtifactError(
            f"no {RUNTIME_LIBRARY} found under {library_root}; build the runtime first"
        )
    return Artifacts(stub_dex=stub.read_bytes(), libraries=libraries)

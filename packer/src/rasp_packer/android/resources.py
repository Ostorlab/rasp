"""Locates the prebuilt artifacts the Android packer injects into an app.

Two artifacts come from the runtime build, not from the packer:

- the stub dex: the small, generic component factory the manifest points to. It
  declares the class named by STUB_FACTORY_CLASS.
- the native runtime library, one per ABI. The stub loads it with
  System.loadLibrary, so each file is named RUNTIME_LIBRARY.

The packer looks for them under this package's resources directory: the stub dex
at ``resources/stub.dex`` and each library at ``resources/lib/<abi>/librasp.so``.
When they are absent, load raises MissingRuntimeArtifactError naming the path it
looked in.
"""

import collections.abc
import dataclasses
import importlib.resources
import json
import pathlib

from rasp_packer import capabilities
from rasp_packer import errors
from rasp_packer import local_policy
from rasp_packer.android import runtime_library

STUB_FACTORY_CLASS = "co.ostorlab.rasp.RaspStub"
RUNTIME_LIBRARY = "librasp.so"

ROOT_MANAGER_PACKAGES_V1: tuple[str, ...] = tuple(
    entry["name"]
    for entry in json.loads(
        (
            importlib.resources.files("rasp_packer.android")
            / "root_manager_packages_v1.json"
        ).read_text()
    )["packages"]
)
"""Fixed selected identifiers shared with native generation; not an app inventory."""

_STUB_DEX = "stub.dex"
_LIBRARY_DIRECTORY = "lib"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Artifacts:
    """The prebuilt files the packer adds to an app.

    Attributes:
        stub_dex: The stub loader dex, used as the app's classes.dex.
        libraries: The native runtime library bytes, keyed by ABI.
        manifests: Optional pristine build sidecars, keyed by ABI; missing entries are legacy/unknown.
    """

    stub_dex: bytes
    libraries: collections.abc.Mapping[str, bytes]
    manifests: collections.abc.Mapping[str, bytes] = dataclasses.field(
        default_factory=dict
    )
    policy_manifests: collections.abc.Mapping[str, bytes] = dataclasses.field(
        default_factory=dict
    )


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
    manifests: dict[str, bytes] = {}
    policy_manifests: dict[str, bytes] = {}
    for abi in abis:
        library = abi / RUNTIME_LIBRARY
        if library.is_file() is False:
            raise errors.MissingRuntimeArtifactError(f"{library} not found")
        libraries[abi.name] = library.read_bytes()
        sidecar = capabilities.read_sidecar(library)
        if sidecar is not None:
            manifests[abi.name] = sidecar
            capabilities.bind(libraries[abi.name], sidecar, "android", abi.name)
        policy_sidecar = local_policy.read_support(library)
        if policy_sidecar is not None:
            local_policy.bind(
                libraries[abi.name], policy_sidecar, "android", abi.name, required=False
            )
            policy_manifests[abi.name] = policy_sidecar
    return Artifacts(
        stub_dex=stub.read_bytes(),
        libraries=libraries,
        manifests=manifests,
        policy_manifests=policy_manifests,
    )


def bindings(
    artifacts: Artifacts, abis: collections.abc.Iterable[str]
) -> tuple[capabilities.Binding, ...] | None:
    """Validate exact selected bytes; a mixed known/legacy set has unknown capabilities."""
    result: list[capabilities.Binding] = []
    unknown = False
    for abi in sorted(abis):
        binding = capabilities.bind(
            artifacts.libraries[abi], artifacts.manifests.get(abi), "android", abi
        )
        if binding is None:
            unknown = True
        else:
            result.append(binding)
    return None if unknown is True or len(result) == 0 else tuple(result)


def policy_bindings(
    artifacts: Artifacts, abis: collections.abc.Iterable[str], *, required: bool
) -> tuple[local_policy.Binding, ...] | None:
    """Bind exact injected ABIs before config insertion; explicit policy cannot use old artifacts."""
    result: list[local_policy.Binding] = []
    unknown = False
    for abi in sorted(abis):
        capability = capabilities.bind(
            artifacts.libraries[abi], artifacts.manifests.get(abi), "android", abi
        )
        binding = local_policy.bind(
            artifacts.libraries[abi],
            artifacts.policy_manifests.get(abi),
            "android",
            abi,
            required=required,
        )
        if required is True and capability is None:
            raise errors.InvalidRuntimeError(
                "local policy requires matching native capability binding"
            )
        if binding is None:
            unknown = True
        else:
            runtime_library.verify_policy_exports(artifacts.libraries[abi])
            result.append(binding)
    return None if unknown is True or len(result) == 0 else tuple(result)

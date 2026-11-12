"""Packing of Android apps: adds the runtime to a built APK or AAB, for on-demand loading.

The packer keeps the app's framework and library dexes in the clear and encrypts only the app's own
("business") dexes, each on its own, so the runtime decrypts one business dex the first time a class
in it is needed. A screen the user never opens is never decrypted, and a decrypted dex is held no
longer than it is used.

It produces the entries the runtime reads from the app's own APK (names and rules taken from the
runtime's ``payload/dex_store.*``, ``payload/assets.h`` and ``loader/loader_dex.*``):

- ``assets/rasp/key.bin`` — the raw 32-byte key, stored. It decrypts the map and every business dex.
- ``assets/rasp/map.bin`` — the class map (see loader_map), encrypted under the key, stored.
- ``assets/business/<i>.dex`` — one encrypted business dex per file, stored.
- the framework dexes and the stub, in the clear, as ``classes.dex`` … ``classesN.dex``.
- ``lib/<abi>/librasp.so`` — the runtime library, one per ABI, with the runtime's config written into
  its ``.rasp_config`` section (see runtime_library). The loader's own dex is already embedded in it at
  the runtime's build.

For AAB files, all paths live under ``base/`` (e.g. ``base/assets/rasp/key.bin``,
``base/dex/classes.dex``, ``base/lib/<abi>/librasp.so``).  The manifest is in protobuf format
instead of binary AXML, and no zipalign or v1 signature stripping is needed.

It sets the manifest's appComponentFactory to the stub, raises minSdk to the runtime's floor (API 31,
which the in-memory loader and ``JNI_GetCreatedJavaVMs`` need), drops the app's original dexes and v1
signatures (APK only), and returns the protected app unsigned, so the customer signs it. The stub and
the native runtime are prebuilt artifacts from the runtime build; see resources.
"""

import collections.abc
import dataclasses
import pathlib
import zipfile

from rasp_packer import archive_validation
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer import verification
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import loader_map
from rasp_packer.android import resources as resources_module
from rasp_packer.android import runtime_library
from rasp_packer.android import split as split_module
from rasp_packer.android.aab import archive as aab_archive
from rasp_packer.android.aab import manifest as aab_manifest_module
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import manifest as apk_manifest_module

PRIMARY_DEX = "classes.dex"
MINIMUM_API_LEVEL = 31

ASSET_DIRECTORY = "assets/rasp"
KEY_ENTRY = f"{ASSET_DIRECTORY}/key.bin"
MAP_ENTRY = f"{ASSET_DIRECTORY}/map.bin"
ASSET_PREFIX = "assets/"

_AAB_BASE = "base/"
_AAB_DEX_PREFIX = "base/dex/"
AAB_KEY_ENTRY = f"{_AAB_BASE}{KEY_ENTRY}"
AAB_MAP_ENTRY = f"{_AAB_BASE}{MAP_ENTRY}"
AAB_ASSET_PREFIX = f"{_AAB_BASE}{ASSET_PREFIX}"

type Splitter = collections.abc.Callable[[pathlib.Path, str], split_module.Split]
type AabSplitter = collections.abc.Callable[[dict[str, bytes], str], split_module.Split]


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts | None = None,
    splitter: Splitter = split_module.split,
    aab_splitter: AabSplitter = split_module.split_from_dex_entries,
) -> identity.AppIdentity:
    """Packs an Android app (APK or AAB), writing the protected output.

    Args:
        app: The built APK or AAB to protect.
        output: Where to write the protected app. It is unsigned.
        config: The runtime's config, written into the app.
        artifacts: The prebuilt stub and libraries. Loaded from the package resources when not given.
        splitter: Splits an APK's classes. The default runs the bundled splitter.
        aab_splitter: Splits an AAB's classes from pre-extracted DEX entries.

    Returns:
        The app's identity with additive effective_checks/bindings metadata; identity equality is preserved.

    Raises:
        InvalidApkError: The APK is invalid or missing required entries.
        InvalidAabError: The AAB is invalid or missing required entries.
        ManifestError: The app's manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
        InvalidRuntimeError: A runtime library is not an ELF file or has no ``.rasp_config`` section.
        ConfigTooLargeError: The runtime's config does not fit in a runtime library.
        UnsupportedAbiError: The app ships native libraries for an ABI the runtime is not built for.
        AlreadyProtectedError: The app already holds the map, or its manifest already names the stub.
        SplitError: The app's classes cannot be read or split.
    """
    if artifacts is None:
        artifacts = resources_module.load()
    with verification.staged_output(output) as staged:
        if _is_aab(app):
            app_identity = _pack_aab(
                app=app,
                output=staged,
                config=config,
                artifacts=artifacts,
                splitter=aab_splitter,
            )
        else:
            app_identity = _pack_apk(
                app=app,
                output=staged,
                config=config,
                artifacts=artifacts,
                splitter=splitter,
            )
    return app_identity


def _is_aab(app: pathlib.Path) -> bool:
    """An AAB contains ``BundleConfig.pb``; an APK does not."""
    try:
        archive_validation.check_file(app)
        with zipfile.ZipFile(app) as zf:
            return "BundleConfig.pb" in zf.namelist()
    except errors.InvalidAppError, zipfile.BadZipFile, OSError:
        return False


def _pack_apk(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts,
    splitter: Splitter,
) -> identity.AppIdentity:
    """Packs an APK."""
    apk = apk_archive.Apk.read(app)
    dex_names = apk.dex_names()
    if PRIMARY_DEX not in dex_names:
        raise errors.InvalidApkError(f"APK has no {PRIMARY_DEX} to protect")
    manifest = apk.manifest()
    app_identity = apk_manifest_module.app_identity(manifest)
    if (
        MAP_ENTRY in apk.names()
        or apk_manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")

    result = splitter(app, app_identity.package_name)

    patched_manifest = apk_manifest_module.set_app_component_factory(
        apk_manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL),
        resources_module.STUB_FACTORY_CLASS,
    )
    key = cipher.new_key()
    map_frame = cipher.encrypt(key, loader_map.build(result.business).encode("utf-8"))
    business_entries = {
        ASSET_PREFIX + dex.path: cipher.encrypt(key, dex.data)
        for dex in result.business
    }
    base_dexes = injection.base_dex_entries(result.framework, artifacts.stub_dex)
    libraries = injection.library_entries(apk, artifacts)
    bindings = resources_module.bindings(
        artifacts, (name.split("/")[1] for name in libraries)
    )
    added = {
        KEY_ENTRY: key,
        MAP_ENTRY: map_frame,
        **business_entries,
        **base_dexes,
        **{
            name: runtime_library.write_config(library, config)
            for name, library in libraries.items()
        },
    }
    apk.write(
        output,
        replace={apk_archive.MANIFEST_ENTRY: patched_manifest},
        add=added,
        remove=set(dex_names) | injection.stale_signature_entries(apk),
    )
    verification.verify(
        app=output,
        platform=platforms.Platform.ANDROID,
        config=config,
        expected_entries={apk_archive.MANIFEST_ENTRY: patched_manifest, **added},
    )
    return dataclasses.replace(
        app_identity, effective_checks=config.checks, bindings=bindings
    )


def _pack_aab(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts,
    splitter: AabSplitter,
) -> identity.AppIdentity:
    """Packs an AAB."""
    aab = aab_archive.Aab.read(app)
    dex_names = aab.dex_names()
    aab_primary_dex = f"{_AAB_DEX_PREFIX}{PRIMARY_DEX}"
    if aab_primary_dex not in dex_names:
        raise errors.InvalidAabError(f"AAB has no {aab_primary_dex} to protect")
    manifest = aab.manifest()
    app_identity = aab_manifest_module.app_identity(manifest)
    if (
        AAB_MAP_ENTRY in aab.names()
        or aab_manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")

    dex_entries: dict[str, bytes] = {}
    for name in dex_names:
        data = aab.get(name)
        if data is not None:
            dex_entries[name.removeprefix(_AAB_DEX_PREFIX)] = data
    result = splitter(dex_entries, app_identity.package_name)

    patched_manifest = aab_manifest_module.set_app_component_factory(
        aab_manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL),
        resources_module.STUB_FACTORY_CLASS,
    )
    key = cipher.new_key()
    map_frame = cipher.encrypt(key, loader_map.build(result.business).encode("utf-8"))
    business_entries = {
        AAB_ASSET_PREFIX + dex.path: cipher.encrypt(key, dex.data)
        for dex in result.business
    }
    base_dexes = {
        f"{_AAB_DEX_PREFIX}{name}": data
        for name, data in injection.base_dex_entries(
            result.framework, artifacts.stub_dex
        ).items()
    }
    abis = injection.resolve_abis(_aab_native_abis(aab), artifacts)
    bindings = resources_module.bindings(artifacts, abis)
    lib_entries = {
        f"base/lib/{abi}/{resources_module.RUNTIME_LIBRARY}": runtime_library.write_config(
            artifacts.libraries[abi], config
        )
        for abi in sorted(abis)
    }
    added = {
        AAB_KEY_ENTRY: key,
        AAB_MAP_ENTRY: map_frame,
        **business_entries,
        **base_dexes,
        **lib_entries,
    }
    aab.write(
        output,
        replace={aab_archive.MANIFEST_ENTRY: patched_manifest},
        add=added,
        remove=set(dex_names),
    )
    verification.verify(
        app=output,
        platform=platforms.Platform.ANDROID,
        config=config,
        expected_entries={aab_archive.MANIFEST_ENTRY: patched_manifest, **added},
    )
    return dataclasses.replace(
        app_identity, effective_checks=config.checks, bindings=bindings
    )


def _aab_native_abis(aab: aab_archive.Aab) -> set[str]:
    """Returns the ABIs the AAB ships native libraries for under ``base/lib/``."""
    abis: set[str] = set()
    for name in aab.names():
        parts = name.split("/")
        if (
            len(parts) == 4
            and parts[0] == "base"
            and parts[1] == "lib"
            and parts[3].endswith(".so")
        ):
            abis.add(parts[2])
    return abis

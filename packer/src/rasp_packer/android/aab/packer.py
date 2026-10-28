"""Packing of Android App Bundles: adds the runtime to a built AAB, for on-demand loading.

A bundle gets the same protection an APK does: the base module's framework and library dexes stay in
the clear and only the app's own ("business") dexes are encrypted, each on its own, decrypted on
demand. The difference is the container. A bundle keeps every part of its base module under a ``base/``
folder, so the entries the APK packer writes at the APK root land under ``base/`` here:
``base/assets/rasp/key.bin``, ``base/assets/business/<i>.dex``, ``base/dex/classes*.dex`` and
``base/lib/<abi>/librasp.so``. bundletool maps those to the APK's ``assets/``, ``classes*.dex`` and
``lib/`` when it builds the APKs a device installs, so the runtime finds the same entries it reads from
a protected APK.

The packer protects the ``base`` module only. A bundle whose base module has no code cannot be
protected, and a bundle with another module that ships code is refused rather than shipped with that
code unprotected. The result is an unsigned bundle: the customer signs it and uploads it to Google
Play.
"""

import collections.abc
import contextlib
import pathlib
import tempfile
import zipfile

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import loader_map
from rasp_packer.android import resources as resources_module
from rasp_packer.android import split as split_module
from rasp_packer.android.aab import bundle
from rasp_packer.android.aab import manifest as manifest_module
from rasp_packer.android.apk import archive

BASE_PRIMARY_DEX = "base/dex/classes.dex"
BASE_ASSET_DIRECTORY = "base/assets/rasp"
BASE_KEY_ENTRY = f"{BASE_ASSET_DIRECTORY}/key.bin"
BASE_MAP_ENTRY = f"{BASE_ASSET_DIRECTORY}/map.bin"
BASE_BUILD_ID_ENTRY = f"{BASE_ASSET_DIRECTORY}/build_id"

type Splitter = collections.abc.Callable[[pathlib.Path, str], split_module.Split]


def pack(
    *,
    apk: archive.Apk,
    output: pathlib.Path,
    build_id: str,
    artifacts: resources_module.Artifacts,
    minimum_api_level: int,
    splitter: Splitter = split_module.split,
) -> identity.AppIdentity:
    """Packs an Android App Bundle, writing the protected bundle to output.

    Args:
        apk: The built bundle to protect, already read into memory.
        output: Where to write the protected bundle. It is unsigned.
        build_id: The id of the protected build, written into the bundle.
        artifacts: The prebuilt stub and libraries.
        minimum_api_level: The lowest API level the protected bundle may declare.
        splitter: Splits the base module's classes into framework and business dexes. The default runs
            the bundled splitter; a test passes a recorded split.

    Returns:
        The app's package name and version, read from the base module's manifest.

    Raises:
        InvalidBundleError: The bundle has no base manifest, no base code, or its manifest has no
            package, no literal android:versionName or no literal android:minSdkVersion.
        UnprotectedModuleError: A module other than base ships code the packer cannot protect.
        ManifestError: The base manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
        UnsupportedAbiError: The bundle ships native libraries for an ABI the runtime is not built for.
        AlreadyProtectedError: The bundle already holds the map, or its manifest already names the stub.
        SplitError: The base module's classes cannot be read or split.
    """
    manifest = bundle.base_manifest(apk)
    app_identity = manifest_module.app_identity(manifest)
    base_dex_names = bundle.base_dex_names(apk)
    if BASE_PRIMARY_DEX not in base_dex_names:
        raise errors.InvalidBundleError(
            f"the bundle's base module has no {BASE_PRIMARY_DEX} to protect"
        )
    _refuse_other_module_code(apk)
    if (
        BASE_MAP_ENTRY in apk.names()
        or manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the bundle is already protected")

    with _base_as_apk(apk, base_dex_names) as base_apk:
        result = splitter(base_apk, app_identity.package_name)

    patched_manifest = manifest_module.protect(
        manifest,
        factory=resources_module.STUB_FACTORY_CLASS,
        minimum_api_level=minimum_api_level,
    )
    key = cipher.new_key()
    map_frame = cipher.encrypt(key, loader_map.build(result.business).encode("utf-8"))
    business_entries = {
        bundle.BASE_ASSET_PREFIX + dex.path: cipher.encrypt(key, dex.data)
        for dex in result.business
    }
    apk.write(
        output,
        replace={bundle.BASE_MANIFEST_ENTRY: patched_manifest},
        add={
            BASE_KEY_ENTRY: key,
            BASE_MAP_ENTRY: map_frame,
            BASE_BUILD_ID_ENTRY: build_id.encode("utf-8"),
            **business_entries,
            **_base_dex_entries(result.framework, artifacts.stub_dex),
            **_library_entries(apk, artifacts),
        },
        remove=set(base_dex_names) | injection.stale_signature_entries(apk),
    )
    return app_identity


def _refuse_other_module_code(apk: archive.Apk) -> None:
    """Refuses a bundle whose non-base modules ship code, which the packer would leave unprotected."""
    offenders = bundle.modules_with_code(apk)
    if len(offenders) > 0:
        raise errors.UnprotectedModuleError(
            "the bundle has modules other than base that ship code the packer cannot protect: "
            + ", ".join(sorted(offenders))
        )


@contextlib.contextmanager
def _base_as_apk(
    apk: archive.Apk, base_dex_names: collections.abc.Sequence[str]
) -> collections.abc.Iterator[pathlib.Path]:
    """Yields the path of a temporary APK-shaped zip holding the base module's dexes as classes*.dex.

    The splitter reads an APK's ``classes*.dex`` entries, so the base module's dexes are copied into a
    throwaway zip under their APK names (``base/dex/classes2.dex`` becomes ``classes2.dex``). The path
    is valid only inside the ``with`` block.
    """
    with tempfile.TemporaryDirectory(prefix="rasp-aab-") as work:
        path = pathlib.Path(work) / "base.apk"
        with zipfile.ZipFile(path, "w") as pseudo_apk:
            for name in base_dex_names:
                leaf = name[len(bundle.BASE_DEX_PREFIX) :]
                pseudo_apk.writestr(
                    leaf, injection.entry(apk, name), compress_type=zipfile.ZIP_STORED
                )
        yield path


def _base_dex_entries(
    framework: collections.abc.Sequence[bytes], stub_dex: bytes
) -> dict[str, bytes]:
    """Returns the base module's clear dex entries: the framework dexes, then the stub, under base/dex/."""
    return {
        bundle.BASE_DEX_PREFIX + name: data
        for name, data in injection.base_dex_entries(framework, stub_dex).items()
    }


def _library_entries(
    apk: archive.Apk, artifacts: resources_module.Artifacts
) -> dict[str, bytes]:
    """Returns the native runtime library entries to add under base/lib/, one per chosen ABI."""
    abis = injection.select_abis(bundle.native_abis(apk), artifacts)
    return {
        f"{bundle.BASE_LIBRARY_PREFIX}{abi}/{resources_module.RUNTIME_LIBRARY}": artifacts.libraries[
            abi
        ]
        for abi in sorted(abis)
    }

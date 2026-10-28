"""Packing of Android apps: adds the runtime to a built APK, for on-demand loading.

The packer keeps the app's framework and library dexes in the clear and encrypts only the app's own
("business") dexes, each on its own, so the runtime decrypts one business dex the first time a class
in it is needed. A screen the user never opens is never decrypted, and a decrypted dex is held no
longer than it is used.

It produces the entries the runtime reads from the app's own APK (names and rules taken from the
runtime's ``payload/dex_store.*``, ``payload/assets.h`` and ``loader/loader_dex.*``):

- ``assets/rasp/key.bin`` — the raw 32-byte key, stored. It decrypts the map and every business dex.
- ``assets/rasp/map.bin`` — the class map (see loader_map), encrypted under the key, stored.
- ``assets/rasp/config.json`` — the runtime's config (see runtime_config), stored.
- ``assets/business/<i>.dex`` — one encrypted business dex per file, stored.
- the framework dexes and the stub, in the clear, as ``classes.dex`` … ``classesN.dex``.
- ``lib/<abi>/librasp.so`` — the runtime library, one per ABI, unmodified. The loader's own dex is
  already embedded in it at the runtime's build, so the packer does not touch the ``.so``.

It sets the manifest's appComponentFactory to the stub, raises minSdk to the runtime's floor (API 31,
which the in-memory loader and ``JNI_GetCreatedJavaVMs`` need), drops the app's original dexes and v1
signatures, and returns the protected APK unsigned, so the customer signs it. The stub and the native
runtime are prebuilt artifacts from the runtime build; see resources.
"""

import collections.abc
import pathlib

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import loader_map
from rasp_packer.android import resources as resources_module
from rasp_packer.android import split as split_module
from rasp_packer.android.apk import archive
from rasp_packer.android.apk import manifest as manifest_module

PRIMARY_DEX = "classes.dex"
MINIMUM_API_LEVEL = 31

ASSET_DIRECTORY = "assets/rasp"
KEY_ENTRY = f"{ASSET_DIRECTORY}/key.bin"
MAP_ENTRY = f"{ASSET_DIRECTORY}/map.bin"
CONFIG_ENTRY = f"{ASSET_DIRECTORY}/{runtime_config.FILE_NAME}"
ASSET_PREFIX = "assets/"

type Splitter = collections.abc.Callable[[pathlib.Path, str], split_module.Split]


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    artifacts: resources_module.Artifacts | None = None,
    splitter: Splitter = split_module.split,
) -> identity.AppIdentity:
    """Packs an Android app, writing the protected APK to output.

    Args:
        app: The built APK to protect.
        output: Where to write the protected APK. It is unsigned.
        config: The runtime's config, written into the APK.
        artifacts: The prebuilt stub and libraries. Loaded from the package resources when not given.
        splitter: Splits the app's classes into framework and business dexes. The default runs the
            bundled splitter; a test passes a recorded split.

    Returns:
        The app's package name and version, read from its manifest.

    Raises:
        InvalidApkError: The app is not a valid APK, has no dex files, or its manifest has no
            package, no literal android:versionName or no literal android:minSdkVersion.
        ManifestError: The app's manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
        UnsupportedAbiError: The app ships native libraries for an ABI the runtime is not built for.
        AlreadyProtectedError: The app already holds the map, or its manifest already names the stub.
        SplitError: The app's classes cannot be read or split.
    """
    if artifacts is None:
        artifacts = resources_module.load()
    apk = archive.Apk.read(app)
    dex_names = apk.dex_names()
    if PRIMARY_DEX not in dex_names:
        raise errors.InvalidApkError(f"APK has no {PRIMARY_DEX} to protect")
    manifest = apk.manifest()
    app_identity = manifest_module.app_identity(manifest)
    if (
        MAP_ENTRY in apk.names()
        or manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")

    result = splitter(app, app_identity.package_name)

    patched_manifest = manifest_module.set_app_component_factory(
        manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL),
        resources_module.STUB_FACTORY_CLASS,
    )
    key = cipher.new_key()
    map_frame = cipher.encrypt(key, loader_map.build(result.business).encode("utf-8"))
    business_entries = {
        ASSET_PREFIX + dex.path: cipher.encrypt(key, dex.data)
        for dex in result.business
    }
    base_dexes = injection.base_dex_entries(result.framework, artifacts.stub_dex)
    apk.write(
        output,
        replace={archive.MANIFEST_ENTRY: patched_manifest},
        add={
            KEY_ENTRY: key,
            MAP_ENTRY: map_frame,
            CONFIG_ENTRY: config.to_json(),
            **business_entries,
            **base_dexes,
            **injection.library_entries(apk, artifacts),
        },
        remove=set(dex_names) | injection.stale_signature_entries(apk),
    )
    return app_identity

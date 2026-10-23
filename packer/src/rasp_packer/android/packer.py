"""Packing of Android apps: adds the runtime to a built APK.

The packer encrypts the app's dex files, adds the stub and the native runtime,
and sets the manifest's appComponentFactory to the stub. At run time Android loads
the stub, whose static initializer loads the runtime; as it loads, the runtime
reads the key and payload from the APK, runs its pre-decryption checks, decrypts
the dex files, and builds a class loader over them that it hands back to the stub;
the stub returns that loader so Android runs the app's own code.

The stub and the native runtime are prebuilt artifacts from the runtime build;
see resources. This module writes the protected APK unsigned, so the customer
signs it.

The decrypted dex files are loaded from memory, which Android supports from
Android 8.0, but the runtime does so through an AppComponentFactory (the stub) and
a class loader with a native-library path that need API 31. So the packer raises
the app's minSdkVersion to MINIMUM_API_LEVEL when it is lower, and the protected
app does not install on older devices.
"""

import pathlib

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android import cipher
from rasp_packer.android import config as config_module
from rasp_packer.android import injection
from rasp_packer.android import payload as payload_module
from rasp_packer.android import resources as resources_module
from rasp_packer.android.apk import archive
from rasp_packer.android.apk import manifest as manifest_module

PRIMARY_DEX = "classes.dex"
MINIMUM_API_LEVEL = 31


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    build_id: str,
    artifacts: resources_module.Artifacts | None = None,
) -> identity.AppIdentity:
    """Packs an Android app, writing the protected APK to output.

    Args:
        app: The built APK to protect.
        output: Where to write the protected APK. It is unsigned.
        build_id: The deterministic id of this protected build.
        artifacts: The prebuilt stub and libraries. Loaded from the package
            resources when not given.

    Returns:
        The app's package name and version, read from its manifest.

    Raises:
        InvalidApkError: The app is not a valid APK, has no dex files, or its
            manifest has no package, no literal android:versionName or no
            literal android:minSdkVersion.
        ManifestError: The app's manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
        UnsupportedAbiError: The app ships native libraries for an ABI the
            runtime is not built for.
        AlreadyProtectedError: The app already holds a payload, or its
            manifest already names the stub as its component factory.
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
        config_module.PAYLOAD_ENTRY in apk.names()
        or manifest_module.app_component_factory(manifest)
        == resources_module.STUB_FACTORY_CLASS
    ):
        raise errors.AlreadyProtectedError("the app is already protected")
    patched_manifest = manifest_module.set_app_component_factory(
        manifest_module.raise_min_sdk_version(manifest, MINIMUM_API_LEVEL),
        resources_module.STUB_FACTORY_CLASS,
    )
    libraries = injection.library_entries(apk, artifacts)
    dexes = [
        payload_module.Dex(name=name, data=injection.entry(apk, name))
        for name in dex_names
    ]
    key = cipher.new_key()
    payload = payload_module.build(key, dexes)
    config = config_module.RuntimeConfig(
        build_id=build_id,
        key_hex=key.hex(),
        dex_names=tuple(dex_names),
    )
    apk.write(
        output,
        replace={
            archive.MANIFEST_ENTRY: patched_manifest,
            PRIMARY_DEX: artifacts.stub_dex,
        },
        add={
            config_module.CONFIG_ENTRY: config.to_json().encode("utf-8"),
            config_module.KEY_ENTRY: key,
            config_module.PAYLOAD_ENTRY: payload,
            **libraries,
        },
        remove={name for name in dex_names if name != PRIMARY_DEX}
        | injection.stale_signature_entries(apk),
    )
    return app_identity

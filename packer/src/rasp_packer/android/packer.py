"""Packing of Android apps: adds the runtime to a built APK.

The packer encrypts the app's dex files, adds the stub loader and the native
runtime, and points the manifest at the stub. At run time the stub loads the
runtime, the runtime runs its pre-decryption checks and, if they pass, decrypts
the dex files; the stub then loads them and hands control to the app's original
application class.

The stub and the native runtime are prebuilt artifacts from the runtime build;
see resources. This module writes the protected APK unsigned, so the customer
signs it.
"""

import pathlib

from rasp_packer import errors
from rasp_packer.android import cipher
from rasp_packer.android import config as config_module
from rasp_packer.android import payload as payload_module
from rasp_packer.android import resources as resources_module
from rasp_packer.android.apk import archive
from rasp_packer.android.apk import manifest as manifest_module

PRIMARY_DEX = "classes.dex"


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    build_id: str,
    artifacts: resources_module.Artifacts | None = None,
) -> None:
    """Packs an Android app, writing the protected APK to output.

    Args:
        app: The built APK to protect.
        output: Where to write the protected APK. It is unsigned.
        build_id: The deterministic id of this protected build.
        artifacts: The prebuilt stub and libraries. Loaded from the package
            resources when not given.

    Raises:
        InvalidApkError: The app is not a valid APK, or has no dex files.
        ManifestError: The app's manifest cannot be read or edited.
        MissingRuntimeArtifactError: A prebuilt runtime artifact is missing.
    """
    if artifacts is None:
        artifacts = resources_module.load()
    apk = archive.Apk.read(app)
    dex_names = apk.dex_names()
    if PRIMARY_DEX not in dex_names:
        raise errors.InvalidApkError(f"APK has no {PRIMARY_DEX} to protect")
    manifest = apk.manifest()
    application_class = manifest_module.application_class(manifest)
    dexes = [
        payload_module.Dex(name=name, data=_entry(apk, name)) for name in dex_names
    ]
    key = cipher.new_key()
    payload = payload_module.build(key, dexes)
    config = config_module.RuntimeConfig(
        build_id=build_id,
        key_hex=key.hex(),
        application_class=application_class,
        dex_names=tuple(dex_names),
    )
    patched_manifest = manifest_module.set_application_class(
        manifest, resources_module.STUB_APPLICATION_CLASS
    )
    apk.write(
        output,
        replace={
            archive.MANIFEST_ENTRY: patched_manifest,
            PRIMARY_DEX: artifacts.stub_dex,
        },
        add={
            config_module.CONFIG_ENTRY: config.to_json().encode("utf-8"),
            config_module.PAYLOAD_ENTRY: payload,
            **_library_entries(artifacts),
        },
        remove={name for name in dex_names if name != PRIMARY_DEX}
        | _stale_signature_entries(apk),
    )


def _entry(apk: archive.Apk, name: str) -> bytes:
    """Returns the bytes of the APK entry `name`."""
    data = apk.get(name)
    if data is None:
        raise errors.InvalidApkError(f"APK entry {name} disappeared while packing")
    return data


def _stale_signature_entries(apk: archive.Apk) -> set[str]:
    """Returns the names of the APK's v1 signature entries, which packing makes invalid."""
    return {name for name in apk.names() if _is_signature(name)}


def _is_signature(name: str) -> bool:
    """Whether the entry `name` is part of a v1 signature."""
    if not name.startswith("META-INF/"):
        return False
    return (
        name.endswith((".SF", ".RSA", ".DSA", ".EC")) or name == "META-INF/MANIFEST.MF"
    )


def _library_entries(artifacts: resources_module.Artifacts) -> dict[str, bytes]:
    """Returns the APK entries of the native runtime library, one per ABI."""
    return {
        f"lib/{abi}/{resources_module.RUNTIME_LIBRARY}": data
        for abi, data in artifacts.libraries.items()
    }

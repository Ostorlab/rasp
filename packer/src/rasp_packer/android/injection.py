"""The APK edits that add the runtime to an app, kept apart from the assembly in packer.py.

They place the native runtime libraries (one per ABI) and the plugins, drop the v1 signature
entries that repacking makes invalid, read an APK entry, and name the base dexes. pack() calls them,
so it reads as its sequence of steps and each edit is tested on its own.
"""

import collections.abc

from rasp_packer import errors
from rasp_packer import plugins as plugins_module
from rasp_packer.android import resources as resources_module
from rasp_packer.android.apk import archive

PLUGIN_LIST_ENTRY = "assets/rasp/plugins.list"
PLUGIN_CONFIG_DIRECTORY = "assets/rasp/plugin-config"


def entry(apk: archive.Apk, name: str) -> bytes:
    """Returns the bytes of the APK entry `name`.

    Args:
        apk: The app's APK.
        name: The entry's full name.

    Returns:
        The entry's bytes.

    Raises:
        InvalidApkError: The entry is absent.
    """
    data = apk.get(name)
    if data is None:
        raise errors.InvalidApkError(f"APK entry {name} disappeared while packing")
    return data


def library_entries(
    apk: archive.Apk, artifacts: resources_module.Artifacts
) -> dict[str, bytes]:
    """Returns the native runtime library entries to add to the app.

    One library is added per ABI runtime_abis returns, so the runtime loads whichever ABI the device
    picks.

    Args:
        apk: The app's APK.
        artifacts: The prebuilt runtime libraries, by ABI.

    Returns:
        The library entries, by APK entry name.

    Raises:
        UnsupportedAbiError: The app ships an ABI the runtime is not built for.
    """
    return {
        f"lib/{abi}/{resources_module.RUNTIME_LIBRARY}": artifacts.libraries[abi]
        for abi in sorted(runtime_abis(apk, artifacts))
    }


def runtime_abis(apk: archive.Apk, artifacts: resources_module.Artifacts) -> set[str]:
    """Returns the ABIs the protected app gets the runtime for.

    They are the ABIs the app ships native libraries for, or every runtime ABI when the app ships
    none.

    Args:
        apk: The app's APK.
        artifacts: The prebuilt runtime libraries, by ABI.

    Returns:
        The ABI names.

    Raises:
        UnsupportedAbiError: The app ships an ABI the runtime is not built for.
    """
    app_abis = native_abis(apk)
    if len(app_abis) == 0:
        return set(artifacts.libraries)
    unsupported = app_abis - set(artifacts.libraries)
    if len(unsupported) > 0:
        raise errors.UnsupportedAbiError(
            "the runtime is not built for the app's ABIs: "
            + ", ".join(sorted(unsupported))
        )
    return app_abis


def plugin_entries(
    plugins: collections.abc.Sequence[plugins_module.Plugin],
    abis: collections.abc.Set[str],
) -> dict[str, bytes]:
    """Returns the entries that add the plugins to the app.

    They are each plugin's library next to the runtime for every ABI in `abis`, each plugin's
    config when it has one, and the plugin list, which names the plugins in load order. With no
    plugin there is no entry, not even the list.

    Args:
        plugins: The plugins, in load order.
        abis: The ABIs the app gets the runtime for.

    Returns:
        The entries, by APK entry name.

    Raises:
        InvalidPluginError: A plugin has no library for one of `abis`.
    """
    if len(plugins) == 0:
        return {}
    entries: dict[str, bytes] = {}
    for plugin in plugins:
        missing = sorted(abis - set(plugin.android_libraries))
        if len(missing) > 0:
            raise errors.InvalidPluginError(
                f"plugin {plugin.name} has no Android library for the ABIs {', '.join(missing)}"
            )
        library = plugins_module.android_library_name(plugin.name)
        for abi in sorted(abis):
            entries[f"lib/{abi}/{library}"] = plugin.android_libraries[abi]
        if len(plugin.config) > 0:
            entries[f"{PLUGIN_CONFIG_DIRECTORY}/{plugin.name}"] = plugin.config
    entries[PLUGIN_LIST_ENTRY] = plugins_module.plugin_list(plugins)
    return entries


def native_abis(apk: archive.Apk) -> set[str]:
    """Returns the ABIs the app ships native libraries for: the folders of lib/ that hold a .so file.

    Args:
        apk: The app's APK.

    Returns:
        The ABI names.
    """
    abis: set[str] = set()
    for name in apk.names():
        parts = name.split("/")
        if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
            abis.add(parts[1])
    return abis


def stale_signature_entries(apk: archive.Apk) -> set[str]:
    """Returns the names of the APK's v1 signature entries, which repacking makes invalid.

    Args:
        apk: The app's APK.

    Returns:
        The signature entry names.
    """
    return {name for name in apk.names() if _is_signature(name)}


def _is_signature(name: str) -> bool:
    """Whether the entry `name` is part of a v1 signature."""
    if not name.startswith("META-INF/"):
        return False
    return (
        name.endswith((".SF", ".RSA", ".DSA", ".EC")) or name == "META-INF/MANIFEST.MF"
    )


def base_dex_entries(
    framework: collections.abc.Sequence[bytes], stub_dex: bytes
) -> dict[str, bytes]:
    """Returns the base dex entries Android loads in the clear: the framework dexes, then the stub.

    The entries are named as a multidex app's are: classes.dex, then classes2.dex, classes3.dex and
    so on, in the order given, with the stub last. Android loads them in that order, and the stub,
    being last, never shadows an app class.

    Args:
        framework: The framework dex files, in load order.
        stub_dex: The stub loader dex.

    Returns:
        The base dex entries, by APK entry name.
    """
    entries: dict[str, bytes] = {}
    for index, data in enumerate([*framework, stub_dex]):
        entries[primary_dex_name(index)] = data
    return entries


def primary_dex_name(index: int) -> str:
    """Returns the multidex entry name at `index`: classes.dex for 0, classesN.dex (N = index + 1) after.

    Args:
        index: The zero-based position in the multidex order.

    Returns:
        The entry name.
    """
    return "classes.dex" if index == 0 else f"classes{index + 1}.dex"

"""The APK edits that add the runtime to an app, kept apart from the assembly in packer.py.

They choose the ABIs and place the native runtime libraries (one per ABI), list the native libraries
of dropped ABIs, drop the v1 signature entries that repacking makes invalid, read an APK entry, and
name the base dexes. pack() calls them, so it reads as its sequence of steps and each edit is tested
on its own.
"""

import collections.abc

from rasp_packer import errors
from rasp_packer.android import resources as resources_module
from rasp_packer.android.apk import archive


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


def resolve_abis(
    app_abis: collections.abc.Set[str],
    artifacts: resources_module.Artifacts,
    chosen: collections.abc.Set[str] | None = None,
) -> set[str]:
    """Returns the ABIs to ship the runtime for.

    Without a choice, the runtime covers every ABI the app ships native libraries for, or every runtime
    ABI when the app ships none. With a choice, the runtime covers exactly the chosen ABIs, and the app's
    native libraries for any other ABI are to be dropped.

    Args:
        app_abis: The ABIs the app ships native libraries for.
        artifacts: The prebuilt runtime libraries, by ABI.
        chosen: The ABIs the protected app supports, or None to follow the app's own.

    Returns:
        The ABIs to include.

    Raises:
        UnsupportedAbiError: The runtime is not built for an ABI the app ships, without a choice, or for
            a chosen ABI.
        InvalidAbisError: The choice is empty, or names an ABI the app ships no native libraries for
            while it ships some for other ABIs.
    """
    runtime_abis = set(artifacts.libraries)
    if chosen is None:
        return _follow_app_abis(app_abis, runtime_abis)
    if len(chosen) == 0:
        raise errors.InvalidAbisError("no ABI is chosen; give at least one")
    unsupported = chosen - runtime_abis
    if len(unsupported) > 0:
        raise errors.UnsupportedAbiError(
            f"the runtime is not built for the chosen ABIs: {_listed(unsupported)}"
        )
    missing = chosen - app_abis
    if len(app_abis) > 0 and len(missing) > 0:
        raise errors.InvalidAbisError(
            f"the app ships no native libraries for the chosen ABIs: {_listed(missing)}; "
            "its own native code would be missing on those devices"
        )
    return set(chosen)


def _follow_app_abis(
    app_abis: collections.abc.Set[str], runtime_abis: set[str]
) -> set[str]:
    """Returns the app's ABIs, or every runtime ABI when the app ships none, refusing one the runtime lacks."""
    if len(app_abis) == 0:
        return runtime_abis
    unsupported = app_abis - runtime_abis
    if len(unsupported) > 0:
        pronoun = "it" if len(unsupported) == 1 else "them"
        raise errors.UnsupportedAbiError(
            f"the runtime is not built for the app's ABIs: {_listed(unsupported)}; "
            f"pass --abis to drop {pronoun}"
        )
    return set(app_abis)


def _listed(abis: collections.abc.Set[str]) -> str:
    """Returns the ABIs sorted and comma-separated."""
    return ", ".join(sorted(abis))


def library_entries(
    abis: collections.abc.Set[str],
    artifacts: resources_module.Artifacts,
    library_filename: str,
) -> dict[str, bytes]:
    """Returns the native runtime library entries to add to the app, one per ABI.

    Args:
        abis: The ABIs to ship the runtime for, as resolve_abis returns them.
        artifacts: The prebuilt runtime libraries, by ABI.
        library_filename: The library's filename in the app.

    Returns:
        The library entries, by APK entry name.
    """
    return {
        f"lib/{abi}/{library_filename}": artifacts.libraries[abi]
        for abi in sorted(abis)
    }


def abi_folder_entries(
    names: collections.abc.Iterable[str],
    prefix: str,
    abis: collections.abc.Set[str],
) -> set[str]:
    """Returns the names of the entries inside the library folder of any of `abis`.

    Args:
        names: The app's entry names.
        prefix: The library directory's prefix, ``lib/`` for an APK and ``base/lib/`` for an AAB.
        abis: The ABIs whose folders to list.

    Returns:
        The entry names.
    """
    folders = tuple(f"{prefix}{abi}/" for abi in abis)
    return {name for name in names if name.startswith(folders)}


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

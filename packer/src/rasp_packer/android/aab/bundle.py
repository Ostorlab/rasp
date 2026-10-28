"""Reading the parts of an Android App Bundle (AAB) the packer needs.

An AAB is a ZIP, like an APK, so the in-memory ZIP container is the same ``archive.Apk``. What differs
is the layout. A bundle holds one folder per module at its root (always a ``base`` module, plus any
feature modules), a ``BundleConfig.pb`` at the root, and the module's parts under its folder: the
manifest at ``<module>/manifest/AndroidManifest.xml`` (in protobuf form, not binary XML), the code at
``<module>/dex/classes*.dex``, the native libraries at ``<module>/lib/<abi>/`` and the assets at
``<module>/assets/``. bundletool later turns the bundle into the APKs a device installs, mapping
``base/assets/x`` to ``assets/x``, ``base/dex/classes.dex`` to ``classes.dex`` and so on.

The packer protects the ``base`` module only, the same protection an APK gets, so this module reads the
base module's manifest, dexes and ABIs, and finds any non-base module that also ships code (which the
packer refuses, rather than leave it unprotected).
"""

import re

from rasp_packer import errors
from rasp_packer.android.apk import archive

BUNDLE_CONFIG_ENTRY = "BundleConfig.pb"
BASE_MODULE = "base"
BASE_MANIFEST_ENTRY = "base/manifest/AndroidManifest.xml"
BASE_DEX_PREFIX = "base/dex/"
BASE_ASSET_PREFIX = "base/assets/"
BASE_LIBRARY_PREFIX = "base/lib/"

_DEX_SUFFIX = ".dex"
_SO_SUFFIX = ".so"
_DEX_LEAF = re.compile(r"classes([2-9]|[1-9][0-9]+)?\.dex")


def is_bundle(apk: archive.Apk) -> bool:
    """Returns whether the archive is an App Bundle: it holds a ``BundleConfig.pb`` at its root."""
    return BUNDLE_CONFIG_ENTRY in apk.names()


def base_manifest(apk: archive.Apk) -> bytes:
    """Returns the protobuf AndroidManifest.xml of the base module.

    Raises:
        InvalidBundleError: The base module has no manifest.
    """
    data = apk.get(BASE_MANIFEST_ENTRY)
    if data is None:
        raise errors.InvalidBundleError(f"bundle has no {BASE_MANIFEST_ENTRY}")
    return data


def base_dex_names(apk: archive.Apk) -> list[str]:
    """Returns the names of the base module's dex entries, in load order.

    The load order is ``base/dex/classes.dex``, ``base/dex/classes2.dex``, ``base/dex/classes3.dex``
    and so on.
    """
    names = [name for name in apk.names() if _is_base_dex(name)]
    return sorted(names, key=_dex_order)


def modules_with_code(apk: archive.Apk) -> set[str]:
    """Returns the names of the modules other than ``base`` that ship a dex file.

    Args:
        apk: The bundle.

    Returns:
        The module names, each a top-level folder other than ``base`` that holds a ``dex/*.dex`` file.
    """
    modules: set[str] = set()
    for name in apk.names():
        parts = name.split("/")
        if (
            len(parts) >= 3
            and parts[0] != BASE_MODULE
            and parts[1] == "dex"
            and parts[-1].endswith(_DEX_SUFFIX)
        ):
            modules.add(parts[0])
    return modules


def native_abis(apk: archive.Apk) -> set[str]:
    """Returns the ABIs the base module ships native libraries for: the folders of ``base/lib/``."""
    abis: set[str] = set()
    for name in apk.names():
        parts = name.split("/")
        if (
            len(parts) == 4
            and parts[0] == BASE_MODULE
            and parts[1] == "lib"
            and parts[3].endswith(_SO_SUFFIX)
        ):
            abis.add(parts[2])
    return abis


def _is_base_dex(name: str) -> bool:
    """Returns whether an entry is a base-module dex: ``base/dex/classes.dex`` or ``base/dex/classesN.dex``."""
    if name.startswith(BASE_DEX_PREFIX) is False:
        return False
    leaf = name[len(BASE_DEX_PREFIX) :]
    return _DEX_LEAF.fullmatch(leaf) is not None


def _dex_order(name: str) -> int:
    """Returns the position Android loads a base dex in, comparing its number numerically."""
    leaf = name[len(BASE_DEX_PREFIX) :]
    middle = leaf[len("classes") : len(leaf) - len(_DEX_SUFFIX)]
    if len(middle) == 0:
        return 1
    return int(middle)

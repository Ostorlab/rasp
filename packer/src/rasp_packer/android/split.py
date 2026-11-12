"""The seam over the dex splitter: sort an app's classes into framework and business dexes.

The on-demand packer keeps the app's framework and library code in the clear and encrypts only the
app's own ("business") code, one dex at a time, served on demand. Telling the two apart, and
regrouping the classes into dex files that each load on their own, is the job of the ``dexsplit``
package, which this module calls in process. This module is the only place that calls it, so swapping
it for another splitter later touches only this file.

There are two ways to tell business code from the rest:

- **Without an R8 mapping** (the default), a class is business when its binary name is under the app's
  package, and framework otherwise. This is right for a debug build, or a release build that does not
  obfuscate. It is wrong for a release build that R8 repackaged: R8 moves the app's own classes out of
  the app's package into generated packages such as ``Y2``, so almost none of them are still under the
  app's package, and almost all of the app's code would ship in the clear. When this module sees that
  shape, it logs a warning telling the operator to pass the mapping.
- **With an R8 mapping** (see ``rasp_packer.android.mapping``), the mapping says which obfuscated
  packages hold the app's own classes, and every class in one of those packages is business. The
  mapping is how the operator recovers full protection on a repackaged release build.

Either way the splitter keeps every Java package of the business code whole in one dex: two business
classes in the same package but in different encrypted dexes would be defined by different class
loaders, and package-private access between them would be refused at run time (an ``IllegalAccessError``).
This is also why a whole obfuscated package is protected when a mapping is used: R8 can put app classes
and library classes in the same generated package, and splitting that package into a clear part and an
encrypted part would break package-private access across the two class loaders. Protecting the package
whole keeps it in one loader and encrypts the library classes in it too, which is more protection, not
less. The framework code is not encrypted and not regrouped: each of its dex files keeps the classes it
came with, in the clear. The splitter still reads and writes each of these files again, so their bytes
can differ from the app's.
"""

import collections.abc
import dataclasses
import logging
import pathlib
import re
import zipfile
import zlib

from dexsplit.strategies import original
from dexsplit.strategies import package_affinity

import dexsplit
from dexsplit import class_sets
from dexsplit import splitter
from rasp_packer import errors
from rasp_packer.android import mapping as mapping_module

_LOGGER = logging.getLogger(__name__)

# The set names the classes are sorted into.
_BUSINESS_SET = "business"
_FRAMEWORK_SET = "framework"

# The asset subfolder, under assets/, that each encrypted business dex lives in.
BUSINESS_DIRECTORY = "business"

# What reading a corrupt, truncated or encrypted APK entry can raise.
_ZIP_READ_ERRORS = (
    OSError,
    zipfile.BadZipFile,
    RuntimeError,
    NotImplementedError,
    zlib.error,
    EOFError,
)

# A top-level ``classes*.dex`` entry of an APK.
_ROOT_DEX = re.compile(r"classes[0-9]*\.dex")

# When no mapping is given, warn that the app looks repackaged if it has at least this many classes
# and at most this fraction of them are under the app's package. Both guard against false warnings: a
# small app has too few classes for the fraction to mean much, and a healthy app has a real share of
# its code under its own package.
_REPACKAGE_MIN_CLASSES = 500
_REPACKAGE_MAX_BUSINESS_RATIO = 0.05


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class BusinessDex:
    """One of the app's own dex files, to be encrypted and served on demand.

    Attributes:
        path: The dex's path under assets/, such as ``business/0.dex``. The runtime reads the entry
            ``assets/business/0.dex`` and names it in the class map.
        data: The dex bytes, in the clear.
        classes: The binary names of the classes the dex defines, such as ``com.example.Main``.
    """

    path: str
    data: bytes
    classes: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Split:
    """The result of splitting an app's classes.

    Attributes:
        framework: The framework dex files, in load order. They ship in the clear as the base dexes.
        business: The app's own dex files, each encrypted and served on demand.
    """

    framework: tuple[bytes, ...]
    business: tuple[BusinessDex, ...]


class SplitError(errors.Error):
    """The app's classes could not be split."""


def split(
    app: pathlib.Path,
    package: str,
    mapping: mapping_module.ClassMapping | None = None,
) -> Split:
    """Splits the classes of an app into framework and business dexes.

    It reads the app's ``classes*.dex`` entries and sorts each class into the business set or the
    framework set, then regroups the business set into dex files with every Java package kept whole
    and keeps the framework set in the dex files it came from.

    Without ``mapping``, a class is business when its binary name is under ``package``. With
    ``mapping``, a class is business when its (obfuscated) package is one the mapping says holds the
    app's own classes; this recovers the app's code on an R8-repackaged release build.

    Args:
        app: The app's APK.
        package: The app's package, such as ``com.example``. Its classes are the business code.
        mapping: The app's R8 mapping, or None to pick business classes by their package.

    Returns:
        The framework dexes in load order, and the business dexes with the classes each defines.

    Raises:
        SplitError: The app cannot be read, or its classes cannot be split.
    """
    dex_entries = _read_apk_dex_entries(app)
    return _split(dex_entries, package, mapping=mapping, label=str(app))


def split_from_dex_entries(
    dex_entries: collections.abc.Mapping[str, bytes],
    package: str,
    mapping: mapping_module.ClassMapping | None = None,
) -> Split:
    """Splits classes from pre-extracted DEX entries (e.g. from an AAB).

    Args:
        dex_entries: A mapping of bare root-level DEX file names (``classes.dex``, ``classes2.dex``,
            ...) to their bytes.
        package: The app's package, such as ``com.example``.
        mapping: The app's R8 mapping, or None to pick business classes by their package.

    Returns:
        The framework dexes in load order, and the business dexes with the classes each defines.

    Raises:
        SplitError: There are no DEX entries, a key is not a bare root-level name, or the classes
            cannot be split.
    """
    if len(dex_entries) == 0:
        raise SplitError("no DEX entries to split")
    for name in dex_entries:
        if "/" in name or "\\" in name or name.endswith(".dex") is False:
            raise SplitError(
                f"dex_entries key must be a bare root-level .dex filename, got: {name!r}"
            )
    return _split(dict(dex_entries), package, mapping=mapping, label="AAB DEX entries")


def _split(
    dex_entries: collections.abc.Mapping[str, bytes],
    package: str,
    *,
    mapping: mapping_module.ClassMapping | None,
    label: str,
) -> Split:
    """Run the splitter with the packer's rules and shape its output into a Split."""
    sets, assignments = _sets_and_assignments(package, mapping)
    try:
        result = splitter.split(dex_entries, sets, assignments)
    except dexsplit.Error as error:
        raise SplitError(f"splitting {label} failed: {error}") from error
    if mapping is None:
        _warn_if_repackaged(result, package)
    return _to_split(result)


def _sets_and_assignments(
    package: str, mapping: mapping_module.ClassMapping | None
) -> tuple[tuple[class_sets.ClassSet, ...], tuple[class_sets.Assignment, ...]]:
    """The business and framework sets, and the rules that sort classes into them.

    Without a mapping, the single rule sends the classes under ``package`` to the business set. With
    a mapping, one rule per obfuscated business package sends every class in that package to the
    business set, so each such package is protected whole. A final ``**`` rule sends everything else
    to the framework set.
    """
    sets = (
        class_sets.ClassSet(_BUSINESS_SET, package_affinity.PackageAffinity()),
        class_sets.ClassSet(_FRAMEWORK_SET, original.Original()),
    )
    business: tuple[class_sets.Assignment, ...]
    if mapping is None:
        business = (class_sets.Assignment(f"{package}.**", _BUSINESS_SET),)
    else:
        business = tuple(
            class_sets.Assignment(_package_pattern(business_package), _BUSINESS_SET)
            for business_package in sorted(mapping.business_packages(package))
        )
    assignments = (*business, class_sets.Assignment("**", _FRAMEWORK_SET))
    return sets, assignments


def _package_pattern(package: str) -> str:
    """The assignment pattern that matches every class directly in a package, the package kept whole.

    ``W2`` gives ``W2.*`` and the default (unnamed) package, the empty string, gives ``*``. In a
    pattern ``*`` matches any characters but a dot, so it matches the classes directly in the package,
    nested classes among them (``$`` is not a dot), but not a sub-package's classes, which are a
    different Java package with their own rule when they hold business classes.
    """
    if len(package) == 0:
        return "*"
    return f"{package}.*"


def _warn_if_repackaged(result: splitter.Result, package: str) -> None:
    """Warn when no mapping was given but the app looks like R8 moved its classes out of its package."""
    business = sum(
        len(output.classes)
        for output in result.files
        if output.set_name == _BUSINESS_SET
    )
    total = sum(len(output.classes) for output in result.files)
    if total < _REPACKAGE_MIN_CLASSES:
        return
    if business > total * _REPACKAGE_MAX_BUSINESS_RATIO:
        return
    _LOGGER.warning(
        "only %d of %d classes are under %r; if R8 repackaged this release build, most of the app's "
        "own code is shipping in the clear. Pass the R8 mapping file with --mapping so the packer can "
        "find the app's classes by their obfuscated names.",
        business,
        total,
        package,
    )


def _to_split(result: splitter.Result) -> Split:
    """Shape the splitter's output files into a Split, reindexing the business dexes from 0."""
    framework = tuple(
        output.data for output in result.files if output.set_name == _FRAMEWORK_SET
    )
    business_files = [
        output for output in result.files if output.set_name == _BUSINESS_SET
    ]
    business = tuple(
        BusinessDex(
            path=f"{BUSINESS_DIRECTORY}/{index}.dex",
            data=output.data,
            classes=tuple(_binary_name(descriptor) for descriptor in output.classes),
        )
        for index, output in enumerate(business_files)
    )
    return Split(framework=framework, business=business)


def _read_apk_dex_entries(app: pathlib.Path) -> dict[str, bytes]:
    """Read every top-level ``classes*.dex`` entry of an APK into a name-to-bytes mapping."""
    try:
        with zipfile.ZipFile(app) as archive:
            return {
                name: archive.read(name)
                for name in archive.namelist()
                if "/" not in name and _ROOT_DEX.fullmatch(name) is not None
            }
    except _ZIP_READ_ERRORS as error:
        raise SplitError(f"cannot read {app}: {error}") from error


def _binary_name(descriptor: str) -> str:
    """Converts a type descriptor to a binary class name: ``Lcom/a/B$C;`` gives ``com.a.B$C``."""
    if len(descriptor) < 2 or descriptor[0] != "L" or descriptor[-1] != ";":
        raise SplitError(f"not a class descriptor: {descriptor!r}")
    return descriptor[1:-1].replace("/", ".")

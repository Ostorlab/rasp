"""The seam over the dex splitter: sort an app's classes into framework and business dexes.

The on-demand packer keeps the app's framework and library code in the clear and encrypts only the
app's own ("business") code, one dex at a time, served on demand. Telling the two apart, and
regrouping the classes into dex files that each load on their own, is the job of the ``dexsplit``
package, which this module calls in process. This module is the only place that calls it, so swapping
it for another splitter later touches only this file.

A class is business when its binary name is under the app's package, framework otherwise. The
splitter keeps every Java package of the business code whole in one dex: two business classes in the
same package but in different encrypted dexes would be defined by different class loaders, and
package-private access between them would be refused at run time. The framework code is not encrypted
and not regrouped; it stays in the dex files it came from, in the clear.
"""

import collections.abc
import dataclasses
import pathlib
import re
import zipfile

from dexsplit.strategies import original
from dexsplit.strategies import package_affinity

import dexsplit
from dexsplit import class_sets
from dexsplit import splitter
from rasp_packer import errors

# The set names the classes are sorted into.
_BUSINESS_SET = "business"
_FRAMEWORK_SET = "framework"

# The asset subfolder, under assets/, that each encrypted business dex lives in.
BUSINESS_DIRECTORY = "business"

# A top-level ``classes*.dex`` entry of an APK.
_ROOT_DEX = re.compile(r"classes[0-9]*\.dex")


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


def split(app: pathlib.Path, package: str) -> Split:
    """Splits the classes of an app into framework and business dexes.

    It reads the app's ``classes*.dex`` entries and sorts every class whose binary name is under
    ``package`` into the business set and the rest into the framework set. It regroups the business
    set into dex files with every Java package kept whole, and keeps the framework set in the dex
    files it came from.

    Args:
        app: The app's APK.
        package: The app's package, such as ``com.example``. Its classes are the business code.

    Returns:
        The framework dexes in load order, and the business dexes with the classes each defines.

    Raises:
        SplitError: The app cannot be read, or its classes cannot be split.
    """
    dex_entries = _read_apk_dex_entries(app)
    return _split(dex_entries, package, label=str(app))


def split_from_dex_entries(
    dex_entries: collections.abc.Mapping[str, bytes], package: str
) -> Split:
    """Splits classes from pre-extracted DEX entries (e.g. from an AAB).

    Args:
        dex_entries: A mapping of bare root-level DEX file names (``classes.dex``, ``classes2.dex``,
            ...) to their bytes.
        package: The app's package, such as ``com.example``.

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
    return _split(dict(dex_entries), package, label="AAB DEX entries")


def _split(
    dex_entries: collections.abc.Mapping[str, bytes], package: str, *, label: str
) -> Split:
    """Run the splitter with the packer's rules and shape its output into a Split."""
    sets = (
        class_sets.ClassSet(_BUSINESS_SET, package_affinity.PackageAffinity()),
        class_sets.ClassSet(_FRAMEWORK_SET, original.Original()),
    )
    assignments = (
        class_sets.Assignment(f"{package}.**", _BUSINESS_SET),
        class_sets.Assignment("**", _FRAMEWORK_SET),
    )
    try:
        result = splitter.split(dex_entries, sets, assignments)
    except dexsplit.Error as error:
        raise SplitError(f"splitting {label} failed: {error}") from error
    return _to_split(result)


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
    except (OSError, zipfile.BadZipFile) as error:
        raise SplitError(f"cannot read {app}: {error}") from error


def _binary_name(descriptor: str) -> str:
    """Converts a type descriptor to a binary class name: ``Lcom/a/B$C;`` gives ``com.a.B$C``."""
    if len(descriptor) < 2 or descriptor[0] != "L" or descriptor[-1] != ";":
        raise SplitError(f"not a class descriptor: {descriptor!r}")
    return descriptor[1:-1].replace("/", ".")

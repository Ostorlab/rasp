"""Read an R8/ProGuard mapping file and find the app's own classes by their obfuscated names.

R8, the shrinker a release Android build runs, renames classes and can move them out of the app's
package into generated packages such as ``Y2`` or ``o3``. After that the name of a class in the dex no
longer tells app code from library code, so the packer can no longer pick the app's own ("business")
classes by their package alone (see ``rasp_packer.android.split``). The build writes a mapping file
that records, for every class it kept, the original name and the obfuscated name the class now has in
the dex. This module reads that file so the packer can map the app's package back onto the obfuscated
names.

The file has one line per class::

    original.Name -> obfuscated.Name:

with the class's members (fields and methods) on indented lines under it. Only the class lines are
read; the member lines are ignored. Nested classes (``Outer$Inner``) have their own class line and are
read like any other class. A class R8 removed is written as ``original.Name -> R8$$REMOVED$$CLASS$$<n>:``;
it is not in the dex, so it is skipped: were it kept, its obfuscated name has no package and would wrongly
mark the dex's default package as business.

What this module returns is the set of obfuscated *packages* that hold at least one of the app's own
classes, not the single class names. The splitter protects those packages whole: two classes of one
Java package that end up in different class loaders cannot reach each other's package-private members,
so a package must stay in one place. A generated package that mixes app and library classes is
therefore protected as a whole, which encrypts the library classes in it too (see
``rasp_packer.android.split`` for why this is the safe choice).
"""

import collections.abc
import dataclasses
import re

from rasp_packer import errors

# A class line: ``original -> obfuscated:``. Member lines are indented, so they do not match.
_CLASS_LINE = re.compile(r"^(?P<original>\S+) -> (?P<obfuscated>\S+):$")

# The obfuscated name R8 gives a class it removed. Such a class is not in the dex.
_REMOVED = re.compile(r"^R8\$\$REMOVED\$\$CLASS\$\$[0-9]+$")


class MappingError(errors.Error):
    """The R8/ProGuard mapping file cannot be read."""


@dataclasses.dataclass(frozen=True, slots=True)
class ClassMapping:
    """The class renames read from an R8/ProGuard mapping file.

    Attributes:
        renames: The obfuscated binary name of each kept class, by its original binary name, such as
            ``{"app.alkahf.MainActivity": "app.alkahf.MainActivity", "app.alkahf.audio.AyahPlayer":
            "X2.c"}``. Classes R8 removed are left out.
    """

    renames: collections.abc.Mapping[str, str]

    def business_packages(self, package: str) -> frozenset[str]:
        """The obfuscated packages that hold at least one class under the app's package.

        A class is the app's own ("business") when its *original* binary name starts with ``package``
        plus a dot, the same rule the package-based split uses without a mapping. Its package is taken
        from its *obfuscated* name, because that is the name the class has in the dex.

        Args:
            package: The app's package, such as ``app.alkahf``.

        Returns:
            The obfuscated packages, in binary form, such as ``{"Y2", "o3", "app.alkahf"}``. The
            default (unnamed) package is the empty string. Empty when no kept class is under
            ``package``.
        """
        prefix = f"{package}."
        return frozenset(
            _package(obfuscated)
            for original, obfuscated in self.renames.items()
            if original.startswith(prefix)
        )


def parse(text: str) -> ClassMapping:
    """Reads the class renames from the text of an R8/ProGuard mapping file.

    It reads every class line and ignores comment lines, blank lines, the indented member lines, and
    classes R8 removed. A non-comment, non-indented line that is not a class line is skipped: an app
    class dropped this way ships in the clear, which is safe, rather than breaking the pack.

    Args:
        text: The contents of the mapping file.

    Returns:
        The class renames.
    """
    renames: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) == 0 or line[0].isspace() is True or line[0] == "#":
            continue
        match = _CLASS_LINE.fullmatch(line)
        if match is None or _REMOVED.fullmatch(match["obfuscated"]) is not None:
            continue
        renames[match["original"]] = match["obfuscated"]
    return ClassMapping(renames=renames)


def _package(binary_name: str) -> str:
    """The package of a binary class name: ``W2.a`` gives ``W2`` and ``a`` gives the empty string."""
    return binary_name.rpartition(".")[0]

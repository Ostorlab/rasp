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
import io
import os
import pathlib
import re
import stat
import types

from dexsplit import _dex
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

    def __post_init__(self) -> None:
        if len(self.renames) > _MAX_RECORDS:
            raise MappingError("mapping exceeds 1000000 class records")
        total = 0
        for source, target in self.renames.items():
            try:
                total += len(source.encode("utf-8")) + len(target.encode("utf-8")) + 6
            except UnicodeError as error:
                raise MappingError("mapping class name is not UTF-8") from error
            if (
                total > _MAX_BYTES
                or _dex.valid_class_name(source) is False
                or _dex.valid_class_name(target) is False
            ):
                raise MappingError("invalid or oversized mapping class names")
        object.__setattr__(self, "renames", types.MappingProxyType(dict(self.renames)))

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
        _dex.charge(work=len(self.renames), storage=len(self.renames) * 48)
        prefix = f"{package}."
        return frozenset(
            _package(obfuscated)
            for original, obfuscated in self.renames.items()
            if original.startswith(prefix)
        )


_MAX_BYTES = 64 * 1024 * 1024
_MAX_LINE_BYTES = 65536
_MAX_RECORDS = 1000000


def read(path: pathlib.Path) -> ClassMapping:
    """Read a regular mapping file with bounds before reads and strict UTF-8 decoding."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if stat.S_ISREG(metadata.st_mode) is False or metadata.st_size > _MAX_BYTES:
                raise MappingError("mapping must be a regular file of at most 64 MiB")

            def lines() -> collections.abc.Iterator[str]:
                total = 0
                while True:
                    line = source.readline(_MAX_LINE_BYTES + 1)
                    if len(line) == 0:
                        return
                    total += len(line)
                    if total > _MAX_BYTES or len(line) > _MAX_LINE_BYTES:
                        raise MappingError(
                            "mapping byte/line compatibility limit exceeded"
                        )
                    yield line.decode("utf-8")

            return _parse_lines(lines())
    except (OSError, UnicodeError) as error:
        raise MappingError(f"cannot read mapping {path}: {error}") from error


def parse(text: str) -> ClassMapping:
    """Parse bounded class records; malformed supplied mappings never silently weaken selection."""
    try:
        if len(text) > _MAX_BYTES or len(text.encode("utf-8")) > _MAX_BYTES:
            raise MappingError("mapping exceeds 64 MiB compatibility limit")
        return _parse_lines(io.StringIO(text))
    except UnicodeError as error:
        raise MappingError(f"mapping is not valid UTF-8: {error}") from error


def _parse_lines(lines: collections.abc.Iterable[str]) -> ClassMapping:
    renames: dict[str, str] = {}
    records = 0
    for number, raw_line in enumerate(lines, 1):
        if len(raw_line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise MappingError(f"mapping line {number} exceeds 65536 bytes")
        line = raw_line.rstrip("\r\n")
        if number == 1:
            line = line.removeprefix("\ufeff")
        if any(ord(character) < 32 and character != "\t" for character in line):
            raise MappingError(f"mapping line {number} has control characters")
        if len(line) == 0 or line[0].isspace() is True or line[0] == "#":
            continue
        match = _CLASS_LINE.fullmatch(line)
        if match is None:
            raise MappingError(f"malformed mapping class record at line {number}")
        _dex.charge(work=1, storage=len(raw_line.encode("utf-8")) * 2 + 128)
        records += 1
        if records > _MAX_RECORDS:
            raise MappingError("mapping exceeds 1000000 class records")
        original, target = match["original"], match["obfuscated"]
        if _dex.valid_class_name(original) is False:
            raise MappingError(f"invalid original class name at mapping line {number}")
        if _REMOVED.fullmatch(target) is not None:
            continue
        if _dex.valid_class_name(target) is False:
            raise MappingError(f"invalid target class name at mapping line {number}")
        previous = renames.get(original)
        if previous is not None and previous != target:
            raise MappingError(f"conflicting mapping for {original}")
        renames[original] = target
    return ClassMapping(renames=renames)


def _package(binary_name: str) -> str:
    """The package of a binary class name: ``W2.a`` gives ``W2`` and ``a`` gives the empty string."""
    return binary_name.rpartition(".")[0]

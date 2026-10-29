"""The seam over the dex splitter: sort an app's classes into framework and business dexes.

The on-demand packer keeps the app's framework and library code in the clear and encrypts only the
app's own ("business") code, one dex at a time, served on demand. Telling the two apart, and
regrouping the classes into dex files that each load on their own, is the job of ``split-dex``
(https://github.com/burogurama/split-dex). The packer ships the prebuilt ``split-dex`` tool inside
itself, next to the stub dex and the runtime libraries, and runs it as a subprocess; this module is
the only place that calls it, so swapping it for another splitter later touches only this file.

A class is business when its binary name is under the app's package, framework otherwise. The
splitter keeps every Java package of the business code whole in one dex: two business classes in the
same package but in different encrypted dexes would be defined by different class loaders, and
package-private access between them would be refused at run time. The framework code is not encrypted
and not regrouped; it stays in the dex files it came from, in the clear.

The bundled tool is used by default. The ``RASP_SPLIT_DEX`` environment variable overrides it with
the path of another ``split-dex`` build, for local development.
"""

import collections.abc
import contextlib
import csv
import dataclasses
import os
import pathlib
import subprocess
import tempfile
import zipfile

from rasp_packer import errors
from rasp_packer.android import resources as resources_module

# The set names handed to the splitter; they appear in its sets.csv.
_BUSINESS_SET = "business"
_FRAMEWORK_SET = "framework"

# The asset subfolder, under assets/, that each encrypted business dex lives in.
BUSINESS_DIRECTORY = "business"

# The environment variable that overrides the bundled tool with another split-dex build.
SPLIT_DEX_ENV = "RASP_SPLIT_DEX"


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

    It runs the bundled ``split-dex`` tool, which sorts every class whose binary name is under
    ``package`` into the business set and the rest into the framework set. It regroups the business
    set into dex files with every Java package kept whole, keeps the framework set in the dex files it
    came from, and writes the dex files and their maps to a temporary directory.

    Args:
        app: The app's APK.
        package: The app's package, such as ``com.example``. Its classes are the business code.

    Returns:
        The framework dexes in load order, and the business dexes with the classes each defines.

    Raises:
        SplitError: The ``split-dex`` tool is missing, fails, or writes output that can't be read.
    """
    return _run_split_dex(app, package, label=str(app))


def split_from_dex_entries(
    dex_entries: collections.abc.Mapping[str, bytes], package: str
) -> Split:
    """Splits classes from pre-extracted DEX entries (e.g. from an AAB).

    The ``split-dex`` tool expects an APK (a ZIP with root-level DEX files).
    This function writes the given entries into a temporary ZIP so the tool can
    read them unchanged.  The keys must be root-level DEX names such as
    ``classes.dex``, ``classes2.dex``, etc.

    Args:
        dex_entries: A mapping of DEX file names to their bytes.
        package: The app's package, such as ``com.example``.

    Returns:
        The framework dexes in load order, and the business dexes with the classes each defines.

    Raises:
        SplitError: The ``split-dex`` tool is missing, fails, or writes output that can't be read.
    """
    if len(dex_entries) == 0:
        raise SplitError("no DEX entries to split")
    with tempfile.TemporaryDirectory(prefix="rasp-aab-dex-") as dex_dir:
        fake_apk = pathlib.Path(dex_dir) / "classes.zip"
        with zipfile.ZipFile(fake_apk, "w") as zf:
            for name, data in dex_entries.items():
                zf.writestr(name, data)
        return _run_split_dex(fake_apk, package, label="AAB DEX entries")


def _run_split_dex(apk: pathlib.Path, package: str, *, label: str) -> Split:
    """Run the ``split-dex`` tool on *apk* and return the parsed output."""
    with _tool() as tool, tempfile.TemporaryDirectory(prefix="rasp-split-") as work:
        out = pathlib.Path(work)
        argv = [
            str(tool),
            "--apk",
            str(apk),
            "--out",
            str(out),
            "--set",
            f"{_BUSINESS_SET}=package-affinity",
            "--set",
            f"{_FRAMEWORK_SET}=original",
            "--assign",
            f"{package}.**={_BUSINESS_SET}",
            "--assign",
            f"**={_FRAMEWORK_SET}",
        ]
        try:
            subprocess.run(argv, check=True, capture_output=True)
        except subprocess.CalledProcessError as error:
            detail = error.stderr.decode("utf-8", "replace").strip()
            raise SplitError(f"split-dex failed on {label}: {detail}") from error
        return read_output(out)


@contextlib.contextmanager
def _tool() -> collections.abc.Iterator[pathlib.Path]:
    """Yields the split-dex executable: the RASP_SPLIT_DEX override, or the bundled tool."""
    override = os.environ.get(SPLIT_DEX_ENV)
    if override is not None and len(override) > 0:
        path = pathlib.Path(override)
        if path.is_file() is False:
            raise SplitError(f"{SPLIT_DEX_ENV} points at no file: {path}")
        yield path
        return
    try:
        with resources_module.split_dex_tool() as path:
            yield path
    except errors.MissingPackerToolError as error:
        raise SplitError(
            f"the split-dex tool is not bundled in this build; set {SPLIT_DEX_ENV} to a split-dex "
            "executable, or use a release build"
        ) from error


def read_output(out: pathlib.Path) -> Split:
    """Reads a splitter output directory into a Split.

    Args:
        out: The splitter's output directory, holding the dex files, index.csv and sets.csv.

    Returns:
        The framework dexes in file order, and the business dexes with their classes.

    Raises:
        SplitError: A map file or a dex file is missing or cannot be read.
    """
    set_of_file = _read_sets(out / "sets.csv")
    classes_of_file = _read_index(out / "index.csv")
    framework_files = sorted(
        (name for name, group in set_of_file.items() if group == _FRAMEWORK_SET),
        key=_dex_file_number,
    )
    business_files = sorted(
        (name for name, group in set_of_file.items() if group == _BUSINESS_SET),
        key=_dex_file_number,
    )
    framework = tuple(_read_dex(out / name) for name in framework_files)
    business = tuple(
        BusinessDex(
            path=f"{BUSINESS_DIRECTORY}/{index}.dex",
            data=_read_dex(out / name),
            classes=tuple(classes_of_file.get(name, ())),
        )
        for index, name in enumerate(business_files)
    )
    return Split(framework=framework, business=business)


def _read_sets(path: pathlib.Path) -> dict[str, str]:
    """Reads sets.csv into the set name of each dex file."""
    rows = _read_csv(path, ("file", "set"))
    return {row["file"]: row["set"] for row in rows}


def _read_index(path: pathlib.Path) -> dict[str, list[str]]:
    """Reads index.csv into the binary class names of each dex file, in file order."""
    classes: dict[str, list[str]] = {}
    for row in _read_csv(path, ("class", "file")):
        classes.setdefault(row["file"], []).append(_binary_name(row["class"]))
    return classes


def _read_csv(
    path: pathlib.Path, header: collections.abc.Sequence[str]
) -> list[dict[str, str]]:
    """Reads a splitter CSV, checking its header."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SplitError(f"cannot read {path.name}: {error}") from error
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames != list(header):
        raise SplitError(f"{path.name} has an unexpected header: {reader.fieldnames}")
    return list(reader)


def _read_dex(path: pathlib.Path) -> bytes:
    """Reads one dex file the splitter wrote."""
    try:
        return path.read_bytes()
    except OSError as error:
        raise SplitError(f"cannot read split dex {path.name}: {error}") from error


def _binary_name(descriptor: str) -> str:
    """Converts a type descriptor to a binary class name: ``Lcom/a/B$C;`` gives ``com.a.B$C``."""
    if len(descriptor) < 2 or descriptor[0] != "L" or descriptor[-1] != ";":
        raise SplitError(f"not a class descriptor: {descriptor!r}")
    return descriptor[1:-1].replace("/", ".")


def _dex_file_number(name: str) -> int:
    """The numeric order of a splitter dex file name, such as 3 for ``3.dex``."""
    stem = name.removesuffix(".dex")
    if not stem.isdigit():
        raise SplitError(f"not a split dex file name: {name!r}")
    return int(stem)

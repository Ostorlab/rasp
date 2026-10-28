"""Reading an AAB and writing a repacked one.

An AAB (Android App Bundle) is a ZIP file with a different directory layout than
an APK. Google Play converts it to APK splits before installing on a device, so
the runtime always sees APKs. The packer only needs to handle the AAB structure
at pack time.

Key differences from an APK:

- DEX files live under ``base/dex/`` instead of the ZIP root.
- The manifest is at ``base/manifest/AndroidManifest.xml`` in Protocol Buffer
  format, not binary AXML.
- Native libraries are at ``base/lib/<abi>/`` instead of ``lib/<abi>/``.
- Assets are at ``base/assets/`` instead of ``assets/``.
- No zipalign is needed: Google Play handles alignment when generating APK splits.
- Metadata files (``BundleConfig.pb``, ``base/resources.pb``) must be preserved
  but the packer does not modify them.

Like the APK archive, this reads all entries into memory and writes a new AAB
with some entries replaced, added or removed. Each kept entry keeps its original
compression. The output is unsigned; the customer signs it.
"""

import collections
import collections.abc
import dataclasses
import pathlib
import re
import zipfile
import zlib
from typing import Self

from rasp_packer import errors

MANIFEST_ENTRY = "base/manifest/AndroidManifest.xml"

_BASE_PREFIX = "base/"
_DEX_DIRECTORY = "base/dex/"
_DEX_PREFIX = "classes"
_DEX_SUFFIX = ".dex"
_FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
_ANDROID_COMPRESSION_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_DEX_NUMBER = re.compile(r"[2-9]|[1-9][0-9]+")
_READ_ERRORS = (
    zipfile.BadZipFile,
    OSError,
    RuntimeError,
    NotImplementedError,
    zlib.error,
    EOFError,
)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Entry:
    """One entry in the AAB.

    Attributes:
        name: The entry path inside the AAB.
        data: The entry bytes.
        compressed: Whether the entry was stored compressed.
    """

    name: str
    data: bytes
    compressed: bool


class Aab:
    """An AAB read into memory."""

    def __init__(self, entries: collections.abc.Sequence[Entry]) -> None:
        """Holds the entries of an AAB.

        Args:
            entries: The AAB's entries, in their order in the archive. Their
                names are unique.
        """
        self._entries = list(entries)
        self._by_name = {entry.name: entry for entry in self._entries}

    @classmethod
    def read(cls, path: pathlib.Path) -> Self:
        """Reads an AAB from disk.

        Args:
            path: The AAB file.

        Returns:
            The AAB.

        Raises:
            InvalidAabError: The file is not a valid ZIP, two entries share a
                name, an entry uses a compression method Android can't read,
                or the entries hold more than 1 GiB once uncompressed.
        """
        try:
            with zipfile.ZipFile(path) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                _check_entries(infos)
                entries = [
                    Entry(
                        name=info.filename,
                        data=archive.read(info),
                        compressed=info.compress_type != zipfile.ZIP_STORED,
                    )
                    for info in infos
                ]
        except _READ_ERRORS as error:
            raise errors.InvalidAabError(f"cannot read AAB {path}: {error}") from error
        return cls(entries)

    def names(self) -> list[str]:
        """Returns the names of all entries, in their original order."""
        return [entry.name for entry in self._entries]

    def get(self, name: str) -> bytes | None:
        """Returns the bytes of an entry, or None if it is absent."""
        entry = self._by_name.get(name)
        if entry is None:
            return None
        return entry.data

    def manifest(self) -> bytes:
        """Returns the Protocol Buffer AndroidManifest.xml.

        Raises:
            InvalidAabError: The AAB has no manifest.
        """
        data = self.get(MANIFEST_ENTRY)
        if data is None:
            raise errors.InvalidAabError(f"AAB has no {MANIFEST_ENTRY}")
        return data

    def dex_names(self) -> list[str]:
        """Returns the names of the app's dex entries under base/dex/, in load order.

        The load order is base/dex/classes.dex, base/dex/classes2.dex and so on.
        """
        names = [entry.name for entry in self._entries if _is_dex(entry.name)]
        return sorted(names, key=_dex_order)

    def write(
        self,
        path: pathlib.Path,
        *,
        replace: collections.abc.Mapping[str, bytes],
        add: collections.abc.Mapping[str, bytes],
        remove: collections.abc.Set[str],
    ) -> None:
        """Writes a repacked AAB.

        No zipalign is applied: Google Play handles alignment when generating
        APK splits from the AAB.

        Args:
            path: Where to write the new AAB.
            replace: Entries to overwrite, by name. They keep their position and
                their original compression.
            add: New entries, by name. They are stored without compression. An
                entry whose name already exists overwrites it in place.
            remove: Names of entries to drop.
        """
        final: list[tuple[str, bytes, int]] = []
        position: dict[str, int] = {}
        for entry in self._entries:
            if entry.name in remove:
                continue
            data = replace.get(entry.name, entry.data)
            compression = (
                zipfile.ZIP_DEFLATED if entry.compressed else zipfile.ZIP_STORED
            )
            position[entry.name] = len(final)
            final.append((entry.name, data, compression))
        for name, data in add.items():
            if name in position:
                index = position[name]
                final[index] = (name, data, final[index][2])
            else:
                position[name] = len(final)
                final.append((name, data, zipfile.ZIP_STORED))
        with zipfile.ZipFile(path, "w") as archive:
            for name, data, compression in final:
                info = zipfile.ZipInfo(name, date_time=_FIXED_TIMESTAMP)
                info.compress_type = compression
                archive.writestr(info, data)


def _check_entries(infos: collections.abc.Sequence[zipfile.ZipInfo]) -> None:
    """Refuses entries that share a name, use a method Android can't read, or are too big once uncompressed."""
    counts = collections.Counter(info.filename for info in infos)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if len(duplicates) > 0:
        raise errors.InvalidAabError(f"AAB has duplicate entries: {duplicates}")
    unreadable = sorted(
        info.filename
        for info in infos
        if info.compress_type not in _ANDROID_COMPRESSION_METHODS
    )
    if len(unreadable) > 0:
        raise errors.InvalidAabError(
            f"AAB has entries Android can't decompress: {unreadable}"
        )
    if sum(info.file_size for info in infos) > _MAX_UNCOMPRESSED_BYTES:
        raise errors.InvalidAabError(
            f"AAB holds more than {_MAX_UNCOMPRESSED_BYTES} bytes once uncompressed"
        )


def _is_dex(name: str) -> bool:
    """Returns whether an entry is a DEX file under base/dex/: base/dex/classes.dex, then base/dex/classesN.dex with N from 2."""
    if not name.startswith(_DEX_DIRECTORY):
        return False
    basename = name[len(_DEX_DIRECTORY) :]
    if (
        "/" in basename
        or not basename.startswith(_DEX_PREFIX)
        or not basename.endswith(_DEX_SUFFIX)
    ):
        return False
    middle = basename[len(_DEX_PREFIX) : len(basename) - len(_DEX_SUFFIX)]
    return len(middle) == 0 or _DEX_NUMBER.fullmatch(middle) is not None


def _dex_order(name: str) -> int:
    """Returns the position Android loads a dex file in, comparing its number numerically."""
    basename = name[len(_DEX_DIRECTORY) :]
    middle = basename[len(_DEX_PREFIX) : len(basename) - len(_DEX_SUFFIX)]
    if len(middle) == 0:
        return 1
    return int(middle)

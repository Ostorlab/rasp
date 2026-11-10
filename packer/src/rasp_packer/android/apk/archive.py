"""Reading an APK and writing a repacked one.

An APK is a ZIP file. This reads all its entries into memory and writes a new
APK with some entries replaced, added or removed. Each kept entry keeps its
original compression, so entries that must stay stored (resources.arsc on recent
Android) are not recompressed.

The APK comes from a customer, so it is checked before anything is read: its
entries must have unique names, use a compression method Android can read
(stored or deflated), and hold at most 1 GiB once uncompressed. That last limit
keeps a small, highly compressed file from filling the memory.

Stored entries are aligned the way zipalign aligns them, so the APK works once
signed without a separate alignment step: a native library (.so) starts on a
16 KB page boundary and any other stored entry on a 4-byte boundary. A native
library in an app with ``android:extractNativeLibs="false"`` is mapped straight
from the APK, so it must be page-aligned or it cannot load. The output is
unsigned; the customer signs it.
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

MANIFEST_ENTRY = "AndroidManifest.xml"

_DEX_PREFIX = "classes"
_DEX_SUFFIX = ".dex"
_SO_SUFFIX = ".so"
_DEFAULT_ALIGNMENT = 4
_SO_ALIGNMENT = 16384
_LOCAL_HEADER_SIZE = 30
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
    """One entry in the APK.

    Attributes:
        name: The entry path inside the APK.
        data: The entry bytes.
        compressed: Whether the entry was stored compressed.
        compressed_size: The size of the compressed bytes in the APK, equal to the data size when stored.
    """

    name: str
    data: bytes
    compressed: bool
    compressed_size: int


class Apk:
    """An APK read into memory."""

    def __init__(self, entries: collections.abc.Sequence[Entry]) -> None:
        """Holds the entries of an APK.

        Args:
            entries: The APK's entries, in their order in the archive. Their
                names are unique.
        """
        self._entries = list(entries)
        self._by_name = {entry.name: entry for entry in self._entries}

    @classmethod
    def read(cls, path: pathlib.Path) -> Self:
        """Reads an APK from disk.

        Args:
            path: The APK file.

        Returns:
            The APK.

        Raises:
            InvalidApkError: The file is not a valid ZIP, two entries share a
                name, an entry uses a compression method Android can't read,
                the entries hold more than 1 GiB once uncompressed, or an entry
                can't be read (encrypted, corrupt or cut short).
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
                        compressed_size=info.compress_size,
                    )
                    for info in infos
                ]
        except _READ_ERRORS as error:
            raise errors.InvalidApkError(f"cannot read APK {path}: {error}") from error
        return cls(entries)

    def names(self) -> list[str]:
        """Returns the names of all entries, in their original order."""
        return [entry.name for entry in self._entries]

    def stored_entries(self) -> dict[str, bytes]:
        """Returns the stored (uncompressed) entries by name."""
        return {
            entry.name: entry.data for entry in self._entries if not entry.compressed
        }

    def get(self, name: str) -> bytes | None:
        """Returns the bytes of an entry, or None if it is absent."""
        entry = self._by_name.get(name)
        if entry is None:
            return None
        return entry.data

    def manifest(self) -> bytes:
        """Returns the binary AndroidManifest.xml.

        Raises:
            InvalidApkError: The APK has no manifest.
        """
        data = self.get(MANIFEST_ENTRY)
        if data is None:
            raise errors.InvalidApkError(f"APK has no {MANIFEST_ENTRY}")
        return data

    def dex_names(self) -> list[str]:
        """Returns the names of the app's dex entries, in load order.

        The load order is classes.dex, classes2.dex, classes3.dex and so on.
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
        """Writes a repacked APK.

        Args:
            path: Where to write the new APK.
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
                # An added entry always ships stored: the key schedule binds its content, and a
                # stored entry is readable without an inflate step.
                final[index] = (name, data, zipfile.ZIP_STORED)
            else:
                position[name] = len(final)
                final.append((name, data, zipfile.ZIP_STORED))
        with zipfile.ZipFile(path, "w") as archive:
            for name, data, compression in final:
                _write_entry(archive, name, data, compression)


def _check_entries(infos: collections.abc.Sequence[zipfile.ZipInfo]) -> None:
    """Refuses entries that share a name, use a method Android can't read, or are too big once uncompressed."""
    counts = collections.Counter(info.filename for info in infos)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if len(duplicates) > 0:
        raise errors.InvalidApkError(f"APK has duplicate entries: {duplicates}")
    unreadable = sorted(
        info.filename
        for info in infos
        if info.compress_type not in _ANDROID_COMPRESSION_METHODS
    )
    if len(unreadable) > 0:
        raise errors.InvalidApkError(
            f"APK has entries Android can't decompress: {unreadable}"
        )
    if sum(info.file_size for info in infos) > _MAX_UNCOMPRESSED_BYTES:
        raise errors.InvalidApkError(
            f"APK holds more than {_MAX_UNCOMPRESSED_BYTES} bytes once uncompressed"
        )


def _write_entry(
    archive: zipfile.ZipFile, name: str, data: bytes, compression: int
) -> None:
    """Writes one entry, padding a stored entry so its data starts aligned."""
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIMESTAMP)
    info.compress_type = compression
    if compression == zipfile.ZIP_STORED:
        stream = archive.fp
        assert stream is not None
        info.extra = _alignment_padding(stream.tell(), name)
    archive.writestr(info, data)


def _alignment_padding(offset: int, name: str) -> bytes:
    """Returns the extra-field padding that aligns an entry's data: 16 KB for a .so, else 4 bytes."""
    alignment = _SO_ALIGNMENT if name.endswith(_SO_SUFFIX) else _DEFAULT_ALIGNMENT
    header_end = offset + _LOCAL_HEADER_SIZE + len(name.encode("utf-8"))
    return b"\x00" * ((alignment - header_end % alignment) % alignment)


def _is_dex(name: str) -> bool:
    """Returns whether an entry is app code Android loads: classes.dex, then classesN.dex with N from 2, at the APK root."""
    if (
        "/" in name
        or not name.startswith(_DEX_PREFIX)
        or not name.endswith(_DEX_SUFFIX)
    ):
        return False
    middle = name[len(_DEX_PREFIX) : len(name) - len(_DEX_SUFFIX)]
    return len(middle) == 0 or _DEX_NUMBER.fullmatch(middle) is not None


def _dex_order(name: str) -> int:
    """Returns the position Android loads a dex file in, comparing its number numerically."""
    middle = name[len(_DEX_PREFIX) : len(name) - len(_DEX_SUFFIX)]
    if len(middle) == 0:
        return 1
    return int(middle)

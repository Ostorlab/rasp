"""An up-front safety check on a built app before the packer opens it.

APKs, AABs and IPAs are all ZIP archives. A crafted archive can carry an entry that is encrypted, a
symbolic link, or whose name escapes the directory it is extracted into (an absolute path or a ``..``
segment), which a packer step that extracts entries to disk by their name could follow outside its
workspace (a "Zip Slip"). The packer refuses such an archive, and one that cannot be read, before any
platform handling, the way the reporting engine screens an uploaded archive before extracting it.
"""

import pathlib
import stat
import zipfile
import zlib

# What reading a corrupt, truncated or crafted archive can raise, mirroring android/apk/archive.py,
# plus ValueError for an undecodable entry name. A file that passed is_zipfile but then fails to open
# or list is treated as dangerous: the packer must not work on it.
_READ_ERRORS = (
    zipfile.BadZipFile,
    OSError,
    RuntimeError,
    NotImplementedError,
    zlib.error,
    EOFError,
    ValueError,
)


def is_dangerous(app: pathlib.Path) -> bool:
    """Returns whether the app archive is unsafe to extract, so the packer must refuse it.

    Args:
        app: Path to the built app: an APK, AAB or IPA.

    Returns:
        True when the file is a zip with a member that is encrypted, a symbolic link, or whose name
        escapes the archive root, or a zip that cannot be read. False when the archive is safe, or
        the file is not a zip: the platform packer reports that the app is invalid.
    """
    if zipfile.is_zipfile(app) is False:
        return False
    try:
        with zipfile.ZipFile(app) as archive:
            return any(_is_member_dangerous(info) for info in archive.infolist())
    except _READ_ERRORS:
        return True


def _is_member_dangerous(info: zipfile.ZipInfo) -> bool:
    """Returns whether a zip member is encrypted, a symbolic link, or escapes the archive root."""
    if info.flag_bits & 0x1 != 0:
        return True
    if stat.S_ISLNK(info.external_attr >> 16) is True:
        return True
    return _is_unsafe_path(info.filename)


def _is_unsafe_path(name: str) -> bool:
    """Returns whether a member name is absolute or traverses outside the root.

    Rejects POSIX, Windows and UNC absolute paths and any ``..`` traversal segment.
    """
    if pathlib.PureWindowsPath(name).is_absolute() is True:
        return True
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") is True:
        return True
    return ".." in pathlib.PurePosixPath(normalized).parts

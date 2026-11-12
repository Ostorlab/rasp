"""An up-front safety check on a built app before the packer opens it.

APKs, AABs and IPAs are all ZIP archives. A crafted archive can carry an entry whose name escapes the
directory it is extracted into (a ``..`` component or an absolute path), uses a backslash separator,
or is a symbolic link. A packer step that extracts entries to disk by their name could then write or
read outside its workspace (a "Zip Slip"). The packer refuses such an archive before any platform
handling, so the rest of the packer never works on a dangerous app.
"""

import pathlib
import stat
import zipfile

# What opening the file as a zip raises when it is not a readable archive. Such a file is not
# dangerous here: the platform packer reports why it is not a valid app.
_NOT_A_ZIP = (zipfile.BadZipFile, OSError)


def is_dangerous(app: pathlib.Path) -> bool:
    """Returns whether the app archive holds an entry that is unsafe to extract.

    An entry is unsafe when its name escapes the archive root, by an absolute path, a ``..``
    component or a backslash separator, or when it is a symbolic link.

    Args:
        app: Path to the built app: an APK, AAB or IPA.

    Returns:
        True when any entry is unsafe. False when the archive is safe, or when the file is not a
        readable zip archive: the platform packer reports that the app is invalid.
    """
    try:
        with zipfile.ZipFile(app) as archive:
            entries = archive.infolist()
    except _NOT_A_ZIP:
        return False
    return any(_is_entry_dangerous(entry) is True for entry in entries)


def _is_entry_dangerous(entry: zipfile.ZipInfo) -> bool:
    """Returns whether one archive entry escapes the archive root or is a symbolic link."""
    name = entry.filename
    if "\\" in name:
        return True
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() is True:
        return True
    if ".." in path.parts:
        return True
    return stat.S_ISLNK(entry.external_attr >> 16) is True

"""Errors of the packer."""


class Error(Exception):
    """Base error of the packer."""


class UnsupportedPlatformError(Error):
    """The packer cannot pack apps of this platform."""


class OutputExistsError(Error):
    """The path to write the protected app to already exists."""


class InvalidAppError(Error):
    """The app file cannot be read, or is not a well-formed archive of a single app."""


class UnsupportedBinaryError(Error):
    """The app's executable cannot be protected: not an arm64 Mach-O, or encrypted."""


class HeaderPaddingError(UnsupportedBinaryError):
    """The new load commands do not fit in the free space after the executable's load commands."""


class AlreadyProtectedError(Error):
    """The app already loads the runtime."""


class InvalidRuntimeError(Error):
    """The runtime to add is missing or malformed."""

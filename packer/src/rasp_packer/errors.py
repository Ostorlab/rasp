"""Errors of the packer."""


class Error(Exception):
    """Base error of the packer."""


class UnsupportedPlatformError(Error):
    """The packer cannot pack apps of this platform."""

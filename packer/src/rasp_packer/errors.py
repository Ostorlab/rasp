"""Errors of the packer."""


class Error(Exception):
    """Base error of the packer."""


class InvalidApkError(Error):
    """The app is not a valid APK, or is missing something the packer needs."""


class InvalidAabError(Error):
    """The app is not a valid AAB, or is missing something the packer needs."""


class ManifestError(Error):
    """The app's AndroidManifest.xml cannot be read or edited."""


class InvalidBuildIdError(Error):
    """The build id cannot be written into the app."""


class MissingRuntimeArtifactError(Error):
    """A prebuilt runtime artifact the packer needs is not present."""


class MissingPackerToolError(Error):
    """A tool the packer bundles and runs is not present in this build."""


class UnsupportedAbiError(Error):
    """The app ships native libraries for an ABI the runtime is not built for."""


class OutputExistsError(Error):
    """The path to write the protected app to already exists."""


class InvalidAppError(Error):
    """The app file cannot be read, or is not a well-formed archive of a single app."""


class DangerousAppError(Error):
    """The app archive holds an unsafe entry (encrypted, a symlink, or escaping the root), or cannot be read."""


class UnsupportedBinaryError(Error):
    """The app's executable cannot be protected: not an arm64 Mach-O, or encrypted."""


class HeaderPaddingError(UnsupportedBinaryError):
    """The new load commands do not fit in the free space after the executable's load commands."""


class AlreadyProtectedError(Error):
    """The app already loads the runtime."""


class InvalidRuntimeError(Error):
    """The runtime to add is missing or malformed."""


class ConfigTooLargeError(Error):
    """The runtime's config does not fit in the space the runtime's binary keeps for it."""


class VerificationError(Error):
    """Packed output does not satisfy its required protection artifact contract."""

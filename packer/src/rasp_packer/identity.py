"""The identity of an app, read from the app itself."""

import dataclasses

from rasp_packer import capabilities


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AppIdentity:
    """Who an app is and which version of it was packed.

    Attributes:
        package_name: The app's package name: the bundle identifier on iOS.
        version: The app's version as users see it: the short version string on iOS.
        effective_checks: Optional packing metadata; groups actually written into config.
        bindings: Optional packing metadata for pristine injected artifacts, or None when unknown.
            Metadata does not affect established identity equality or hashing.
    """

    package_name: str
    version: str

    effective_checks: tuple[str, ...] = dataclasses.field(
        default=(), compare=False, repr=False
    )
    bindings: tuple[capabilities.Binding, ...] | None = dataclasses.field(
        default=None, compare=False, repr=False
    )

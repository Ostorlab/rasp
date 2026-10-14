"""The identity of an app, read from the app itself."""

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AppIdentity:
    """Who an app is and which version of it was packed.

    Attributes:
        package_name: The app's package name: the bundle identifier on iOS.
        version: The app's version as users see it: the short version string on iOS.
    """

    package_name: str
    version: str

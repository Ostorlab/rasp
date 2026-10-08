"""The platforms the packer protects apps for."""

import enum


@enum.unique
class Platform(enum.StrEnum):
    """A platform the runtime supports."""

    ANDROID = "android"
    IOS = "ios"

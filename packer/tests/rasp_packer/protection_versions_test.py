"""Tests of the protection versions."""

from rasp_packer import platforms
from rasp_packer import protection_versions


def testProtectionVersions_whenRead_hasAPositiveVersionForEveryPlatform() -> None:
    versions = protection_versions.PROTECTION_VERSIONS

    assert set(versions) == set(platforms.Platform)
    assert all(version >= 1 for version in versions.values())

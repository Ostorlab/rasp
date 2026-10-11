"""Tests of the build id."""

import uuid

from rasp_packer import build
from rasp_packer import platforms

_APPLICATION_ID = uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90")
_OTHER_APP_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
_APP_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64


def _compute(
    *,
    application_id: uuid.UUID = _APPLICATION_ID,
    app_digest: str = _APP_DIGEST,
    platform: platforms.Platform = platforms.Platform.IOS,
    protection_version: int = 1,
) -> str:
    """Computes a build id from the default inputs, with the given ones replaced."""
    return build.compute_id(
        application_id=application_id,
        app_digest=app_digest,
        platform=platform,
        protection_version=protection_version,
    )


def testComputeId_whenCalled_usesTheVersionedScheme() -> None:
    build_id = _compute()

    assert build_id.startswith("rasp-build/v1:") is True


def testComputeId_whenDefaultInputs_givesThePinnedBuildId() -> None:
    build_id = _compute()

    assert (
        build_id
        == "rasp-build/v1:4c5a32fd703008601668904390d719baca676c0de6419587e2a6dbdca40f0ab7"
    )


def testComputeId_whenSameInputs_givesTheSameBuildId() -> None:
    assert _compute() == _compute()


def testComputeId_whenAppIdChanges_givesADifferentBuildId() -> None:
    assert _compute() != _compute(application_id=_OTHER_APP_ID)


def testComputeId_whenAppDigestChanges_givesADifferentBuildId() -> None:
    assert _compute() != _compute(app_digest=_OTHER_DIGEST)


def testComputeId_whenPlatformChanges_givesADifferentBuildId() -> None:
    android = _compute(platform=platforms.Platform.ANDROID)

    assert _compute() != android


def testComputeId_whenProtectionVersionChanges_givesADifferentBuildId() -> None:
    assert _compute() != _compute(protection_version=2)

"""Tests of the packer's entry point."""

import pathlib
import uuid

import pytest

from rasp_packer import errors
from rasp_packer import packer
from rasp_packer import platforms

_RASP_APP_ID = uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90")


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testPack_whenPlatformNotAvailableYet_raisesUnsupportedPlatformError(
    platform: platforms.Platform, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.UnsupportedPlatformError, match=str(platform)):
        packer.pack(
            app=tmp_path / "app",
            platform=platform,
            output=tmp_path / "out",
            rasp_app_id=_RASP_APP_ID,
        )

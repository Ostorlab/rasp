"""Tests of the runtime's config."""

import json

from rasp_packer import runtime_config


def testToJson_whenGivenABuildId_writesAJsonObjectWithIt() -> None:
    config = runtime_config.RuntimeConfig(build_id="build-1")

    assert config.to_json() == b'{"build_id":"build-1"}'


def testToJson_whenTheBuildIdIsNotAscii_writesItInUtf8() -> None:
    config = runtime_config.RuntimeConfig(build_id='bühl "7"')

    assert json.loads(config.to_json()) == {"build_id": 'bühl "7"'}
    assert "ü".encode() in config.to_json()

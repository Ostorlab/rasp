"""Tests of the runtime config."""

from rasp_packer.android import config


def _config() -> config.RuntimeConfig:
    return config.RuntimeConfig(
        build_id="rasp-build/v1:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        key_hex="ab" * 32,
        dex_names=("classes.dex", "classes2.dex"),
    )


def testFromJson_whenGivenToJsonOutput_returnsTheSameConfig() -> None:
    original = _config()
    assert config.RuntimeConfig.from_json(original.to_json()) == original


def testToJson_whenCalled_endsWithNewline() -> None:
    assert _config().to_json().endswith("\n")

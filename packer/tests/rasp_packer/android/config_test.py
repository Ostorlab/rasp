"""Tests of the runtime config."""

from rasp_packer.android import config


def _config() -> config.RuntimeConfig:
    return config.RuntimeConfig(
        build_id="rasp-build/v1:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        key_hex="ab" * 32,
        application_class="com.example.MyApp",
        dex_names=("classes.dex", "classes2.dex"),
    )


def testToJsonFromJson_roundTrips() -> None:
    original = _config()
    assert config.RuntimeConfig.from_json(original.to_json()) == original


def testToJson_endsWithNewline() -> None:
    assert _config().to_json().endswith("\n")

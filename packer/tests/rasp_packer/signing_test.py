"""Tests for the signing hint."""

import pathlib

from rasp_packer import signing


def testNextStep_whenApk_returnsApksignerCommand() -> None:
    """An APK gets the apksigner command with the keystore and key alias."""
    hint = signing.next_step(pathlib.Path("app-protected.apk"))

    assert hint == (
        "next: sign it with apksigner sign --ks <your-keystore.jks> "
        "--ks-key-alias <key-alias> app-protected.apk"
    )


def testNextStep_whenAab_returnsJarsignerCommand() -> None:
    """An AAB gets the jarsigner command with the keystore and key alias."""
    hint = signing.next_step(pathlib.Path("app-protected.aab"))

    assert hint == (
        "next: sign it with jarsigner -keystore <your-keystore.jks> "
        "app-protected.aab <key-alias>"
    )


def testNextStep_whenIpa_returnsResignInstruction() -> None:
    """An IPA gets the re-sign instruction."""
    hint = signing.next_step(pathlib.Path("app-protected.ipa"))

    assert hint == (
        "next: re-sign app-protected.ipa with the app's distribution certificate "
        "and provisioning profile before uploading it"
    )


def testNextStep_whenUppercaseSuffix_matchesTheVariant() -> None:
    """The suffix is matched whatever its case."""
    hint = signing.next_step(pathlib.Path("APP-PROTECTED.APK"))

    assert hint is not None
    assert hint.startswith("next: sign it with apksigner sign")


def testNextStep_whenUnknownSuffix_returnsNone() -> None:
    """A suffix that is not an app format has no hint."""
    assert signing.next_step(pathlib.Path("app-protected.zip")) is None

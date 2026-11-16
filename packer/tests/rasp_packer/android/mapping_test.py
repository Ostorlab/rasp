"""Tests of the R8/ProGuard mapping reader."""

from rasp_packer.android import mapping


def testParse_whenClassLines_recordsOriginalToObfuscated() -> None:
    text = (
        "app.alkahf.MainActivity -> app.alkahf.MainActivity:\n"
        "app.alkahf.audio.AyahPlayer -> X2.c:\n"
    )

    result = mapping.parse(text)

    assert dict(result.renames) == {
        "app.alkahf.MainActivity": "app.alkahf.MainActivity",
        "app.alkahf.audio.AyahPlayer": "X2.c",
    }


def testParse_whenNestedClass_recordsItByItsOwnLine() -> None:
    text = (
        "app.alkahf.MainActivity -> W2.m:\n"
        "app.alkahf.MainActivity$onCreate$1 -> W2.j:\n"
    )

    result = mapping.parse(text)

    assert result.renames["app.alkahf.MainActivity$onCreate$1"] == "W2.j"


def testParse_whenMemberLines_ignoresThem() -> None:
    text = (
        "app.alkahf.audio.AyahPlayer -> X2.c:\n"
        "    java.lang.String url -> a\n"
        "    29:146:void play(int):0 -> b\n"
    )

    result = mapping.parse(text)

    assert dict(result.renames) == {"app.alkahf.audio.AyahPlayer": "X2.c"}


def testParse_whenCommentAndBlankLines_ignoresThem() -> None:
    text = (
        "# compiler: R8\n"
        "\n"
        "app.alkahf.MainActivity -> W2.m:\n"
        '      # {"id":"sourceFile","fileName":"MainActivity.kt"}\n'
    )

    result = mapping.parse(text)

    assert dict(result.renames) == {"app.alkahf.MainActivity": "W2.m"}


def testParse_whenClassWasRemovedByR8_skipsIt() -> None:
    text = (
        "app.alkahf.LocaleManager -> R8$$REMOVED$$CLASS$$452:\n"
        "app.alkahf.MainActivity -> W2.m:\n"
    )

    result = mapping.parse(text)

    assert dict(result.renames) == {"app.alkahf.MainActivity": "W2.m"}


def testParse_whenMalformedLine_skipsItAndKeepsTheRest() -> None:
    text = (
        "this line has no arrow and no colon\n"
        "app.alkahf.MainActivity -> W2.m:\n"
        "also -> malformed without trailing colon\n"
    )

    result = mapping.parse(text)

    assert dict(result.renames) == {"app.alkahf.MainActivity": "W2.m"}


def testParse_whenEmpty_hasNoRenames() -> None:
    result = mapping.parse("")

    assert dict(result.renames) == {}


def testBusinessPackages_whenClassesUnderPackage_returnsTheirObfuscatedPackages() -> (
    None
):
    result = mapping.parse(
        "app.alkahf.MainActivity -> W2.m:\n"
        "app.alkahf.audio.AyahPlayer -> X2.c:\n"
        "app.alkahf.audio.AyahPlayer$play$1 -> X2.a:\n"
    )

    assert result.business_packages("app.alkahf") == frozenset({"W2", "X2"})


def testBusinessPackages_whenClassKeepsItsOriginalPackage_returnsThatPackage() -> None:
    result = mapping.parse(
        "app.alkahf.data.quran.QuranDatabase -> app.alkahf.data.quran.QuranDatabase:\n"
    )

    assert result.business_packages("app.alkahf") == frozenset(
        {"app.alkahf.data.quran"}
    )


def testBusinessPackages_whenObfuscatedToDefaultPackage_returnsEmptyString() -> None:
    result = mapping.parse("app.alkahf.MainActivity -> a:\n")

    assert result.business_packages("app.alkahf") == frozenset({""})


def testBusinessPackages_whenPrefixIsNotAPackageBoundary_excludesIt() -> None:
    result = mapping.parse(
        "app.alkahf.MainActivity -> W2.m:\napp.alkahfish.Other -> Z9.a:\n"
    )

    assert result.business_packages("app.alkahf") == frozenset({"W2"})


def testBusinessPackages_whenNoClassUnderPackage_isEmpty() -> None:
    result = mapping.parse("androidx.core.Foo -> a.b:\n")

    assert result.business_packages("app.alkahf") == frozenset()

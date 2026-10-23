"""Tests of the on-demand class map text."""

from rasp_packer.android import loader_map
from rasp_packer.android import split


def testBuild_whenBusinessDexes_writesOneLinePerClassInOrder() -> None:
    business = (
        split.BusinessDex(
            path="business/0.dex", data=b"", classes=("com.example.A", "com.example.B")
        ),
        split.BusinessDex(
            path="business/1.dex", data=b"", classes=("com.example.sub.C",)
        ),
    )
    assert loader_map.build(business) == (
        "com.example.A,business/0.dex\n"
        "com.example.B,business/0.dex\n"
        "com.example.sub.C,business/1.dex\n"
    )


def testBuild_whenNoBusinessClasses_isEmpty() -> None:
    assert loader_map.build(()) == ""
    assert (
        loader_map.build(
            (split.BusinessDex(path="business/0.dex", data=b"", classes=()),)
        )
        == ""
    )

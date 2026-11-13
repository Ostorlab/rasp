"""Exact predecessor bytes and semantic rule preservation for RT19 activation."""

import hashlib
import json
import pathlib
import re
import sys


def main() -> None:
    """Validate the integrated source contract without inferring device or backend support."""
    root = pathlib.Path(sys.argv[1])
    manifest = root / "packer/src/rasp_packer/checks_manifest.json"
    current = json.loads(manifest.read_bytes())
    assert current["revision"] == 10
    for platform, count, total in (("android", 6, 79), ("ios", 2, 54)):
        spec = current["platforms"][platform]
        assert sum(len(group["observations"]) for group in spec["groups"]) == total
        hooks = next(group for group in spec["groups"] if group["name"] == "hooks")
        del hooks["observations"][-count:]
    current["revision"] = 9
    assert (
        hashlib.sha256((json.dumps(current, indent=2) + "\n").encode()).hexdigest()
        == "45e3c9b2fa72008cfbc2926d971474041c12314cdbf81b422e87ec15dc58170f"
    )
    registry = root / "runtime/core/src/decision_registry.h"
    # Exact semantic blocks from immutable HD02 67002a9; works in source archives without Git.
    blocks = re.findall(r"    \{\n.*?    \},\n", registry.read_text(), re.DOTALL)
    assert len(blocks) == 125
    assert (
        hashlib.sha256("".join(blocks).encode()).hexdigest()
        == "494678cce937a0f51a1da7ee65f2160b8a65a07226fd72692cfce7bc75ca299b"
    )
    for relative, digest in (
        (
            "runtime/ios/capture_exports.txt",
            "deab8877e301e1af609e05119a322fdc0db8ee0afa49e4bb49cb65c03a9d4936",
        ),
        (
            "runtime/android/policy_exports.map",
            "309fb8ea1f9bbd859d194fa510c6f86895a0d391795931c3c07dc2525c091ff2",
        ),
    ):
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest
    selectors = json.loads(
        (root / "packer/src/rasp_packer/local_policy_selectors_v1.json").read_bytes()
    )
    for platform, digest in (
        ("android", "4fc0472f79da9d12cd51ed776f8983e232540dbdeab3f8c4a4d4c4cde8ff1cc9"),
        ("ios", "261338bd00015151a51a0bc3f338939f76d16843231659ddbc85e4a3fec6e405"),
    ):
        selection = {
            "schema_version": 1,
            "platform": platform,
            "rules": [row for row in selectors["rules"] if row["platform"] == platform],
        }
        assert (
            hashlib.sha256(
                json.dumps(selection, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            == digest
        )
    print(
        "RT19 exact revision9 history, all semantic rules/selectors and HD02 exports verified"
    )


if __name__ == "__main__":
    main()

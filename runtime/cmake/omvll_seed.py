"""Canonical O-MVLL build input shared by configure, launcher and Python 3.10 plugin.

The seed controls part of the plugin's RNG behavior. It is not a cryptographic
key and does not establish binary reproducibility or extraction resistance.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys


class Error(ValueError):
    """Invalid seed policy; never include supplied values in diagnostics."""


@dataclasses.dataclass(frozen=True)
class SeedPolicy:
    """One captured seed and its diagnostic purpose."""

    seed: int
    mode: str


def parse_seed(value: str) -> int:
    """Accept canonical ASCII decimal in the plugin's nonnegative signed-int range."""
    if (
        type(value) is not str
        or len(value) > 10
        or re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None
    ):
        raise Error("invalid O-MVLL seed policy")
    seed = int(value)
    if seed > 2147483647:
        raise Error("invalid O-MVLL seed policy")
    return seed


def parse_policy(seed: str | None, mode: str | None) -> SeedPolicy:
    """Resolve the supported default, or require an explicit canonical seed."""
    if mode is None:
        mode = "default" if seed is None else "explicit"
    if mode == "default" and seed is None:
        return SeedPolicy(seed=1, mode=mode)
    if mode not in ("explicit", "release", "diagnostic") or seed is None:
        raise Error("invalid O-MVLL seed policy")
    return SeedPolicy(seed=parse_seed(seed), mode=mode)


def main() -> int:
    """Print only the validated configure-time scalar policy, never invalid input."""
    try:
        policy = parse_policy(
            os.environ.get("RASP_OMVLL_SEED"), os.environ.get("RASP_OMVLL_SEED_MODE")
        )
    except Error:
        print("invalid O-MVLL seed policy", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(policy), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

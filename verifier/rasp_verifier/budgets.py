"""Enforce binary size and measured device latency budgets without inventing samples."""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import pathlib

MIN_SAMPLES = 30


@dataclasses.dataclass(frozen=True)
class BudgetResult:
    name: str
    measured: float
    limit: float
    passed: bool


def check_size(artifact: pathlib.Path, max_bytes: int) -> BudgetResult:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("size budget must be a positive integer")
    size = artifact.stat().st_size
    if size <= 0 or artifact.is_file() is False:
        raise ValueError("artifact must be a nonempty regular file")
    return BudgetResult("binary_bytes", size, max_bytes, size <= max_bytes)


def check_latency(
    device: str, samples_ms: list[float], max_p95_ms: float
) -> BudgetResult:
    if not isinstance(device, str) or len(device.strip()) == 0:
        raise ValueError("a reference device identifier is required")
    if len(samples_ms) < MIN_SAMPLES:
        raise ValueError(f"at least {MIN_SAMPLES} measured samples are required")
    if (
        type(max_p95_ms) not in {int, float}
        or math.isfinite(max_p95_ms) is False
        or max_p95_ms <= 0
    ):
        raise ValueError("latency budget must be finite and positive")
    for sample in samples_ms:
        if (
            type(sample) not in {int, float}
            or math.isfinite(sample) is False
            or sample < 0
        ):
            raise ValueError("samples must be finite nonnegative measurements")
    p95 = sorted(samples_ms)[math.ceil(0.95 * len(samples_ms)) - 1]
    return BudgetResult(f"{device}:p95_ms", p95, max_p95_ms, p95 <= max_p95_ms)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    size = subparsers.add_parser("size")
    size.add_argument("artifact", type=pathlib.Path)
    size.add_argument("--max-bytes", type=int, required=True)
    latency = subparsers.add_parser("latency")
    latency.add_argument(
        "metrics", type=pathlib.Path, help="JSON with device and samplesMs"
    )
    latency.add_argument("--max-p95-ms", type=float, required=True)
    args = parser.parse_args()
    try:
        if args.command == "size":
            result = check_size(args.artifact, args.max_bytes)
        else:
            metrics = json.loads(args.metrics.read_text())
            result = check_latency(
                metrics["device"], metrics["samplesMs"], args.max_p95_ms
            )
    except (ValueError, TypeError, KeyError, OSError):
        print(
            json.dumps(
                {"passed": False, "error": "invalid budget, artifact, or measurements"}
            )
        )
        return 2
    print(json.dumps(dataclasses.asdict(result)))
    return 0 if result.passed is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Explicit Clang -> LLVM pass -> object integration, including cross compilation."""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-prefix", type=pathlib.Path, required=True)
    parser.add_argument("--plugin", type=pathlib.Path, required=True)
    parser.add_argument("--functions", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--probe-symbol", default="rasp_guard_probe")
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("flags", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    flags = args.flags[1:] if args.flags[:1] == ["--"] else args.flags
    if any(flag.startswith(("-O", "-flto", "-fpass-plugin")) or flag in {"-o", "-c", "-S", "-emit-llvm"} for flag in flags):
        parser.error("optimization/output flags are controlled by this pipeline")
    binary = args.llvm_prefix / "bin"
    version = subprocess.run([str(binary / "llvm-config"), "--version"], check=True, capture_output=True, text=True).stdout
    if version.startswith("18.") is False:
        parser.error("LLVM 18 toolchain and matching plugin required")
    environment = dict(os.environ, RASP_FUNCTIONS=args.functions, RASP_SEED=args.seed, RASP_PROBE_SYMBOL=args.probe_symbol)
    with tempfile.TemporaryDirectory() as directory:
        original = pathlib.Path(directory) / "original.bc"
        hardened = pathlib.Path(directory) / "hardened.bc"
        subprocess.run([str(binary / "clang"), *flags, "-O0", "-Xclang", "-disable-O0-optnone", "-emit-llvm", "-c", str(args.input), "-o", str(original)], check=True)
        subprocess.run([str(binary / "opt"), "-load-pass-plugin", str(args.plugin), "-passes=rasp-harden", "-verify-each", str(original), "-o", str(hardened)], check=True, env=environment)
        subprocess.run([str(binary / "clang"), *flags, "-c", str(hardened), "-o", str(args.output)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

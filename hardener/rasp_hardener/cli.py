"""``rasp-hardener`` command-line interface (design §6: pre-build generator + post-build CLI, SDK-only mode).

Subcommands:

- ``gen-build``  derive a build from a fresh (or given) seed, emit ``build_generated.h`` + ``build_seed.h`` into
                 the native ``cpp`` dir, and write the registration manifest. This is the pre-build generator a
                 CI job runs before compiling the app, and the post-build registration step in one.
- ``show``       print a non-secret summary of the build a seed produces (id, opcode map, detector order).
- ``register``   (re)emit only the registration manifest for a seed — e.g. to hand to the trust service.

The manifest carries the secret build key; keep it out of source control and deliver it to the trust service
over a trusted channel. ``--seed`` takes hex (32 chars / 16 bytes); omit it for a random build.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import emit
from .manifest import build_manifest
from .seed import SEED_LEN, BuildProfile

# The native sources whose bytes define the build, hashed into the integrity root.
NATIVE_SOURCES = ["detectors.c", "signals.c", "sha256.c", "report.c", "rasp_jni.c", "guard.c", "strobf.c"]


def _profile_from_arg(seed_hex: str | None) -> BuildProfile:
    if seed_hex is None:
        return BuildProfile.derive()
    seed = bytes.fromhex(seed_hex)
    if len(seed) != SEED_LEN:
        raise SystemExit(f"--seed must be {SEED_LEN} bytes ({SEED_LEN * 2} hex chars)")
    return BuildProfile.derive(seed)


def _code_paths(cpp_dir: pathlib.Path) -> list[pathlib.Path]:
    return [cpp_dir / name for name in NATIVE_SOURCES if (cpp_dir / name).exists()]


def cmd_gen_build(args: argparse.Namespace) -> int:
    profile = _profile_from_arg(args.seed)
    cpp_dir = pathlib.Path(args.cpp_dir)
    written = emit.emit_headers(profile, cpp_dir)
    manifest = build_manifest(
        profile,
        package_name=args.package,
        signing_cert_sha256=args.cert or [],
        code_paths=_code_paths(cpp_dir),
    )
    manifest_path = pathlib.Path(args.manifest)
    manifest.write(manifest_path)
    print(f"build_id      {profile.build_id}")
    print(f"seed          {profile.seed_hex}")
    for p in written:
        print(f"emitted       {p}")
    print(f"manifest      {manifest_path}")
    print(f"integrity     {manifest.integrity_root or '(no code hashed)'}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    import json

    profile = _profile_from_arg(args.seed)
    print(json.dumps(profile.summary(), indent=2))
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    profile = _profile_from_arg(args.seed)
    cpp_dir = pathlib.Path(args.cpp_dir)
    manifest = build_manifest(
        profile,
        package_name=args.package,
        signing_cert_sha256=args.cert or [],
        code_paths=_code_paths(cpp_dir) if cpp_dir.exists() else None,
    )
    if args.manifest:
        pathlib.Path(args.manifest).write_text(manifest.to_json() + "\n")
        print(f"manifest written to {args.manifest}")
    else:
        print(manifest.to_json())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rasp-hardener", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    default_cpp = "flutter_rasp/android/src/main/cpp"

    gb = sub.add_parser("gen-build", help="emit per-build headers and the registration manifest")
    gb.add_argument("--seed", help="16-byte seed as hex; omit for a random build")
    gb.add_argument("--cpp-dir", default=default_cpp, help="native cpp dir to write headers into")
    gb.add_argument("--package", default="dev.ostorlab.rasp.demo_bank", help="app package name")
    gb.add_argument("--cert", action="append", help="app signing-cert SHA-256 (repeatable)")
    gb.add_argument("--manifest", default="build_manifest.json", help="registration manifest output path")
    gb.set_defaults(func=cmd_gen_build)

    sh = sub.add_parser("show", help="print a non-secret summary of the build a seed produces")
    sh.add_argument("--seed", help="16-byte seed as hex; omit for a random build")
    sh.set_defaults(func=cmd_show)

    rg = sub.add_parser("register", help="emit only the registration manifest")
    rg.add_argument("--seed", help="16-byte seed as hex; omit for a random build")
    rg.add_argument("--cpp-dir", default=default_cpp, help="native cpp dir to hash (optional)")
    rg.add_argument("--package", default="dev.ostorlab.rasp.demo_bank", help="app package name")
    rg.add_argument("--cert", action="append", help="app signing-cert SHA-256 (repeatable)")
    rg.add_argument("--manifest", help="output path; prints to stdout if omitted")
    rg.set_defaults(func=cmd_register)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

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
import hashlib
import hmac
import json
import os
import pathlib
import sys

from rasp_hardener import aes
from rasp_hardener import assets
from rasp_hardener import vm
from rasp_hardener import emit
from rasp_hardener import literals
from rasp_hardener import names
from rasp_hardener import whitebox
from rasp_hardener.manifest import build_manifest
from rasp_hardener.seed import SEED_LEN, BuildProfile

WBAES_KEY_LEN = 16

# The native sources whose bytes define the build, hashed into the integrity root.
NATIVE_SOURCES = ["detectors.c", "signals.c", "sha256.c", "report.c", "rasp_jni.c", "guard.c", "strobf.c", "literals.c", "literals.def", "symbols.def", "integrity.c", "wbaes.c", "securestore.c", "weave.c", "vm.c", "assets.c"]


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
    lits = literals.with_build_key(literals.parse_literals(cpp_dir / "literals.def"), profile.build_key_hex)
    symbols = names.parse_symbols(cpp_dir / "symbols.def")
    written = emit.emit_headers(profile, cpp_dir, lits)
    names_header = cpp_dir / "build_names.h"
    names_header.write_text(emit.render_build_names_h(profile, symbols))
    symbols_map = cpp_dir / "symbols.map"
    symbols_map.write_text(json.dumps(emit.render_symbols_map(profile, symbols), indent=2, sort_keys=True) + "\n")
    written += [names_header, symbols_map]
    manifest = build_manifest(
        profile,
        package_name=args.package,
        signing_cert_sha256=args.cert or [],
        code_paths=_code_paths(cpp_dir),
        so_path=args.so,
    )
    # With a compiled .so, emit the regions header so the device hashes the same bytes and seals with the
    # integrity-derived key (design §8). Without --so, the manifest carries only the legacy source-hash root.
    if args.so is not None:
        regions = [(r["offset"], r["length"]) for r in manifest.integrity_regions]
        integrity_header = cpp_dir / "integrity_regions.h"
        integrity_header.write_text(emit.render_integrity_regions_h(regions))
        written = written + [integrity_header]
    manifest_path = pathlib.Path(args.manifest)
    manifest.write(manifest_path)
    print(f"build_id      {profile.build_id}")
    # Never print the raw seed: it derives build_key (the report MAC key) and would leak into CI logs.
    print(f"seed_fp       {profile.seed_fingerprint}")
    for p in written:
        print(f"emitted       {p}")
    print(f"manifest      {manifest_path}")
    print(f"integrity     {manifest.integrity_root or '(no code hashed)'}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
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


def _wbaes_key(args: argparse.Namespace) -> bytes:
    """The white-box AES key: explicit --key, else derived from --seed, else random."""
    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) != WBAES_KEY_LEN:
            raise SystemExit(f"--key must be {WBAES_KEY_LEN} bytes ({WBAES_KEY_LEN * 2} hex chars)")
        return key
    if args.seed:
        seed = bytes.fromhex(args.seed)
        if len(seed) != SEED_LEN:
            raise SystemExit(f"--seed must be {SEED_LEN} bytes")
        return hmac.new(seed, b"raxp/wbaes-key", hashlib.sha256).digest()[:WBAES_KEY_LEN]
    return os.urandom(WBAES_KEY_LEN)


def cmd_gen_wbkey(args: argparse.Namespace) -> int:
    key = _wbaes_key(args)
    encoding_seed = hmac.new(key, b"rasp/whitebox-encoding/v1", hashlib.sha256).digest()
    tables = whitebox.generate(key, encoding_seed=encoding_seed)
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(whitebox.render_tables_h(tables))
    # Self-check: the emitted tables must reproduce reference AES over several distinct probes (one probe
    # can coincide for a broken table; a handful across the state space catches generation/emission bugs).
    round_keys = aes.key_expansion(key)
    probes = [bytes(range(16)), bytes(16), b"\xff" * 16, bytes(range(15, -1, -1))]
    ok = all(tables.encrypt_block(p) == aes.encrypt_block(round_keys, p) for p in probes)
    print(f"wbaes tables  {out_path}")
    print(f"self-check    {'ok' if ok else 'FAILED'}")
    print("note          affine encoded tables: no DCA/DFA resistance claim (see TODO §8)")
    return 0 if ok else 1



def cmd_compile_vm(args: argparse.Namespace) -> int:
    profile = _profile_from_arg(args.seed)
    code = vm.compile_expression(args.expression, profile)
    pathlib.Path(args.out).write_bytes(vm.opcode_bytes(profile) + code)
    return 0


def cmd_asset(args: argparse.Namespace) -> int:
    key = pathlib.Path(args.key_file).read_bytes()
    root = bytes.fromhex(args.guard_root)
    data = pathlib.Path(args.input).read_bytes()
    if args.command == "pack-asset":
        output = assets.seal(data, args.identity, key, root)
        if args.tables is not None:
            pathlib.Path(args.tables).write_text(whitebox.render_tables_h(assets.tables(key, root)))
    else:
        output = assets.open_package(data, args.identity, key, root)
    pathlib.Path(args.out).write_bytes(output)
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
    gb.add_argument("--so", help="compiled .so to hash for the integrity root; emits integrity_regions.h")
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

    wb = sub.add_parser("gen-wbkey", help="emit white-box AES-128 tables (wbaes_tables.h) for SecureStore")
    wb.add_argument("--key", help="16-byte AES key as hex; overrides --seed")
    wb.add_argument("--seed", help="16-byte build seed as hex; derives the WB key when --key is omitted")
    wb.add_argument("--out", default=default_cpp + "/wbaes_tables.h", help="output header path")
    wb.set_defaults(func=cmd_gen_wbkey)

    virtual = sub.add_parser("compile-vm", help="compile arithmetic expression; output = 16-byte opcode table || bytecode")
    virtual.add_argument("--seed", required=True)
    virtual.add_argument("--expression", required=True)
    virtual.add_argument("--out", required=True)
    virtual.set_defaults(func=cmd_compile_vm)
    for command in ["pack-asset", "open-asset"]:
        resource = sub.add_parser(command, help="authenticated resource package bound to guard root and identity")
        resource.add_argument("--key-file", required=True, help="private file containing exactly 32 raw key bytes")
        resource.add_argument("--guard-root", required=True, help="expected 32-byte digest of guarded live regions in hex")
        resource.add_argument("--identity", required=True)
        resource.add_argument("--input", required=True)
        resource.add_argument("--out", required=True)
        resource.add_argument("--tables", help="pack only: private encoded AES header for the native loader")
        resource.set_defaults(func=cmd_asset)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

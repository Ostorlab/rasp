"""Public pack, inspect and reference backend commands."""

from __future__ import annotations

import argparse
import collections.abc
import ipaddress
import json
import pathlib
import ssl
import sys

from rasp_elf import backend
from rasp_elf import packer
from rasp_elf import protocol


def load_policy(path: pathlib.Path | None) -> collections.abc.Callable[[backend.Evidence], str] | None:
    if path is None:
        return None
    policy = json.loads(protocol.read_regular_file(path, 16384))
    if isinstance(policy, dict) is False or set(policy) - {"default_action", "operations"} != set():
        raise ValueError("invalid policy fields")
    default = policy.get("default_action", "allow")
    raw_operations = policy.get("operations", {})
    if (
        isinstance(default, str) is False
        or default not in protocol.ACTIONS
        or isinstance(raw_operations, dict) is False
    ):
        raise ValueError("invalid policy action or operations")
    default_action: str = default
    operations: dict[str, str] = {}
    for name, action in raw_operations.items():
        if (
            isinstance(name, str) is False
            or isinstance(action, str) is False
            or name not in protocol.OPERATIONS
            or action not in protocol.ACTIONS
        ):
            raise ValueError("invalid policy operation/action")
        operations[name] = action

    def decide(evidence: backend.Evidence) -> str:
        return operations.get(evidence.operation, default_action)

    return decide


def serve(args: argparse.Namespace) -> None:
    policy = load_policy(args.policy)
    authorizer = backend.Authorizer(
        protocol.read_private_key(args.decision_key),
        protocol.read_public_key(args.publisher_public),
        policy=policy,
        audit_path=args.audit,
    )
    for manifest in args.manifest:
        authorizer.register(protocol.read_regular_file(manifest, protocol.MAX_MESSAGE_BYTES))
    address = ipaddress.ip_address(args.host)
    if address.version != 4:
        raise ValueError("reference server currently listens on IPv4; use an application server for IPv6")
    if (args.tls_cert is None) != (args.tls_key is None):
        raise ValueError("both TLS certificate and key are required")
    if address.is_loopback is False and args.tls_cert is None:
        raise ValueError("nonloopback backend binding requires TLS")
    if not 1 <= args.port <= 65535:
        raise ValueError("invalid listen port")
    with backend.ReferenceServer((args.host, args.port), authorizer) as server:
        if args.tls_cert is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(args.tls_cert), str(args.tls_key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https" if args.tls_cert is not None else "http"
        print(f"RASP backend listening on {scheme}://{args.host}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pack Linux x86-64 glibc ELF executables with runtime RASP.")
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen", help="generate publisher and backend signing keys outside app bundles")
    keys.add_argument("--output", type=pathlib.Path, required=True)
    pack = commands.add_parser("pack", help="inject runtime and create a signed companion-file bundle")
    pack.add_argument("input", type=pathlib.Path)
    pack.add_argument("--output", type=pathlib.Path, required=True)
    pack.add_argument("--publisher-key", type=pathlib.Path, required=True)
    pack.add_argument("--backend", default="", help="http[s]://host:port; HTTP only on literal loopback")
    pack.add_argument("--backend-public", type=pathlib.Path)
    pack.add_argument("--interval-ms", type=int, default=250)
    inspect = commands.add_parser("inspect", help="verify publisher signature, file hashes and ELF injection")
    inspect.add_argument("bundle", type=pathlib.Path)
    inspect.add_argument("--publisher-public", type=pathlib.Path, required=True)
    server = commands.add_parser("serve", help="run reference evidence verifier and policy backend")
    server.add_argument("--publisher-public", type=pathlib.Path, required=True)
    server.add_argument("--decision-key", type=pathlib.Path, required=True)
    server.add_argument("--manifest", type=pathlib.Path, action="append", required=True)
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8788)
    server.add_argument("--policy", type=pathlib.Path)
    server.add_argument("--audit", type=pathlib.Path)
    server.add_argument("--tls-cert", type=pathlib.Path)
    server.add_argument("--tls-key", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            packer.keygen(args.output)
            print(json.dumps({"keys": str(args.output), "private_keys": "publisher.key, backend.key"}))
        elif args.command == "pack":
            server_public = (
                protocol.read_public_key(args.backend_public) if args.backend_public is not None else "00" * 32
            )
            report = packer.pack(
                args.input,
                args.output,
                protocol.read_private_key(args.publisher_key),
                endpoint=args.backend,
                server_public=server_public,
                interval_ms=args.interval_ms,
            )
            print(json.dumps(report, indent=2, sort_keys=True))
        elif args.command == "inspect":
            print(
                json.dumps(
                    packer.inspect(args.bundle, protocol.read_public_key(args.publisher_public)),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "serve":
            serve(args)
    except (ValueError, OSError, TypeError) as error:
        print(f"rasp-elf: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The `rasp` command line: a thin client of the packer library."""

import argparse
import collections.abc
import dataclasses
import json
import os
import pathlib
import sys
import typing
from importlib import metadata

from rasp_packer import banner
from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import inspection
from rasp_packer import packer
from rasp_packer import platforms

EXIT_OK = 0
EXIT_FAILED = 1


class _Writer(typing.Protocol):
    """An output that takes text."""

    def write(self, text: str, /) -> object:
        """Writes the text."""
        ...


class _RootParser(argparse.ArgumentParser):
    """The parser of `rasp` itself, whose help starts with the banner when the output is a terminal."""

    def print_help(self, file: _Writer | None = None) -> None:
        """Prints the help to the file, or to stdout.

        Printed to stdout, it starts with the banner when stdout is a terminal.
        """
        if file is None and banner.is_enabled(sys.stdout, os.environ) is True:
            sys.stdout.write(banner.render(metadata.version("rasp-packer"), os.environ))
        super().print_help(file)


def _parser() -> argparse.ArgumentParser:
    """Builds the parser of the `rasp` command line, with its `pack` and `inspect` commands."""
    parser = _RootParser(
        prog="rasp",
        description="Protects built Android (APK, AAB) and iOS (IPA) apps with the RASP runtime.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {metadata.version('rasp-packer')}",
    )
    commands = parser.add_subparsers(
        dest="command", parser_class=argparse.ArgumentParser
    )

    pack = commands.add_parser(
        "pack", help="add the runtime to a built app (the result is unsigned)"
    )
    pack.add_argument(
        "app", type=pathlib.Path, help="the built app, an APK, AAB, or IPA"
    )
    pack.add_argument(
        "--platform",
        type=platforms.Platform,
        choices=list(platforms.Platform),
        required=True,
        help="the platform of the app",
    )
    pack.add_argument(
        "--build-id",
        required=True,
        help="id of the protected build, written into the app",
    )
    pack.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="where to write the protected app",
    )
    pack.add_argument(
        "--checks",
        type=_split_checks,
        help="the check groups the app runs, comma-separated, such as debugger,hooks; "
        f"{_required_checks()} always runs (default: only {_required_checks()})",
    )
    pack.add_argument(
        "--mapping",
        type=pathlib.Path,
        default=None,
        help=(
            "the app's R8/ProGuard mapping file (Android only); with it the packer protects the "
            "app's own classes even after R8 has repackaged them out of the app's package"
        ),
    )
    pack.add_argument(
        "--pin-certificate",
        type=pathlib.Path,
        help="the certificate the app will be signed with, PEM or DER; the pack refuses to decrypt "
        "under any other signer (Android only)",
    )
    _add_json_argument(pack)

    inspect_command = commands.add_parser(
        "inspect",
        help="report whether a built app is protected, and the runtime config it carries",
    )
    inspect_command.add_argument(
        "app", type=pathlib.Path, help="the built app, an APK, AAB, or IPA"
    )
    inspect_command.add_argument(
        "--platform",
        type=platforms.Platform,
        choices=list(platforms.Platform),
        required=True,
        help="the platform of the app",
    )
    _add_json_argument(inspect_command)
    return parser


def _add_json_argument(command: argparse.ArgumentParser) -> None:
    """Adds `--json` to a command, which then prints its result as one JSON object instead of text."""
    command.add_argument(
        "--json",
        action="store_true",
        help="print the result as one JSON object with sorted keys; warnings still go to stderr",
    )


def _print_json(fields: dict[str, object]) -> None:
    """Prints the fields as one JSON object, with its keys sorted."""
    print(json.dumps(fields, sort_keys=True))


def _split_checks(value: str) -> list[str]:
    """Splits the comma-separated check groups given on the command line.

    Each id is stripped of the spaces around it, and the empty ones, such as the one after a trailing comma, are
    dropped.

    Raises:
        argparse.ArgumentTypeError: No id is left, as with an empty value, so argparse exits with a usage error
            rather than packing an app that runs the required groups only.
    """
    checks = [check.strip() for check in value.split(",")]
    checks = [check for check in checks if check != ""]
    if len(checks) == 0:
        raise argparse.ArgumentTypeError("give at least one check id")
    return checks


def _required_checks() -> str:
    """Returns the ids of the check groups every protected app runs, sorted and comma-separated."""
    return ",".join(sorted(check_groups.REQUIRED_CHECKS))


def _pack(arguments: argparse.Namespace) -> int:
    """Packs the app given on the command line and prints the result, as text or, with `--json`, as one JSON object.

    Without `--checks`, it warns and packs the app with only the required check groups. It warns
    about each given check id that is not one of the platform's groups, which the packer skips.
    """
    checks: list[str] | None = arguments.checks
    if checks is None:
        print(
            "rasp pack: warning: no --checks given, so the app runs only the required checks: "
            f"{_required_checks()}. Pass --checks, such as --checks debugger,hooks, to choose "
            "the checks it runs.",
            file=sys.stderr,
        )
        checks = []
    try:
        result = packer.pack(
            app=arguments.app,
            platform=arguments.platform,
            output=arguments.output,
            build_id=arguments.build_id,
            checks=checks,
            mapping=arguments.mapping,
            pin_certificate=getattr(arguments, "pin_certificate", None),
        )
    except errors.Error as error:
        print(f"rasp pack: {error}", file=sys.stderr)
        return EXIT_FAILED
    for check in result.skipped_checks:
        print(
            f"rasp pack: warning: {check!r} is not a check of {arguments.platform}, skipped",
            file=sys.stderr,
        )
    if arguments.json is True:
        _print_json({**dataclasses.asdict(result), "output": str(result.output)})
        return EXIT_OK
    print(
        f"packed {arguments.platform} app: {result.output} "
        f"(package {result.package_name}, version {result.version}, build {result.build_id})"
    )
    return EXIT_OK


def _inspect(arguments: argparse.Namespace) -> int:
    """Inspects the app given on the command line and prints what it read, one aligned `label  value` line each.

    With `--json`, it prints the inspection's fields as one JSON object instead.

    The build id, the check groups and the ABIs are printed only for a protected app, and the ABIs only for Android.
    """
    try:
        result = inspection.inspect(app=arguments.app, platform=arguments.platform)
    except errors.Error as error:
        print(f"rasp inspect: {error}", file=sys.stderr)
        return EXIT_FAILED
    if arguments.json is True:
        _print_json(dataclasses.asdict(result))
        return EXIT_OK
    lines = [
        ("protected", "yes" if result.protected is True else "no"),
        ("package", result.package_name),
        ("version", result.version),
    ]
    if result.build_id is not None:
        lines.append(("build id", result.build_id))
        lines.append(("checks", ",".join(result.checks)))
    if len(result.abis) > 0:
        lines.append(("abis", ",".join(result.abis)))
    width = max(len(label) for label, _ in lines)
    for label, value in lines:
        print(f"{label.ljust(width)}  {value}")
    return EXIT_OK


def main(argv: collections.abc.Sequence[str] | None = None) -> int:
    """Runs the `rasp` command line.

    Args:
        argv: The arguments, without the program name. None reads them from the process.

    Returns:
        The exit code of the process. Without a command it prints the help and returns 0.
    """
    parser = _parser()
    arguments = parser.parse_args(argv)
    if arguments.command is None:
        parser.print_help()
        return EXIT_OK
    match arguments.command:
        case "pack":
            return _pack(arguments)
        case "inspect":
            return _inspect(arguments)
        case _:
            raise AssertionError(f"unknown command {arguments.command!r}")

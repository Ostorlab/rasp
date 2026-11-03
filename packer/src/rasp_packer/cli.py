"""The `rasp` command line: a thin client of the packer library."""

import argparse
import collections.abc
import pathlib
import sys
from importlib import metadata

from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import packer
from rasp_packer import platforms

EXIT_OK = 0
EXIT_FAILED = 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rasp",
        description="Protects built Android (APK, AAB) and iOS (IPA) apps with the RASP runtime.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {metadata.version('rasp-packer')}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

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
    return parser


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
    """Packs the app given on the command line and prints the result.

    Without `--checks`, it warns and packs the app with only the required check groups.
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
        )
    except errors.Error as error:
        print(f"rasp pack: {error}", file=sys.stderr)
        return EXIT_FAILED
    print(
        f"packed {arguments.platform} app: {result.output} "
        f"(package {result.package_name}, version {result.version}, build {result.build_id})"
    )
    return EXIT_OK


def main(argv: collections.abc.Sequence[str] | None = None) -> int:
    """Runs the `rasp` command line.

    Args:
        argv: The arguments, without the program name. None reads them from the process.

    Returns:
        The exit code of the process.
    """
    arguments = _parser().parse_args(argv)
    match arguments.command:
        case "pack":
            return _pack(arguments)
        case _:
            raise AssertionError(f"unknown command {arguments.command!r}")

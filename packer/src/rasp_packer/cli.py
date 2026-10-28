"""The `rasp` command line: a thin client of the packer library."""

import argparse
import collections.abc
import pathlib
import sys
from importlib import metadata

from rasp_packer import errors
from rasp_packer import packer
from rasp_packer import platforms

EXIT_OK = 0
EXIT_FAILED = 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rasp",
        description="Protects built Android and iOS apps with the RASP runtime.",
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
        "app", type=pathlib.Path, help="the built app, an APK, an AAB or an IPA"
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
    return parser


def _pack(arguments: argparse.Namespace) -> int:
    """Packs the app given on the command line and prints the result."""
    try:
        result = packer.pack(
            app=arguments.app,
            platform=arguments.platform,
            output=arguments.output,
            build_id=arguments.build_id,
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

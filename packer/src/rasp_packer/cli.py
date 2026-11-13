"""The `rasp` command line: a thin client of the packer library."""

import argparse
import collections.abc
import pathlib
import sys
from importlib import metadata

from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import local_policy
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
        "the platform's required groups always run (default: only required groups)",
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
        "--local-policy",
        type=pathlib.Path,
        help="bounded embedded policy JSON; default report-only; gating requires adapted host calls",
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


def _required_checks(platform: platforms.Platform) -> str:
    """Returns the ids of the check groups every protected app runs, sorted and comma-separated."""
    required = check_groups.REQUIRED_CHECKS_BY_PLATFORM[platform]
    return ",".join(sorted(required))


def _pack(arguments: argparse.Namespace) -> int:
    """Packs the app given on the command line and prints the result.

    Without `--checks`, it warns and packs the app with only the required check groups. It warns
    about each given check id that is not one of the platform's groups, which the packer skips.
    """
    checks: list[str] | None = arguments.checks
    if checks is None:
        print(
            "rasp pack: warning: no --checks given, so the app runs only the required checks: "
            f"{_required_checks(arguments.platform)}. Pass --checks, such as --checks debugger,hooks, to choose "
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
            local_policy=None
            if arguments.local_policy is None
            else local_policy.load(arguments.local_policy),
        )
    except errors.Error as error:
        print(f"rasp pack: {error}", file=sys.stderr)
        return EXIT_FAILED
    for check in result.skipped_checks:
        print(
            f"rasp pack: warning: {check!r} is not a check of {arguments.platform}, skipped",
            file=sys.stderr,
        )
    capability_status = "unknown (legacy runtime artifacts)"
    if result.capability_bindings is not None:
        capability_status = ",".join(
            sorted({binding.catalogue_id for binding in result.capability_bindings})
        )
    print(
        f"packed {arguments.platform} app: {result.output} "
        f"(package {result.package_name}, version {result.version}, build {result.build_id}; "
        "unsigned, structurally verified)"
        f"\ncapabilities {capability_status}; effective checks {','.join(result.effective_checks)}"
        f"\nlocal policy {result.policy_mode}; hash {result.policy_sha256}; effective config {result.effective_config_sha256}; host calls only, adaptation unverified"
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

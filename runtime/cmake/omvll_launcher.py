"""Freeze iOS compile inputs and refuse drift at the actual O-MVLL load boundary.

This local build policy is not an artifact sidecar or a trust/efficacy claim.
The compiler still runs in its original working directory with unchanged argv.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import types
import typing

# Conservative root-name reservation from CPython v3.10.7 Python/stdlib_module_names.h.
# Host builtin/stdlib sets alone omit embedded-version or platform-specific module names.
_PYTHON310_STDLIB_NAMES = """
__future__ _abc _aix_support _ast _asyncio _bisect _blake2 _bootsubprocess _bz2 _codecs
_codecs_cn _codecs_hk _codecs_iso2022 _codecs_jp _codecs_kr _codecs_tw _collections
_collections_abc _compat_pickle _compression _contextvars _crypt _csv _ctypes _curses
_curses_panel _datetime _dbm _decimal _elementtree _frozen_importlib
_frozen_importlib_external _functools _gdbm _hashlib _heapq _imp _io _json _locale
_lsprof _lzma _markupbase _md5 _msi _multibytecodec _multiprocessing _opcode _operator
_osx_support _overlapped _pickle _posixshmem _posixsubprocess _py_abc _pydecimal _pyio
_queue _random _scproxy _sha1 _sha256 _sha3 _sha512 _signal _sitebuiltins _socket
_sqlite3 _sre _ssl _stat _statistics _string _strptime _struct _symtable _thread
_threading_local _tkinter _tracemalloc _uuid _warnings _weakref _weakrefset _winapi
_zoneinfo abc aifc antigravity argparse array ast asynchat asyncio asyncore atexit
audioop base64 bdb binascii binhex bisect builtins bz2 cProfile calendar cgi cgitb chunk
cmath cmd code codecs codeop collections colorsys compileall concurrent configparser
contextlib contextvars copy copyreg crypt csv ctypes curses dataclasses datetime dbm
decimal difflib dis distutils doctest email encodings ensurepip enum errno faulthandler
fcntl filecmp fileinput fnmatch fractions ftplib functools gc genericpath getopt getpass
gettext glob graphlib grp gzip hashlib heapq hmac html http idlelib imaplib imghdr imp
importlib inspect io ipaddress itertools json keyword lib2to3 linecache locale logging
lzma mailbox mailcap marshal math mimetypes mmap modulefinder msilib msvcrt
multiprocessing netrc nis nntplib nt ntpath nturl2path numbers opcode operator optparse
os ossaudiodev pathlib pdb pickle pickletools pipes pkgutil platform plistlib poplib
posix posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc pydoc_data pyexpat
queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select
selectors shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver spwd
sqlite3 sre_compile sre_constants sre_parse ssl stat statistics string stringprep struct
subprocess sunau symtable sys sysconfig syslog tabnanny tarfile telnetlib tempfile
termios textwrap this threading time timeit tkinter token tokenize trace traceback
tracemalloc tty turtle turtledemo types typing unicodedata unittest urllib uu uuid venv
warnings wave weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp
zipfile zipimport zlib zoneinfo
"""
_PYTHON310_STDLIB_ROOTS = frozenset(_PYTHON310_STDLIB_NAMES.split())


def check_source_module(path: pathlib.Path) -> None:
    """Refuse competing root loaders without importing or executing the module."""
    if path.suffix != ".py" or path.stem == "" or "." in path.stem:
        raise ValueError("root config must be one source module")
    for candidate in path.parent.iterdir():
        if candidate.name == path.stem and candidate.is_dir() is True:
            raise ValueError("same-stem package is unsupported")
        if candidate.name.startswith(path.stem + ".") and candidate.suffix in (
            ".so",
            ".pyd",
            ".dylib",
            ".pyc",
        ):
            # Include foreign-ABI suffixes: host 3.14 suffixes do not describe embedded 3.10.
            raise ValueError("competing native or bytecode root is unsupported")
    finder = importlib.machinery.FileFinder(
        str(path.parent),
        (
            importlib.machinery.ExtensionFileLoader,
            importlib.machinery.EXTENSION_SUFFIXES,
        ),
        (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
        (
            importlib.machinery.SourcelessFileLoader,
            importlib.machinery.BYTECODE_SUFFIXES,
        ),
    )
    spec = finder.find_spec(path.stem)
    if (
        spec is None
        or type(spec.loader) is not importlib.machinery.SourceFileLoader
        or spec.submodule_search_locations is not None
        or spec.origin is None
        or pathlib.Path(spec.origin).resolve() != path.resolve(strict=True)
    ):
        raise ValueError("root module does not resolve to captured source")


SEED_SOURCE = pathlib.Path(__file__).resolve().with_name("omvll_seed.py")
try:
    check_source_module(SEED_SOURCE)
    if "omvll_seed" in sys.modules:
        raise ValueError("shared seed module was already imported")
except (OSError, ValueError):
    print("O-MVLL launcher refused ambiguous shared seed module", file=sys.stderr)
    sys.exit(1)

# Execute only this owned helper's source bytes, not a package, preimport or timestamp-valid .pyc.
# Custom configuration is never executed by this validation step.
omvll_seed = types.ModuleType("omvll_seed")
omvll_seed.__file__ = str(SEED_SOURCE)
sys.modules["omvll_seed"] = omvll_seed
exec(compile(SEED_SOURCE.read_bytes(), str(SEED_SOURCE), "exec"), vars(omvll_seed))


class Error(ValueError):
    """An input no longer agrees with the configured build policy."""


class FrozenPolicy(typing.TypedDict):
    """Configure-owned document authenticated by the generated launch command."""

    seed: str
    mode: str
    plugin: str
    config: str
    pythonpath: str
    yaml: str
    files: dict[str, str]


def file_digest(path: pathlib.Path) -> str:
    """Hash the actual file bytes rather than its path or archive label."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_policy(state: pathlib.Path, expected_digest: str) -> FrozenPolicy:
    """Validate the configure-owned document before interpreting its fields."""
    if state.stat().st_size > 16384 or file_digest(state) != expected_digest:
        raise Error("frozen policy identity changed; use a new build directory")
    return typing.cast(FrozenPolicy, json.loads(state.read_bytes()))


def check_config_modules(policy: FrozenPolicy) -> None:
    """Bind the configured root and any shared helper candidate, not custom imports."""
    config = pathlib.Path(policy["config"])
    pythonpath = pathlib.Path(policy["pythonpath"])
    check_source_module(config)
    # Upstream imports sys/pathlib and creates omvll before importing Path.stem.
    # Conservatively refuse loaded/builtin/selected-stdlib names as custom roots.
    if (
        config.stem in _PYTHON310_STDLIB_ROOTS
        or config.stem in sys.stdlib_module_names
        or config.stem in sys.modules
        or config.stem in sys.builtin_module_names
        or config.stem in ("omvll", "omvll_seed")
        or importlib.machinery.FrozenImporter.find_spec(config.stem) is not None
        or (pythonpath / (config.stem + ".py")).exists()
        or (pythonpath / config.stem).is_dir()
    ):
        raise Error("reserved or preimported root module name")
    for directory in {config.parent, pythonpath}:
        if any(
            candidate.name == "omvll_seed" or candidate.name.startswith("omvll_seed.")
            for candidate in directory.iterdir()
        ):
            helper = directory / "omvll_seed.py"
            check_source_module(helper)
            if helper.resolve(strict=True) != SEED_SOURCE:
                raise Error("shared seed root differs from captured helper")


def check_environment(policy: FrozenPolicy) -> None:
    """Allow absent build-shell settings; supplied settings must agree exactly."""
    if any(name in os.environ for name in ("CCC_OVERRIDE_OPTIONS", "CL", "_CL_")):
        raise Error("driver argument override environment is unsupported")
    seed = os.environ.get("RASP_OMVLL_SEED")
    mode = os.environ.get("RASP_OMVLL_SEED_MODE")
    if seed is not None and mode is not None:
        omvll_seed.parse_policy(seed, mode)
    if seed is not None and omvll_seed.parse_seed(seed) != int(policy["seed"]):
        raise Error("inherited seed conflicts with frozen policy")
    if mode is not None and mode != policy["mode"]:
        raise Error("inherited seed mode conflicts with frozen policy")
    for name, expected in (
        ("OMVLL_CONFIG", policy["config"]),
        ("OMVLL_PYTHONPATH", policy["pythonpath"]),
    ):
        value = os.environ.get(name)
        if value is not None and str(pathlib.Path(value).resolve()) != expected:
            raise Error("inherited O-MVLL path conflicts with frozen policy")


def freeze(arguments: argparse.Namespace) -> int:
    """Capture inputs once; reconfiguration preserves the build directory's seed."""
    state = pathlib.Path(arguments.state)
    if state.exists() is True or arguments.previous_sha256 != "":
        policy = read_policy(state, arguments.previous_sha256)
        check_environment(policy)
        seed = omvll_seed.parse_policy(
            None if policy["mode"] == "default" else policy["seed"], policy["mode"]
        )
    else:
        seed = omvll_seed.parse_policy(
            os.environ.get("RASP_OMVLL_SEED"), os.environ.get("RASP_OMVLL_SEED_MODE")
        )
    config = pathlib.Path(arguments.config).resolve(strict=True)
    plugin = pathlib.Path(arguments.plugin).resolve(strict=True)
    pythonpath = pathlib.Path(arguments.pythonpath).resolve(strict=True)
    if pythonpath.is_dir() is False:
        raise Error("Python standard library path is not a directory")
    plugin_digest = file_digest(plugin)
    if arguments.archive is not None:
        with tarfile.open(arguments.archive) as archive:
            stream = archive.extractfile("omvll-xcode.dylib")
            if stream is None:
                raise Error("plugin archive member missing")
            with stream:
                archived = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    archived.update(chunk)
        if archived.hexdigest() != plugin_digest:
            raise Error("extracted plugin differs from the selected archive")
    yaml = pathlib.Path(arguments.yaml).absolute()
    policy = {
        "seed": str(seed.seed),
        "mode": seed.mode,
        "config": str(config),
        "plugin": str(plugin),
        "pythonpath": str(pythonpath),
        "yaml": str(yaml),
        "files": {},
    }
    check_config_modules(policy)
    check_environment(policy)
    yaml.write_text(
        f"OMVLL_PYTHONPATH: {json.dumps(str(pythonpath))}\n"
        f"OMVLL_CONFIG: {json.dumps(str(config))}\n",
        encoding="utf-8",
    )
    policy["files"] = {
        str(path): file_digest(path)
        for path in (
            config,
            plugin,
            yaml,
            pathlib.Path(__file__),
            SEED_SOURCE,
        )
    }
    state.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")
    print(file_digest(state))
    return 0


def run(arguments: argparse.Namespace) -> int:
    """Check nearest YAML, identities and environment before launching the child."""
    state = pathlib.Path(arguments.state)
    policy = read_policy(state, arguments.sha256)
    check_environment(policy)
    for name, expected in policy["files"].items():
        if file_digest(pathlib.Path(name)) != expected:
            raise Error("configured file content changed; reconfigure before compiling")
    check_config_modules(policy)
    cwd = pathlib.Path.cwd()
    effective_yaml = next(
        (
            directory / "omvll.yml"
            for directory in (cwd, *cwd.parents)
            if (directory / "omvll.yml").exists()
        ),
        None,
    )
    if (
        effective_yaml is None
        or effective_yaml.resolve() != pathlib.Path(policy["yaml"]).resolve()
    ):
        raise Error("effective omvll.yml differs from the configured file")
    command: list[str] = arguments.command
    if len(command) > 0 and command[0] == "--":
        command = command[1:]
    plugins = [
        value.split("=", 1)[1]
        for value in command
        if value.startswith("-fpass-plugin=")
    ]
    if (
        len(command) == 0
        or len(plugins) != 1
        or str(pathlib.Path(plugins[0]).resolve()) != policy["plugin"]
    ):
        raise Error("compiler command must load exactly the captured plugin")
    if any(
        value.startswith(("@", "-working-directory", "--config"))
        or value == "-fpass-plugin"
        for value in command
    ):
        raise Error("indirect compiler settings are unsupported by the frozen launcher")
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONCASEOK"):
        environment.pop(name, None)
    environment.update(
        CLANG_NO_DEFAULT_CONFIG="1",
        RASP_OMVLL_SEED_MODE=policy["mode"],
        OMVLL_CONFIG=policy["config"],
        OMVLL_PYTHONPATH=policy["pythonpath"],
        PYTHONDONTWRITEBYTECODE="1",
    )
    if policy["mode"] == "default":
        environment.pop("RASP_OMVLL_SEED", None)
    else:
        environment["RASP_OMVLL_SEED"] = policy["seed"]
    # An empty per-invocation cache avoids importing stale bytecode for hashed source.
    with tempfile.TemporaryDirectory(prefix="omvll-python-", dir=state.parent) as cache:
        environment["PYTHONPYCACHEPREFIX"] = cache
        return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    """Run configure capture or one guarded compile without exposing input values."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    capture = commands.add_parser("freeze")
    for name in ("state", "yaml", "config", "plugin", "pythonpath"):
        capture.add_argument(f"--{name}", required=True)
    capture.add_argument("--archive")
    capture.add_argument("--previous-sha256", default="")
    compile_command = commands.add_parser("run")
    compile_command.add_argument("--state", required=True)
    compile_command.add_argument("--sha256", required=True)
    compile_command.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        return freeze(arguments) if arguments.action == "freeze" else run(arguments)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        print(
            "O-MVLL launcher refused inconsistent or unavailable build inputs",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""Request-scoped CPython audit hooks and SQLite sink interception.

This is application instrumentation, not a sandbox against arbitrary Python code
already executing in the process. Source-value matching does not track arbitrary
transformations; applications must pass the decoded values used by their sinks.
"""

from __future__ import annotations

import collections
import collections.abc
import contextlib
import contextvars
import dataclasses
import functools
import importlib._bootstrap
import importlib._bootstrap_external
import inspect
import ipaddress
import os
import pathlib
import re
import socket
import sqlite3
import sqlite3.dbapi2
import subprocess
import sys
import threading
import typing

from rasp_agent import patches


@dataclasses.dataclass(frozen=True)
class Policy:
    allowed_roots: tuple[str, ...] = ()
    allowed_executables: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    block_deserialization: bool = True
    denied_sinks: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.denied_sinks.issubset(patches.SINKS) is False:
            raise ValueError("denied_sinks must contain only a supported sink")
        for path in (*self.allowed_roots, *self.allowed_executables):
            if os.path.isabs(path) is False:
                raise ValueError("policy paths must be absolute")
        for network in self.allowed_networks:
            ipaddress.ip_network(network)


@dataclasses.dataclass(frozen=True)
class Event:
    tenant_id: str
    request_id: str
    sink: str
    reason: str


class Blocked(PermissionError):
    def __init__(self, event: Event) -> None:
        super().__init__(f"RASP blocked {event.sink}: {event.reason}")
        self.event = event


@dataclasses.dataclass
class Scope:
    tenant_id: str
    request_id: str
    sources: tuple[str, ...]
    policy: Policy
    events: collections.deque[Event] = dataclasses.field(
        default_factory=lambda: collections.deque(maxlen=100)
    )


_scope: contextvars.ContextVar[Scope | None] = contextvars.ContextVar(
    "rasp_request", default=None
)
_install_lock = threading.Lock()
_installed = False
_sqlite_connect = sqlite3.connect
_popen_init = subprocess.Popen.__init__
_popen_signature = inspect.signature(_popen_init)
_import_name: contextvars.ContextVar[str | None] = contextvars.ContextVar("rasp_import_name", default=None)
_module_paths: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar("rasp_module_paths", default=())
_import_directory: contextvars.ContextVar[str | None] = contextvars.ContextVar("rasp_import_directory", default=None)
_finder_spec = importlib._bootstrap_external.FileFinder.find_spec
_loader_write = importlib._bootstrap_external.SourceFileLoader.set_data
_sql_tokens = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|\[(?:[^\]])*\]|--[^\n]*|/\*[\s\S]*?\*/|[\w$]+|[^\s]", re.UNICODE)


@contextlib.contextmanager
def request_scope(
    tenant_id: str,
    request_id: str,
    sources: collections.abc.Iterable[str],
    policy: Policy,
) -> collections.abc.Iterator[Scope]:
    """Bind trusted application identity and decoded untrusted values to one request."""
    if len(tenant_id.strip()) == 0 or len(request_id.strip()) == 0:
        raise ValueError("tenant and request identifiers are required")
    values = tuple(sources)
    if len(values) > 256 or any(
        not isinstance(value, str) or len(value) > 8192 for value in values
    ):
        raise ValueError("request sources exceed supported bounds")
    scope = Scope(
        tenant_id, request_id, tuple(value for value in values if value != ""), policy
    )
    token = _scope.set(scope)
    try:
        yield scope
    finally:
        _scope.reset(token)


def _block(scope: Scope, sink: str, reason: str) -> typing.NoReturn:
    event = Event(scope.tenant_id, scope.request_id, sink, reason)
    scope.events.append(event)
    raise Blocked(event)


def _enforce_patch(scope: Scope, sink: str) -> None:
    if sink in scope.policy.denied_sinks:
        _block(scope, sink, "virtual_patch")


def check_sql(query: str) -> None:
    scope = _scope.get()
    if scope is None:
        return
    _enforce_patch(scope, "sql")
    if any(_source_changes_sql(query, source) is True for source in scope.sources):
        _block(scope, "sql", "request_value_in_statement")


def _source_changes_sql(query: str, source: str) -> bool:
    """Conservative token correlation; short values and literal contents are data."""
    if len(source) < 3:
        return False
    tokens = list(_sql_tokens.finditer(query))
    start = query.find(source)
    while start != -1:
        end = start + len(source)
        overlaps = [token for token in tokens if token.start() < end and token.end() > start]
        if len(overlaps) > 1:
            return True
        if len(overlaps) == 1:
            token = overlaps[0]
            text = token.group()
            if text.startswith(("'", '"', "`", "[", "--", "/*")) is False and token.start() == start and token.end() == end:
                return True
        start = query.find(source, start + 1)
    return False


def _import_hook(original: collections.abc.Callable[..., typing.Any], *, specification: bool = False) -> collections.abc.Callable[..., typing.Any]:
    @functools.wraps(original)
    def import_operation(module: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        token = _import_name.set(module.name if specification is True else module)
        try:
            return original(module, *args, **kwargs)
        finally:
            _import_name.reset(token)
    return import_operation


def _find_module(finder: typing.Any, fullname: str, target: typing.Any = None) -> typing.Any:
    if _import_name.get() != fullname:
        return _finder_spec(finder, fullname, target)
    token = _import_directory.set(os.path.realpath(finder.path))
    try:
        return _finder_spec(finder, fullname, target)
    finally:
        _import_directory.reset(token)


def _code_hook(original: collections.abc.Callable[..., typing.Any]) -> collections.abc.Callable[..., typing.Any]:
    @functools.wraps(original)
    def module_code(loader: typing.Any, fullname: str) -> typing.Any:
        if _import_name.get() != fullname:
            return original(loader, fullname)
        source = loader.get_filename(fullname)
        paths = [os.path.realpath(source)]
        if isinstance(loader, importlib._bootstrap_external.SourceFileLoader) is True:
            paths.append(os.path.realpath(importlib._bootstrap_external.cache_from_source(source)))
        token = _module_paths.set(tuple(paths))
        try:
            return original(loader, fullname)
        finally:
            _module_paths.reset(token)
    return module_code


def _cache_module(loader: typing.Any, path: str, data: bytes, **kwargs: typing.Any) -> None:
    if _scope.get() is not None and loader.name == _import_name.get() and os.path.realpath(path) in _module_paths.get():
        return  # Imports read code; they do not acquire permission to write cache files.
    _loader_write(loader, path, data, **kwargs)


def _init_process(process: subprocess.Popen[typing.Any], *args: typing.Any, **kwargs: typing.Any) -> None:
    scope = _scope.get()
    if scope is not None:
        bound = _popen_signature.bind(process, *args, **kwargs)
        if bool(bound.arguments.get("shell", False)) is True:
            _block(scope, "process", "shell_execution")
    _popen_init(process, *args, **kwargs)


def _check_path(scope: Scope, path: str | bytes | int) -> None:
    _enforce_patch(scope, "file")
    if isinstance(path, int):
        return  # An existing descriptor is a capability acquired by the application.
    if os.path.isabs(os.fsdecode(path)) is False:
        _block(
            scope, "file", "relative_path"
        )  # Audit events do not expose os.open's dir_fd.
    resolved = pathlib.Path(os.path.realpath(os.fsdecode(path)))
    for root in scope.policy.allowed_roots:
        if resolved.is_relative_to(os.path.realpath(root)):
            return
    _block(scope, "file", "outside_allowed_roots")


def _check_process(scope: Scope, executable: str | bytes) -> None:
    _enforce_patch(scope, "process")
    if os.path.isabs(os.fsdecode(executable)) is False:
        _block(scope, "process", "relative_executable")
    resolved = os.path.realpath(os.fsdecode(executable))
    if any(
        resolved == os.path.realpath(allowed)
        for allowed in scope.policy.allowed_executables
    ):
        return
    _block(scope, "process", "executable_not_allowed")


def _check_network(
    scope: Scope, connection: socket.socket, destination: object
) -> None:
    _enforce_patch(scope, "network")
    if connection.family not in {socket.AF_INET, socket.AF_INET6}:
        _block(scope, "network", "unsupported_address_family")
    if not isinstance(destination, tuple) or len(destination) < 2:
        _block(scope, "network", "invalid_address")
    try:
        address = ipaddress.ip_address(destination[0])
    except ValueError:
        # DNS must be resolved explicitly first, so every actual address is checked.
        _block(scope, "network", "unresolved_address")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if any(
        address in ipaddress.ip_network(network)
        for network in scope.policy.allowed_networks
    ):
        return
    if address.is_global is False:
        _block(scope, "network", "nonpublic_address")


def _audit(event: str, args: tuple[typing.Any, ...]) -> None:
    scope = _scope.get()
    if scope is None:
        return
    if event == "open":
        _enforce_patch(scope, "file")
        module_paths = _module_paths.get()
        flags = args[2]
        is_read_only = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) == 0
        if isinstance(args[0], (str, bytes)) and is_read_only is True and os.path.realpath(os.fsdecode(args[0])) in module_paths:
            return  # Only the loader's exact read, never arbitrary reads under sys.path.
        _check_path(scope, args[0])
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.listdir", "os.scandir", "os.chmod", "os.chown", "os.utime", "os.truncate"}:
        _enforce_patch(scope, "file")
        if event == "os.listdir" and isinstance(args[0], (str, bytes)) and os.path.realpath(os.fsdecode(args[0])) == _import_directory.get():
            return  # Only the current FileFinder's import discovery, never application listing.
        _check_path(scope, args[0])
    elif event in {"os.rename", "os.link", "shutil.copyfile", "shutil.copytree"}:
        _check_path(scope, args[0])
        _check_path(scope, args[1])
    elif event == "os.symlink":
        target, link = os.fsdecode(args[0]), os.fsdecode(args[1])
        _check_path(scope, link)
        _check_path(scope, target if os.path.isabs(target) is True else os.path.join(os.path.dirname(link), target))
    elif event == "shutil.rmtree":
        _check_path(scope, args[0])
    elif event in {"subprocess.Popen", "os.exec", "os.posix_spawn"}:
        _check_process(scope, args[0])
    elif event == "os.spawn":
        _check_process(scope, args[1])
    elif event == "os.system":
        _block(scope, "process", "shell_execution")
    elif event == "socket.connect":
        _check_network(scope, args[0], args[1])
    elif event == "pickle.find_class":
        _enforce_patch(scope, "deserialization")
        if scope.policy.block_deserialization is True:
            _block(scope, "deserialization", "pickle_global_resolution")


class Cursor(sqlite3.Cursor):
    def execute(self, sql: str, parameters: typing.Any = ()) -> Cursor:
        check_sql(sql)
        super().execute(sql, parameters)
        return self

    def executemany(self, sql: str, seq_of_parameters: typing.Any) -> Cursor:
        check_sql(sql)
        super().executemany(sql, seq_of_parameters)
        return self

    def executescript(self, sql_script: str) -> Cursor:
        check_sql(sql_script)
        super().executescript(sql_script)
        return self


class Connection(sqlite3.Connection):
    def cursor(self, factory: type[Cursor] = Cursor) -> Cursor:
        if factory is not Cursor:
            raise ValueError("custom cursor factories are not supported")
        return super().cursor(factory)

    def execute(self, sql: str, parameters: typing.Any = ()) -> Cursor:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: typing.Any) -> Cursor:
        return self.cursor().executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> Cursor:
        return self.cursor().executescript(sql_script)


def _connect(*args: typing.Any, **kwargs: typing.Any) -> Connection:
    positional = list(args)
    if len(positional) > 5:
        factory = positional[5]
        if factory is not sqlite3.Connection and factory is not Connection:
            raise ValueError("custom connection factories are not supported")
        positional[5] = Connection
    else:
        factory = kwargs.get("factory", Connection)
        if factory is not sqlite3.Connection and factory is not Connection:
            raise ValueError("custom connection factories are not supported")
        kwargs["factory"] = Connection
    return _sqlite_connect(*positional, **kwargs)


def install() -> None:
    """Install once at process startup, before application imports capture sinks."""
    global _installed
    with _install_lock:
        if _installed is True:
            return
        sys.addaudithook(_audit)
        subprocess.Popen.__init__ = _init_process
        importlib._bootstrap._find_and_load = _import_hook(importlib._bootstrap._find_and_load)
        importlib._bootstrap._find_spec = _import_hook(importlib._bootstrap._find_spec)
        importlib._bootstrap._exec = _import_hook(importlib._bootstrap._exec, specification=True)
        importlib._bootstrap_external.FileFinder.find_spec = _find_module
        importlib._bootstrap_external.SourceFileLoader.get_code = _code_hook(importlib._bootstrap_external.SourceFileLoader.get_code)
        importlib._bootstrap_external.SourcelessFileLoader.get_code = _code_hook(importlib._bootstrap_external.SourcelessFileLoader.get_code)
        importlib._bootstrap_external.SourceFileLoader.set_data = _cache_module
        sqlite3.connect = _connect
        sqlite3.dbapi2.connect = _connect
        _installed = True

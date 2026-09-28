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
import ipaddress
import importlib._bootstrap_external
import inspect
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


@dataclasses.dataclass(frozen=True)
class Policy:
    allowed_roots: tuple[str, ...] = ()
    allowed_executables: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    block_deserialization: bool = True
    denied_sinks: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
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
_loader_read = importlib._bootstrap_external.FileLoader.get_data
_module_read: contextvars.ContextVar[str | None] = contextvars.ContextVar("rasp_module_read", default=None)
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


def _read_module(loader: typing.Any, path: str) -> bytes:
    token = _module_read.set(os.path.realpath(path))
    try:
        return _loader_read(loader, path)
    finally:
        _module_read.reset(token)


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
        module_path = _module_read.get()
        flags = args[2]
        is_read_only = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) == 0
        if module_path is not None and isinstance(args[0], (str, bytes)) and is_read_only is True and os.path.realpath(os.fsdecode(args[0])) == module_path:
            return  # Only the loader's exact read, never arbitrary reads under sys.path.
        _check_path(scope, args[0])
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.listdir", "os.scandir", "os.chmod", "os.chown", "os.utime", "os.truncate"}:
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
        if issubclass(factory, Cursor) is False:
            raise ValueError("custom cursors must preserve RASP interception")
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
        if (
            factory is not sqlite3.Connection
            and issubclass(factory, Connection) is False
        ):
            raise ValueError("custom connections must preserve RASP interception")
        positional[5] = Connection if factory is sqlite3.Connection else factory
    else:
        factory = kwargs.get("factory", Connection)
        if factory is sqlite3.Connection:
            factory = Connection
        if issubclass(factory, Connection) is False:
            raise ValueError("custom connections must preserve RASP interception")
        kwargs["factory"] = factory
    return _sqlite_connect(*positional, **kwargs)


def install() -> None:
    """Install once at process startup, before application imports capture sinks."""
    global _installed
    with _install_lock:
        if _installed is True:
            return
        sys.addaudithook(_audit)
        subprocess.Popen.__init__ = _init_process
        importlib._bootstrap_external.FileLoader.get_data = _read_module
        sqlite3.connect = _connect
        sqlite3.dbapi2.connect = _connect
        _installed = True

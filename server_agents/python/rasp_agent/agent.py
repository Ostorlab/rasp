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
import os
import pathlib
import socket
import sqlite3
import sqlite3.dbapi2
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
    if any(source in query for source in scope.sources):
        _block(scope, "sql", "request_value_in_statement")


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
        sqlite3.connect = _connect
        sqlite3.dbapi2.connect = _connect
        _installed = True

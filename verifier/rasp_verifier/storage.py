"""Scoped persistence contracts; atomic operations are part of the interface."""
from __future__ import annotations

import copy
import dataclasses
import threading
import typing


@dataclasses.dataclass(frozen=True, slots=True)
class Scope:
    tenant_id: str = "default"
    app_id: str = "default"

    def __post_init__(self) -> None:
        if self.tenant_id == "" or self.app_id == "":
            raise ValueError("tenant and application scope are required")


class ConflictError(Exception):
    """An insert-only identity already exists."""


class Store(typing.Protocol):
    scope: Scope

    def get(self, kind: str, record_id: str) -> dict[str, typing.Any] | None: ...
    def put(self, kind: str, record_id: str, value: dict[str, typing.Any], *, insert_only: bool = False) -> None: ...
    def delete(self, kind: str, record_id: str) -> None: ...
    def put_challenge(self, nonce: str, purpose: str, install_id: str, expires_at: float) -> None: ...
    def consume_challenge(self, nonce: str, purpose: str, install_id: str, now: float) -> bool: ...
    def advance_counter(self, key_id: str, counter: int) -> bool: ...
    def bind_install(self, install_id: str, value: dict[str, typing.Any], key_id: str = "") -> None: ...


@dataclasses.dataclass
class _MemoryData:
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    records: dict[tuple[Scope, str, str], dict[str, typing.Any]] = dataclasses.field(default_factory=dict)
    challenges: dict[tuple[Scope, str], tuple[str, str, float]] = dataclasses.field(default_factory=dict)
    counters: dict[tuple[Scope, str], int] = dataclasses.field(default_factory=dict)


class MemoryStore:
    def __init__(self, scope: Scope = Scope(), *, data: _MemoryData | None = None) -> None:
        self.scope = scope
        self._data = _MemoryData() if data is None else data

    def scoped(self, scope: Scope) -> MemoryStore:
        return MemoryStore(scope, data=self._data)

    def get(self, kind: str, record_id: str) -> dict[str, typing.Any] | None:
        with self._data.lock:
            return copy.deepcopy(self._data.records.get((self.scope, kind, record_id)))

    def put(self, kind: str, record_id: str, value: dict[str, typing.Any], *, insert_only: bool = False) -> None:
        key = (self.scope, kind, record_id)
        with self._data.lock:
            if insert_only is True and key in self._data.records:
                raise ConflictError(record_id)
            self._data.records[key] = copy.deepcopy(value)

    def delete(self, kind: str, record_id: str) -> None:
        with self._data.lock:
            self._data.records.pop((self.scope, kind, record_id), None)

    def put_challenge(self, nonce: str, purpose: str, install_id: str, expires_at: float) -> None:
        with self._data.lock:
            key = (self.scope, nonce)
            if key in self._data.challenges:
                raise ConflictError(nonce)
            self._data.challenges[key] = (purpose, install_id, expires_at)

    def consume_challenge(self, nonce: str, purpose: str, install_id: str, now: float) -> bool:
        with self._data.lock:
            key = (self.scope, nonce)
            entry = self._data.challenges.get(key)
            if entry is None or entry[:2] != (purpose, install_id) or entry[2] < now:
                return False
            del self._data.challenges[key]
            return True

    def advance_counter(self, key_id: str, counter: int) -> bool:
        if type(counter) is not int or counter <= 0 or counter > 9223372036854775807:
            return False
        with self._data.lock:
            key = (self.scope, key_id)
            if counter <= self._data.counters.get(key, 0):
                return False
            self._data.counters[key] = counter
            return True

    def bind_install(self, install_id: str, value: dict[str, typing.Any], key_id: str = "") -> None:
        with self._data.lock:
            install_key = (self.scope, "install", install_id)
            binding_key = (self.scope, "app_attest_binding", key_id)
            if install_key in self._data.records:
                raise ConflictError("install_exists")
            if key_id != "" and binding_key in self._data.records:
                raise ConflictError("key_already_bound")
            # Prepare copies before mutating shared state.
            install_value = copy.deepcopy(value)
            binding_value = {"installId": install_id}
            self._data.records[install_key] = install_value
            if key_id != "":
                self._data.records[binding_key] = binding_value

"""PostgreSQL store. Each operation uses a transaction-local application scope."""
from __future__ import annotations

import contextlib
import importlib.resources
import typing
import types

import psycopg
import psycopg_pool
from psycopg.types import json as pg_json

from rasp_verifier import storage


def migrate(dsn: str) -> None:
    """Run idempotent schema migration using a separate schema-owner connection."""
    source = importlib.resources.files("rasp_verifier").joinpath("migrations/001_trust.sql").read_text()
    with psycopg.connect(dsn) as connection:
        connection.execute(source)


class PostgresStore:
    def __init__(self, dsn: str, scope: storage.Scope) -> None:
        self.dsn = dsn
        self.scope = scope
        self.pool = psycopg_pool.ConnectionPool(dsn, min_size=0, max_size=8, open=True)

    def close(self) -> None:
        """Close this scoped store's owned pool after all callers have stopped."""
        self.pool.close()

    def __enter__(self) -> PostgresStore:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: types.TracebackType | None) -> None:
        self.close()

    def scoped(self, scope: storage.Scope) -> PostgresStore:
        return PostgresStore(self.dsn, scope)

    @contextlib.contextmanager
    def transaction(self) -> typing.Iterator[psycopg.Connection]:
        with self.pool.connection() as connection:
            connection.execute("SELECT set_config('rasp.tenant_id', %s, true), set_config('rasp.app_id', %s, true)",
                               (self.scope.tenant_id, self.scope.app_id))
            yield connection

    def get(self, kind: str, record_id: str) -> dict[str, typing.Any] | None:
        with self.transaction() as connection:
            row = connection.execute("SELECT value FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind=%s AND record_id=%s",
                                     (self.scope.tenant_id, self.scope.app_id, kind, record_id)).fetchone()
            return None if row is None else row[0]

    def put(self, kind: str, record_id: str, value: dict[str, typing.Any], *, insert_only: bool = False) -> None:
        clause = "DO NOTHING" if insert_only is True else "DO UPDATE SET value=EXCLUDED.value"
        with self.transaction() as connection:
            row = connection.execute(
                "INSERT INTO rasp_records (tenant_id,app_id,kind,record_id,value) VALUES (%s,%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id,app_id,kind,record_id) " + clause + " RETURNING record_id",
                (self.scope.tenant_id, self.scope.app_id, kind, record_id, pg_json.Jsonb(value))).fetchone()
            if row is None:
                raise storage.ConflictError(record_id)

    def delete(self, kind: str, record_id: str) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind=%s AND record_id=%s",
                               (self.scope.tenant_id, self.scope.app_id, kind, record_id))

    def put_challenge(self, nonce: str, purpose: str, install_id: str, expires_at: float) -> None:
        with self.transaction() as connection:
            row = connection.execute(
                "INSERT INTO rasp_challenges VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING nonce",
                (self.scope.tenant_id, self.scope.app_id, nonce, purpose, install_id, expires_at)).fetchone()
            if row is None:
                raise storage.ConflictError(nonce)

    def consume_challenge(self, nonce: str, purpose: str, install_id: str, now: float) -> bool:
        with self.transaction() as connection:
            row = connection.execute(
                "DELETE FROM rasp_challenges WHERE tenant_id=%s AND app_id=%s AND nonce=%s AND purpose=%s "
                "AND install_id=%s AND expires_at >= %s RETURNING nonce",
                (self.scope.tenant_id, self.scope.app_id, nonce, purpose, install_id, now)).fetchone()
            return row is not None

    def advance_counter(self, key_id: str, counter: int) -> bool:
        if type(counter) is not int or counter <= 0 or counter > 9223372036854775807:
            return False
        with self.transaction() as connection:
            row = connection.execute(
                "INSERT INTO rasp_counters VALUES (%s,%s,%s,%s) ON CONFLICT (tenant_id,app_id,key_id) "
                "DO UPDATE SET counter=EXCLUDED.counter WHERE rasp_counters.counter < EXCLUDED.counter RETURNING counter",
                (self.scope.tenant_id, self.scope.app_id, key_id, counter)).fetchone()
            return row is not None

    def bind_install(self, install_id: str, value: dict[str, typing.Any], key_id: str = "") -> None:
        with self.transaction() as connection:
            row = connection.execute(
                "INSERT INTO rasp_records VALUES (%s,%s,'install',%s,%s) ON CONFLICT DO NOTHING RETURNING record_id",
                (self.scope.tenant_id, self.scope.app_id, install_id, pg_json.Jsonb(value))).fetchone()
            if row is None:
                raise storage.ConflictError("install_exists")
            if key_id != "":
                row = connection.execute(
                    "INSERT INTO rasp_records VALUES (%s,%s,'app_attest_binding',%s,%s) ON CONFLICT DO NOTHING RETURNING record_id",
                    (self.scope.tenant_id, self.scope.app_id, key_id, pg_json.Jsonb({"installId": install_id}))).fetchone()
                if row is None:
                    raise storage.ConflictError("key_already_bound")

"""Real PostgreSQL tests require an isolated migrated database and runtime role."""
from __future__ import annotations

import os
import unittest
import uuid

import psycopg

from rasp_verifier import postgres
from rasp_verifier import storage
from tests import test_storage
from tests import test_trust
from tests import helpers
from rasp_verifier import durable_registry
from rasp_verifier import registry
from rasp_verifier import trust
from rasp_verifier import jose
from rasp_verifier import platform

@unittest.skipUnless(os.environ.get("RASP_TEST_POSTGRES_DSN"), "requires isolated PostgreSQL DSN")
class PostgresStorageTest(test_storage.MemoryStorageTest):
    def setUp(self) -> None:
        self.scope = storage.Scope(uuid.uuid4().hex, "com.example")
        self.store = postgres.PostgresStore(os.environ["RASP_TEST_POSTGRES_DSN"], self.scope)
        self.other = self.store.scoped(storage.Scope("other-" + self.scope.tenant_id, self.scope.app_id))

    def testRecords_whenStoreRecreated_preservesData(self) -> None:
        self.store.put("build", "durable", {"value": 123})
        restarted = self.store.scoped(self.scope)
        self.assertEqual(restarted.get("build", "durable"), {"value": 123})

    def testRls_whenQueryOmitsScope_filtersRowsAndRejectsCrossTenantWrites(self) -> None:
        self.store.put("secret", "same", {"owner": "one"})
        self.other.put("secret", "same", {"owner": "two"})
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute("SELECT value FROM rasp_records").fetchall(), [({"owner": "one"},)])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.store.transaction() as connection:
                connection.execute("INSERT INTO rasp_records VALUES (%s,%s,'secret','forged','{}')", (self.other.scope.tenant_id, self.scope.app_id))


@unittest.skipUnless(os.environ.get("RASP_TEST_POSTGRES_DSN"), "requires isolated PostgreSQL DSN")
class PostgresTrustFlow(test_trust.TrustFlow):
    def setUp(self) -> None:
        self.scope = storage.Scope(uuid.uuid4().hex, helpers.PACKAGE)
        self.state = postgres.PostgresStore(os.environ["RASP_TEST_POSTGRES_DSN"], self.scope)
        builds = durable_registry.BuildRegistry(self.state)
        builds.register(registry.Build(helpers.BUILD_ID, helpers.BUILD_KEY, helpers.PACKAGE, [helpers.APP_CERT_SHA256]))
        self.trust = trust.TrustService(signing_key=jose.SigningKey.generate(), package_name=helpers.PACKAGE,
            signing_cert_sha256=[helpers.APP_CERT_SHA256], builds=builds, state=self.state,
            platform_attestation=platform.StubPlatformAttestation())

    def testTrust_whenProcessStateRecreated_usesPersistedInstall(self) -> None:
        chain, _ = self._bind()
        previous = self.trust
        self.trust = trust.TrustService(signing_key=previous.signing_key, package_name=helpers.PACKAGE,
            signing_cert_sha256=[helpers.APP_CERT_SHA256], builds=durable_registry.BuildRegistry(self.state.scoped(self.scope)),
            state=self.state.scoped(self.scope), platform_attestation=platform.StubPlatformAttestation())
        self.assertEqual(self._token(chain)["risk"], "none")

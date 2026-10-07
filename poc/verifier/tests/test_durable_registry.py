"""Scoped persistence adapters retain identity and monotonic revocation."""
from __future__ import annotations

import unittest

from rasp_verifier import durable_registry
from rasp_verifier import registry
from rasp_verifier import storage
from tests import helpers


class DurableRegistryTest(unittest.TestCase):
    def testBuild_whenReregisteredAfterRevocation_staysRevoked(self) -> None:
        state = storage.MemoryStore(storage.Scope("tenant", helpers.PACKAGE))
        builds = durable_registry.BuildRegistry(state)
        build = registry.Build(helpers.BUILD_ID, helpers.BUILD_KEY, helpers.PACKAGE, [helpers.APP_CERT_SHA256])
        builds.register(build)
        self.assertEqual(builds.get(build.build_id), build)
        builds.revoke(build.build_id)
        builds.register(build)
        with self.assertRaises(registry.RegistryError):
            builds.get(build.build_id)

    def testInstall_whenDuplicateBound_preservesKeyAndTenant(self) -> None:
        state = storage.MemoryStore(storage.Scope("tenant", helpers.PACKAGE))
        installs = durable_registry.InstallRegistry(state)
        install = registry.Install("install", b"public-key", "thumb", "tee", "verified", True, None, True)
        installs.bind(install)
        with self.assertRaises(registry.RegistryError):
            installs.bind(install)
        self.assertEqual(installs.get("install"), install)
        other = durable_registry.InstallRegistry(state.scoped(storage.Scope("other", helpers.PACKAGE)))
        with self.assertRaises(registry.RegistryError):
            other.get("install")
        installs.unbind("install")
        with self.assertRaises(registry.RegistryError):
            installs.get("install")

"""Build/install registries backed by a scoped Store."""
from __future__ import annotations

import base64
import dataclasses

from rasp_verifier import registry
from rasp_verifier import storage


class BuildRegistry:
    def __init__(self, store: storage.Store) -> None:
        self.store = store
        self.scope = store.scope

    def register(self, build: registry.Build) -> None:
        data = dataclasses.asdict(build)
        data["build_key"] = build.build_key.hex()
        self.store.put("build", build.build_id, data)

    def register_manifest(self, data: dict) -> registry.Build:
        build = registry.Build.from_manifest(data)
        self.register(build)
        return build

    def get(self, build_id: str) -> registry.Build:
        data = self.store.get("build", build_id)
        if data is None:
            raise registry.RegistryError("unknown_build", build_id)
        data["build_key"] = bytes.fromhex(data["build_key"])
        build = registry.Build(**data)
        if build.revoked is True or self.store.get("build_revocation", build_id) is not None:
            raise registry.RegistryError("revoked_build", build_id)
        return build

    def revoke(self, build_id: str) -> None:
        # Revocation is a separate monotonic record: concurrent registration cannot erase it.
        self.store.put("build_revocation", build_id, {"revoked": True})


class InstallRegistry:
    def __init__(self, store: storage.Store) -> None:
        self.store = store
        self.scope = store.scope

    def bind(self, install: registry.Install) -> None:
        data = dataclasses.asdict(install)
        data["public_key_der"] = base64.b64encode(install.public_key_der).decode()
        try:
            self.store.put("install", install.install_id, data, insert_only=True)
        except storage.ConflictError as error:
            raise registry.RegistryError("install_exists", install.install_id) from error

    def get(self, install_id: str) -> registry.Install:
        data = self.store.get("install", install_id)
        if data is None:
            raise registry.RegistryError("unknown_install", install_id)
        data["public_key_der"] = base64.b64decode(data["public_key_der"], validate=True)
        return registry.Install(**data)

    def unbind(self, install_id: str) -> None:
        self.store.delete("install", install_id)

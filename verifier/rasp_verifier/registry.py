"""In-memory registries for the trust service: genuine builds and bound installs.

A real deployment backs these with a database (the design calls for Postgres). They are kept as small,
thread-safe classes here so the reference trust service runs from a single process for demos and tests.

- Build registry: the identity of each genuine build the hardener produced — its per-build MAC key (used to
  verify the sealed report), the app package and signing-certificate digests, and whether it is revoked. A
  report whose `buildId` is unknown or revoked is refused.
- Install registry: the public key each install bound with hardware Key Attestation, plus the attestation
  summary (security level, verified boot, per-use user auth). Token issuance verifies a proof of possession
  against this key, so a token is tied to the exact install that bound.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class RegistryError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class Build:
    build_id: str
    build_key: bytes
    package_name: str
    signing_cert_sha256: list[str]
    revoked: bool = False


class BuildRegistry:
    def __init__(self, builds: list[Build] | None = None):
        self._lock = threading.Lock()
        self._builds: dict[str, Build] = {b.build_id: b for b in builds or []}

    def register(self, build: Build) -> None:
        with self._lock:
            self._builds[build.build_id] = build

    def revoke(self, build_id: str) -> None:
        with self._lock:
            build = self._builds.get(build_id)
            if build is not None:
                build.revoked = True

    def get(self, build_id: str) -> Build:
        with self._lock:
            build = self._builds.get(build_id)
        if build is None:
            raise RegistryError("unknown_build", build_id)
        if build.revoked:
            raise RegistryError("revoked_build", build_id)
        return build


@dataclass
class Install:
    install_id: str
    public_key_der: bytes
    thumbprint: str
    security_level: str
    verified_boot_state: str | None
    device_locked: bool | None
    os_patch_level: int | None
    user_auth_required: bool
    attestation_warnings: list[str] = field(default_factory=list)
    bound_at: float = field(default_factory=time.time)


class InstallRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._installs: dict[str, Install] = {}

    def bind(self, install: Install) -> None:
        with self._lock:
            self._installs[install.install_id] = install

    def get(self, install_id: str) -> Install:
        with self._lock:
            install = self._installs.get(install_id)
        if install is None:
            raise RegistryError("unknown_install", install_id)
        return install

    def unbind(self, install_id: str) -> None:
        with self._lock:
            self._installs.pop(install_id, None)

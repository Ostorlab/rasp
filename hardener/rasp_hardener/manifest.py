"""Build-registration manifest (design §6 "build registration"; §7 build registry).

Every hardened build must be registered with the trust service before its sealed reports are accepted: the
service keys on ``build_id`` and needs the matching ``build_key`` to verify the report MAC, the app identity to
match against attestation, and the code identity to know what it registered. This module produces that record.

The manifest is SECRET server-side material — it carries ``build_key_hex``. It is meant to be delivered to the
trust service over a trusted channel (CI secret, not committed), then loaded into the build registry (see
``verifier``'s ``BuildRegistry.from_manifest``). The build *seed* is never included; only a non-secret
fingerprint, so a build can be correlated without being reproduced.
"""

from __future__ import annotations

import json
import pathlib
import time
from dataclasses import asdict, dataclass, field

from rasp_hardener import codehash
from rasp_hardener.seed import BuildProfile

MANIFEST_VERSION = "raxp-build-manifest-1"


@dataclass
class BuildManifest:
    build_id: str
    build_key_hex: str
    package_name: str
    signing_cert_sha256: list[str]
    code_hashes: dict[str, str] = field(default_factory=dict)
    integrity_root: str = ""
    # File offset/length ranges the device hashes at runtime to reproduce `integrity_root` (design §8),
    # present when the build was hashed from a compiled `.so`. Empty for the legacy source-hash root.
    integrity_regions: list[dict] = field(default_factory=list)
    seed_fingerprint: str = ""
    created_at: float = field(default_factory=time.time)
    revoked: bool = False
    version: str = MANIFEST_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def write(self, path: str | pathlib.Path) -> None:
        pathlib.Path(path).write_text(self.to_json() + "\n")

    @classmethod
    def from_dict(cls, data: dict) -> "BuildManifest":
        known = {f: data[f] for f in cls.__dataclass_fields__ if f in data}
        return cls(**known)

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "BuildManifest":
        return cls.from_dict(json.loads(pathlib.Path(path).read_text()))


def build_manifest(
    profile: BuildProfile,
    *,
    package_name: str,
    signing_cert_sha256: list[str],
    code_paths: list[str | pathlib.Path] | None = None,
    so_path: str | pathlib.Path | None = None,
) -> BuildManifest:
    """Assemble a manifest for `profile`.

    When `so_path` is given, the integrity root is taken over the compiled `.so`'s code/read-only regions —
    the exact bytes the device reproduces at runtime (design §8), and the regions are recorded so the device
    knows what to hash. Otherwise it falls back to the legacy root over `code_paths` source hashes plus the
    signing cert.
    """
    code_hashes = codehash.hash_paths(code_paths) if len(code_paths or []) > 0 else {}
    if so_path is not None:
        root, regions = codehash.so_integrity_root(so_path)
        integrity_regions = [{"offset": off, "length": size} for (off, size) in regions]
    else:
        integrity_regions = []
        # The signing cert is part of the code identity, so bind it whenever either input is present — not
        # only when code files were hashed (otherwise `register` with just --cert would drop the cert).
        if len(code_hashes) > 0 or len(signing_cert_sha256) > 0:
            root = codehash.integrity_root(code_hashes, signing_cert_sha256)
        else:
            root = ""
    return BuildManifest(
        build_id=profile.build_id,
        build_key_hex=profile.build_key_hex,
        package_name=package_name,
        signing_cert_sha256=list(signing_cert_sha256),
        code_hashes=code_hashes,
        integrity_root=root,
        integrity_regions=integrity_regions,
        seed_fingerprint=profile.seed_fingerprint,
    )

"""rasp-hardener: the build-time hardening toolchain for flutter_rasp (design §6).

Given a random per-build seed it derives the build's secrets and layout (:mod:`seed`), encrypts the native
string registry (:mod:`literals`, :mod:`strenc`), derives internal symbol names (:mod:`names`), emits the C headers the native build consumes (:mod:`emit`), hashes the code
into an integrity root via the guard mesh (:mod:`codehash`, :mod:`guardmesh`), and produces the registration
manifest the trust service loads (:mod:`manifest`). The CLI in :mod:`cli` ties these into ``gen-build`` /
``show`` / ``register`` commands for CI.

It also carries the §8 white-box crypto pieces: a FIPS-197 AES-128 reference (:mod:`aes`) and optionally affine encoded
white-box AES table generation (:mod:`whitebox`) for the native SecureStore.

Additional modules provide a bounded seeded arithmetic VM and authenticated resources
with integrity-derived data keys. The compiler and build integration directories
contain opt-in LLVM and Gradle transformations. Supported scopes and unimplemented
advanced protections are documented in hardener/DEEP_HARDENING.md.
"""

from rasp_hardener.guardmesh import guard_offset, guard_root
from rasp_hardener.manifest import BuildManifest, build_manifest
from rasp_hardener.seed import BuildProfile
from rasp_hardener.whitebox import WhiteBoxTables
from rasp_hardener.whitebox import generate as generate_whitebox

__all__ = [
    "BuildProfile",
    "BuildManifest",
    "build_manifest",
    "guard_root",
    "guard_offset",
    "WhiteBoxTables",
    "generate_whitebox",
]

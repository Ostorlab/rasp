"""rasp-hardener: the build-time hardening toolchain for flutter_rasp (design §6).

Given a random per-build seed it derives the build's secrets and layout (:mod:`seed`), encrypts the native
string literals (:mod:`strenc`), emits the C headers the native build consumes (:mod:`emit`), hashes the code
into an integrity root via the guard mesh (:mod:`codehash`, :mod:`guardmesh`), and produces the registration
manifest the trust service loads (:mod:`manifest`). The CLI in :mod:`cli` ties these into ``gen-build`` /
``show`` / ``register`` commands for CI.

This is the Python-implemented portion of the design's build-time hardening. The LLVM/O-LLVM native
obfuscation passes, the DEX/ASM Gradle plugin, and code virtualization remain future work (see the repo TODO).
"""

from .guardmesh import guard_offset, guard_root
from .manifest import BuildManifest, build_manifest
from .seed import BuildProfile

__all__ = ["BuildProfile", "BuildManifest", "build_manifest", "guard_root", "guard_offset"]

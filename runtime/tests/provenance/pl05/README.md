# Frozen PL05 source for the Apple acceptance gate

This is the complete 215-file tracked source tree of `Ostorlab/rasp-plugins`
commit `eb7e4306eeaf449031822910c73e1ecc9d0a34f2`, tree
`8e91681d074a16e4e1c444f1e88e2d244db4474e`. It replaces a private cross-repository
checkout that the runtime repository's default CI token cannot fetch. It grants
no new token authority and does not weaken or skip the combined Apple gate.

`source.tar` is deterministic uncompressed USTAR: sorted regular files, original
0644/0755 modes, zero owner IDs/names and timestamps, no directory/link/PAX entries.
`inventory.json` records every path, Git mode/blob, length and SHA256, plus archive
and raw commit integrity. `commit.raw` is the exact Git commit payload, with its
original tree and parent identifier; there is no repository history or `.git`.
The archive SHA256 is
`ab5f0cf933fb4f1dc93d96ca7d75f6be121035e8fb5053da46578f04453f0bca`.

The exact tracked tree includes its existing curl, Mbed TLS and yyjson **source**
archives and the vendored runtime API headers. These cannot be removed while
claiming the pinned 215-file tree. There are no fetched/unpacked build dependency
caches, build outputs, environment files, account credentials or backend archives.
Tracked test fixtures and workflow files remain source, under the ignored build
path; their presence is not a new workflow or a deployment.

From `runtime/`, `python3 tools/pl05_snapshot.py` validates the complete archive,
Git blob/tree encodings and pinned commit hash. `--extract` performs the same
validation before creating only the fresh, known ignored
`runtime/build/rt19-plugin-sources` destination. An existing destination fails;
there is no overwrite, merge, Git initialization, fetch or credential fallback.
The exporter uses this same validator and rechecks every extracted byte/mode,
recording `kind: frozen_verified_source` and the full inventory.

The validator accepts only this exact source. It rejects unexpected, duplicate,
absolute, traversal, link, special-file and metadata entries; missing/changed
bytes or modes; altered commit/tree pins; noncanonical, compressed, truncated,
concatenated or trailing archive content. It bounds archive bytes to 8MiB,
individual files to 2MiB, inventory to 256KiB, commit payload to 4KiB, paths to
240 ASCII characters/16 components, and membership to exactly 215 files.
Extraction writes validated regular data exclusively, never `extractall`.

Reproduction requires the immutable source objects, not a sibling checkout:
read `git cat-file commit <pin>`, `git ls-tree -rz <pin>` and `git cat-file blob`
for all 215 entries; serialize sorted paths with the USTAR settings above.
Independently compare every original blob/mode, every reconstructed Git subtree
payload and the raw commit, and regenerate identical archive bytes. The original
local generation/audit scripts and their hashes are retained with the RT19
snapshot task evidence. Changes to this pin require a new reviewed snapshot.

Focused tests run with `PYTHONPATH=runtime/tools python -m pytest runtime/tools/tests`.
They prove source/extraction/export integrity, not an Apple build, an installed
IPA, device execution, signing, attestation or backend acceptance. All existing
Apple build/consumer/strict/min12/export/O-MVLL gates remain required.

RT22 refreshes only the current snapshot association. The previous1197/b155 snapshot remains available in immutable native parent `db5d62f69b1404441753fde6be6c5f204ccd5aaa` (214 files, archive SHA256 `007003ebb7671dc7b394fc1a887df020961b4f497b49c7b60119ed98578ca143`); it is not relabelled as new-source build or device evidence.

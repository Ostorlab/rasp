# Release-specific built-in capabilities (schema 1, revision 1)

`packer/src/rasp_packer/checks_manifest.json` is the source of truth for this revision's
21 Android and 24 iOS built-in `(group, signal, source)` entries. It was audited against
`runtime/{android,ios}/src/checks/*.cpp` and the production `builtin.cpp` dispatchers,
including PR215 iOS integrity. `checks.py` reads this catalogue for requested, required
and default selection. Identity is required by the public packer; no `--checks` means
identity only. Unknown requested names are skipped and reported; repeated names count
once. Native config parsing itself does not force identity when given absent/empty checks.

Each entry declares its successful value kind (`none` for an always-unsupported source),
one observation per invocation, possible
statuses and support conditions. `string_list` values have variable length, including zero;
list members are data, not additional signal/source identities. Android supports the four
listed ABIs at API31+, iOS the shipped arm64/iOS12+ device build. `ios_device` probes emit
unsupported on simulators/non-iOS hosts; `apple` emulator tells also work on simulators;
`never` means an explicit unsupported observation (iOS user CAs). Android probes emit
unsupported off Android. OS floors and ABI lists describe the supported release presets;
other build targets/floors are rejected by the producer until deliberately modelled.
Read `behavior` for per-source limitations and partial-data behavior. Non-OK statuses have
no value. None of these built-ins emits timeout today, although the observation type
supports it. This catalogue cannot establish that a probe completed or ran.

## Binding production to consumption

CMake emits `<binary>.capabilities.json` using `runtime/tools/capabilities.py` after linking.
The sidecar contains the full catalogue, schema version, SHA-256 of its canonical JSON,
SHA-256 of the **pristine linked bytes**, platform, ABI and OS floor. The binary digest
changes across different source/compiler/plugin builds sharing the same runtime version.
No exports, constructors or runtime code are added for metadata. Plugin signal names,
cardinality and possible plugin changes to built-in delivery remain **unmodelled**.

`cmake --install build/android --prefix <stage> --component runtime` stages the library
and sidecar under `rasp_packer/android/resources/lib/<abi>/`. The same command with
`build/ios` stages the entire framework, including its adjacent sidecar, under
`rasp_packer/ios/resources/`. Add the separately built Android `stub.dex` as documented in
the runtime README. Copy those staged package resources into `packer/src/rasp_packer/`
before building the wheel. Package-resource discovery uses `importlib.resources`, including
installed wheels. There is no separate release-publishing workflow in this base;
`.github/workflows/runtime.yml` now stages and validates both native release platforms
through the production packer binding and config readers/writers.

Before config mutation, Android resources and the APK/AAB consumer validate the exact
selected library bytes; iOS validates the exact pristine framework bytes it then writes.
Validation bounds JSON size (128 KiB), rejects duplicate keys/groups/signal-source pairs,
unknown structure/schema/kinds/statuses/conditions, foreign catalogue identities, target
mismatches and byte digest mismatches. Even a self-consistent foreign catalogue is refused;
there is no runtime-version-string lookup or fallback to the installed catalogue.

Missing sidecar = legacy/unknown. Legacy packing continues with the documented check
selection semantics, but `PackResult.capability_bindings` is `None`. A mix of known and
legacy selected ABIs is also unknown. Invalid **present** sidecars fail packing with
`InvalidRuntimeError`; no protected output is written. Copying a newly generated sidecar
onto an old binary is not a valid release process: only its actual source build may emit
capabilities. Hashes are association/integrity checks inside the release distribution,
not tamper resistance, signatures, signature verification or device attestation.

The public `PackResult` exposes `effective_checks` (the config actually written) and
`capability_bindings` (one `catalogue_id`, pristine `artifact_sha256`, platform, ABI and
minimum OS per injected native artifact). `None` must never be expanded into current
expectations. The CLI prints unknown capabilities explicitly. Config insertion changes
binary bytes: the registered digest identifies the pre-config artifact, not a hash of the
customer's configured/signed executable. The pristine iOS sidecar is removed from the copied framework before mutation; its
provenance is returned to the caller, while the source artifact and sidecar stay untouched.

## Complete-cycle / server-health dependency contract

`docs/fixtures/check-capabilities-v1.json` supplies selection/unknown-status examples.
Register build ID, platform, effective groups and **validated** artifact bindings together
in the authenticated backend build registry. Resolve outputs only for the exact registered
catalogue identity; preserve per-ABI provenance. Reject unknown IDs/schema or mark health
unsupported. Never populate current expectations for an unmatched release or `None`.

For an enabled group, a future complete-cycle envelope must distinguish fixed observation
identities from variable list values, snapshot vs delta, dropped/truncated outputs, error,
unsupported and eventual timeout. Plugins can add/change delivery; their outputs cannot
be assumed complete from this catalogue. Error/unsupported do not mean clean or missing;
empty values are present observations. No cycle IDs, completion envelope, transport retry
idempotency, server missing-check verdicts or freshness policy are implemented here.
Silence/offline/suspension cannot establish runtime removal or bypass. Those workers must
register the manifest alongside build config and explicitly add cycle/transport contracts.

## Adding checks and integrating RT03/RT04

Neither RT03 nor RT04 is present on base `fca230fa669a8a97c5c45dbf8dab9825930d374e`.
When integrated, update this same catalogue and bump revision before emitting artifacts:

- RT03: register `hook.threads/proc_task` (string list; OK/error/unsupported), plus incomplete,
  disappearing, denied, malformed, task-limit and truncation behavior from its final code.
  Do not call generic gmain a marker or claim every renamed/hidden thread is visible.
- RT04: register `proc_status_syscall` and `proc_maps_syscall`, and each added Android
  syscall-wrapper path source independently with its failures;
  register iOS direct sysctl/parent sources with their actual arm64/API gates and explicit
  unsupported observations elsewhere. Preserve source divergence. A libc syscall wrapper
  is hookable and is not an attestation source.
- Future checks: add actual dispatch groups/output identities and required semantics,
  model dynamic identities/cardinality explicitly (or mark unmodelled), retain typed values
  and non-OK statuses, update contract fixtures and compiled dispatch tests, then rebuild
  and distribute **binary plus sidecar**. New catalogue identities require deliberate
  consumer/backend registry support; older consumer versions refuse them.

## External publisher and final-stack follow-ups

The separate `rasp-plugins` repository's
`.github/workflows/publish-packer.yml:252` currently stages only Android `librasp.so`,
dropping the adjacent `.capabilities.json`. Its publisher must copy **both files** for
every ABI, preserve their association through wheel creation, and verify the installed
wheel with the production consumer. Its iOS tar path preserves the sidecar. This checkout
does not change that external publisher. Until that follow-up lands, published Android
artifacts lacking sidecars remain explicitly unknown; they must not receive this catalogue's
expectations merely because the packer has it installed.

The final integration stack must incorporate reviewed/normalized RT04 upstream sources
and then update the catalogue revision, source contracts, tests and producer/consumer
artifacts together. This branch's catalogue covers only the approved PR215 base; it is
not complete for later RT03/RT04 sources. Root owns that dependency sequence and publisher
follow-up. Local artifact/wheel validation here includes the sidecar deliberately and does
not establish that the separate publisher currently preserves Android provenance.

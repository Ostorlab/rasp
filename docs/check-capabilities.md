# Release-specific built-in capabilities

An old or unmatched runtime must never silently receive the installed packer's current
output expectations. The packer assigns capabilities only when a sidecar matches the exact
pristine native binary, platform and supported ABI. A runtime version string is insufficient
because different source, compiler or plugin builds can share it.

`packer/src/rasp_packer/checks_manifest.json` is the versioned source of truth for built-in
group, signal and source identities. Its entries come from the platform check implementations
and production `builtin.cpp` dispatchers. The catalogue describes possible outputs, not
execution evidence or device attestation. Schema 1, revision 7 declares 52 Android and 26 iOS
built-in signal/source identities.

The current canonical catalogue ID is `c6ed667281a13f3072a886b6b1cbc10d352b354299266669438239045a5b6daf`. Revision6
`c996747579cf54fbb5af396f3b70d707407ca3146e582897474f1070e2746be5` remains
foreign to this revision7 consumer even with matching pristine bytes and sidecar.

Revision5 adds four [Android identity observations](android-signer-observations.md): actual
Application package, complete current signer sets from APK and PackageManager, and ordered
single-signer rotation history. The two legacy certificate outputs remain first-signer
strings. Identity has nine expected outputs; error/unsupported sources are present coverage,
not missing or benign. Native cycle identities and typed test expectations generate from
the canonical manifest without a draft overlay; RT07's immutable metadata/observation handoff
and all RT06/RT08 collectors remain intact.

## Group selection and output semantics

`checks.py` resolves config groups from each platform's own catalogue entry:

- Identity is required on both current platforms; no `--checks` selects identity only.
- Unknown requested names are skipped and reported; repeated names count once.
- `REQUIRED_CHECKS_BY_PLATFORM` supplies required groups for the selected platform.
  `REQUIRED_CHECKS` remains the compatibility view of groups required on every platform.
- Native parsing does not force identity when config checks are absent or empty.

Each source declares an observation count, successful value kind, statuses and support
conditions. `string_list` values may contain zero or more members; those members are data,
not additional observation identities. An always-unsupported source declares value kind
`none`. Non-OK observations have no value. Read each entry's `behavior` for partial-data,
read-error and truncation limits.

Android `hook.inline/prologue` emits one observation with a variable string list of at most
32 distinct changed libc/libdl names in fixed resolution order. An empty OK list requires all
32 comparisons to succeed. Unavailable symbols/libraries, invalid ELF/maps, incomparable
relocations and denied/short/stale memory reads are error results with no value or partial
list. Off Android or on an unimplemented Android build architecture it is unsupported.
Authorized instrumentation can change these bytes; this is not a malware verdict. The fixed
list cannot cover other inline sites, renamed/unlisted targets, hidden modules or matching
modified disk/memory; its APIs remain hookable. See [the mechanism and limits](../runtime/inline_hooks.md).
The schema's `value_cardinality` remains `variable`; its bound is specified in `behavior`,
as for the existing map/thread list outputs. Revision 2 and 3 artifacts remain foreign to this
consumer even when their sidecars match their own pristine bytes.

Android's opt-in `accessibility`, `input_method` and `notification_access` groups add four
fixed output identities. Accessibility emits enabled component/capability/request-mask records;
IME emits an enabled-component list plus the API34+ selected component; notification access
emits enabled-listener components through the AndroidX-compatible secure setting. API31–33
selected IME is explicitly unsupported, never inferred from the enabled list. The schema1
`android` support condition names the platform; each row's `behavior` supplies its API gates,
Context requirements, limits and null/error contract. Read [exact contracts and primary API
provenance](android-service-observations.md) and the [portable benign/positive/unknown fixtures](fixtures/android-service-observations-v1.json).
Null/denied/malformed/over-limit values are unknown/error; only complete explicit empty lists
or settings strings can be empty OK. Assistive services/keyboards and authorized support tools
are legitimate context. Neither enabled access nor capability flags establish malware or
active control. Existing groups, identity-only defaults and all iOS outputs are preserved.

Android's supported release presets target API31+ and the four listed ABIs. The iOS release
preset and consumer support arm64/iOS12+. `ios_device` probes emit unsupported on simulators
and non-iOS hosts; `apple` emulator tells also work on simulators; `never` means an explicit
unsupported observation, such as iOS user CAs. Android probes emit unsupported off Android.
Other build floors and targets require deliberate catalogue and consumer support.

The iOS consumer's expected ABI is `macho.RUNTIME_ABI`, matching the ARM64 slices that
`macho.add_runtime` instruments. Metadata is checked against that contract; a sidecar cannot
choose its own accepted architecture. Adding another ABI requires changes to the actual
consumer and build support, not just a new sidecar value.

## Native build and packer binding

A capabilities sidecar is the adjacent `<binary>.capabilities.json` file emitted by the
native CMake build. It contains the full catalogue, schema version, canonical catalogue
SHA-256, pristine linked-binary SHA-256, platform, ABI and OS floor. The build is the producer;
the packer is the consumer that validates those bytes before inserting app config.

Build and stage instructions are in [the runtime build guide](../runtime/README.md#build)
and the platform package-resource READMEs. Ship each binary and its sidecar together. Package
discovery uses `importlib.resources`, including installed wheels. Native CI stages real
release artifacts and checks binding plus production config readers and writers.

Validation bounds JSON to 128 KiB and rejects duplicate keys, groups or signal/source pairs;
unknown structure, schema, kinds, statuses or support conditions; foreign catalogue
identities; target/floor mismatches; and changed binary digests. A self-consistent foreign
catalogue is still refused. There is no runtime-version lookup or current-catalogue fallback.

A missing sidecar permits legacy packing with unknown capabilities:
`PackResult.capability_bindings` is `None`. A selected mixture of known and legacy ABIs is
also unknown. Invalid present metadata raises `InvalidRuntimeError` before protected output
creation. Generating new metadata for an arbitrary old binary is not a valid release process;
capabilities must come from that binary's actual source build.

Config insertion changes the binary. On iOS, the pristine sidecar is removed from the copied
framework before mutation; the source binary and sidecar stay untouched. Returned provenance
identifies the validated source artifact, not the configured or customer-signed executable.

`PackResult.effective_checks` records the groups actually written into config.
`capability_bindings` records each selected native artifact's catalogue identity, pristine
byte digest, platform, ABI and minimum OS. The CLI prints unknown capabilities explicitly.
Direct platform `AppIdentity` access, equality and hashing remain compatible.

These hashes associate files inside a trusted release distribution. They do not authenticate
a release, resist an attacker who changes both files, prove a check ran or attest a device.
Plugin outputs, cardinality and changes to built-in delivery remain unmodelled. Fixture and
host tests do not establish physical-device detection behavior or replace native SDK CI.

## Backend and complete-cycle contract

[The contract fixtures](fixtures/check-capabilities-v1.json) supply selection and unknown-state
examples. Register build ID, platform, effective groups and validated artifact bindings
together in the authenticated backend registry. Resolve expectations only for the exact
registered catalogue identity and preserve per-ABI provenance. Unknown releases have
unsupported expectations; never substitute the current catalogue.

A future complete-cycle envelope must distinguish fixed observation identities from variable
list values, snapshots from deltas, and complete delivery from dropped or truncated outputs.
Error and unsupported observations are present results, not clean or missing checks. Empty
values are present observations. Plugins can change delivery, so their completeness cannot
be inferred from the built-in catalogue.

Cycle IDs, completion envelopes, transport retry idempotency, missing-check verdicts and
freshness policy are separate contracts. Silence, offline periods and suspension cannot
establish runtime removal or bypass. No physical-device validation or check efficacy is
implied by this manifest.

## Catalogue and publisher updates

When adding a built-in, register its actual dispatch group, signal/source identities, typed
values, observation/value cardinality, statuses and ABI/API conditions. Model dynamic
identities explicitly or mark them unmodelled. Preserve source divergence and non-OK results.
Do not treat a generic `gmain` thread as an instrumentation marker or claim that every renamed
or hidden thread is visible. A libc syscall wrapper is hookable and is not an attestation
source. See [the second-source contracts](../runtime/second_sources.md) for the reviewed
read bounds and native syscall gates, and the [Context bridge guide](../runtime/android/stub/README.md)
for optional host initialization and availability.

Bump the catalogue revision, update fixtures and compiled dispatch tests, then rebuild and
ship binary plus sidecar. New catalogue identities require deliberate packer/backend support;
foreign old catalogues remain rejected rather than being reassigned current expectations.
Later independent checks require their own catalogue update when integrated.

The external publisher must use the validator and catalogue from the selected runtime source
reference, stage each ABI's binary with its sidecar, and verify the installed wheel using that
same consumer contract. Changing the selected runtime reference requires matching packer,
metadata and fixture expectations. This repository's local wheel tests do not establish that
another publisher preserves the association; verify that release path independently.


Revision6 adds the opt-in Android `overlay` group's ten [window observation outputs](android-window-observations.md),
source `window_callback`: two finite availability/coverage strings and eight bounded integer snapshots/deltas.
All revision5 signer/current/history, service context, inline-hook and iOS rows are preserved exactly. Each selected
actual measurement cycle drains window events once and hands the same immutable metadata/observations to both
plugin callbacks. Complete source coverage is not continuous window ownership or evidence of overlay absence.

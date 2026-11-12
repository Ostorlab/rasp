# Native measurement cycle contract v1

Consumer entry point: `rasp/cycle.h`, shared by the Android and iOS monitors and
native plugins. The compiled catalogue comes from the same validated
`checks_manifest.json` and canonical SHA-256 as the packer release binding.
The catalogue ID identifies definitions, not pristine binary bytes. Resolve the
latter through the registered packer release; never hash a config-mutated image.

## Identity and time

A monitor creates one secure random v4 `session_id` on its thread at startup,
independent of the installation ID. Each actual run has a new v4 `run_id` and a
nonzero increasing uint64 `sequence`. Exhaustion makes sequence unavailable and
sets overflow; it never wraps or repeats. IDs are unverified telemetry claims,
never authenticated host sessions, login sessions or attestation.

`duration_ns` covers builtins and synchronous plugin measurements, excluding
callbacks and transport. It is absent if the monotonic clock is unavailable or
moves backwards; equal ticks report measured zero with duration available.
`observed_at_unix_ms` is the completion device wall time, only within
[2000-01-01, 2100-01-01) UTC. Absence means unavailable, not server time. Device
suspension/clock adjustment can change timing; this API asserts no freshness.

## Completion and coverage

`execution_finished` is set only after every selected builtin and plugin check
returns. A stalled/crashed thread emits no finished snapshot; there is no timeout
thread cancellation, heartbeat-as-completion or silence verdict.

`complete` additionally requires known config/catalogue, valid sequence and
monotonic duration, exact enabled builtin coverage, and no drops/overflow.
Builtins are synchronous with no timeout cancellation. The additive catalogue
status vocabulary supports timeout at the native enum bit, without declaring it
for sources that cannot emit it. Unsupported, error and timeout observations are present, including an entirely
unsupported run. Status summaries count retained observations, with a separate
unknown-status count. A complete run can contain unmodelled plugin outputs; it
makes no claim about their expected cardinality or transport delivery.

Known catalogue groups carry an optional `enabled` state: false is disabled,
null is unavailable config. Empty configured groups are known/disabled; a missing
list is unknown. Unknown configured group names are counted and prevent complete.

Expected/seen/missing/extra refer only to builtin signal/source identities, counted
before plugin checks. Missing identities are listed; duplicates, disabled and
foreign builtin outputs count as extra. Plugin outputs cannot repair missing
builtins even if they use the same identity. Plugin outputs are counted separately
and remain unmodelled. An absent, invalid (including duplicate identities) or oversized catalogue makes coverage unknown: `catalogue_known` is false and `complete` cannot be true. Duplicate identities are invalid, not truncated; `catalogue_truncated` is reserved for representation bounds.

Bounds: 256 catalogue identities, 64 groups, 96 bytes per identity/group name;
256 retained observations; 1024 bytes per string value, 64 list entries, and
64 KiB total observation text per snapshot. An oversized observation is dropped
whole (never rewritten into benign evidence). Drops count builtin and plugin
observations, invalidate complete, and are distinct from missing execution.
The accessibility, input-method and notification service collectors may return up to 128 list entries. The cycle limit remains
64: a 65..128 entry list is dropped whole, `dropped` increments and `complete` is
false even when the builtin identity was present. A finite production-path fixture
checks exactly 128 entries and the legacy callback's empty retained span. The integrated real-JVM fixture also exercises the accessibility
collector through this cycle path at 64 and 128 entries. These are simulated
Android services on a real JVM, not device evidence.

Counters saturate at uint64 max and set overflow. Coverage/config truncation is
explicit and invalidates complete. No new check selection or builtin order.

## Immutable handoff and compatibility

All checks finish before dispatch constructs one owned `shared_ptr<const
CycleSnapshot>` containing metadata **and the observations together**. While
synchronous callbacks run, `plugins::kCycleSnapshot` in their Context holds that
same pointer. This key is runtime-owned; plugins read it and retain their own
copy of the pointer. An additive `Plugin::on_cycle` callback receives the pointer too.
Callbacks run in plugin order; each existing `on_observations` precedes that
plugin's `on_cycle`. Existing callbacks and checks keep their signatures/order.
The legacy observation span expires at callback return. During monitor dispatch it
contains only retained observations. A legacy callback that ignores the cycle key
cannot see drops/coverage metadata; an asynchronous legacy consumer copying only
that span still loses metadata until it migrates to owned snapshots. Direct legacy
run_plugins preserves its original unbounded observation behavior and makes no
cycle-completeness claim.

An asynchronous consumer must copy/retain the owning snapshot during its
callback, and derive both observations and metadata from that snapshot. It must
not fetch the process Context later or pair a saved span with a newer run.
Context dispatches are serialized; snapshot publication/clearing is atomic under
Context's lock, and plugin measurements see no previous cycle. Recursive dispatch
on the same Context/monitor is unsupported. Independent contexts can run together.
Direct legacy `run_plugins` calls clear the key and never synthesize cycle success
or invoke `on_cycle`. The key is cleared after callback dispatch. Retained pointers
remain immutable and valid across subsequent runs.

A delivery batch ID is **not** allocated by this API. The serializer owns one fresh
v4 batch UUID per immutable serialized payload, stores it with those bytes and the
snapshot, and reuses both on retry/fallback. Consumers must bound their pending
snapshot and serialized-payload queues. Splitting a run into payloads gives
separate batch IDs and no claim of atomic full delivery. Dropping/truncating at
serialization must downgrade delivery completeness, never mutate the snapshot.

## Cross-repository rollout

[docs/fixtures/measurement-cycle-v1.json](fixtures/measurement-cycle-v1.json) is consumer-readable semantic fixture
data, not a GraphQL input. BE03 accepts only optional `sessionId`, `runId`,
`batchId`, `observedAt` (RFC3339 conversion required). This change emits no network
fields. Sequence, duration, catalogue/config and health require an explicit
additive backend schema and transport rollout before transmission. Network/DNS
plugin implementation is coordinated separately; native availability may precede
it. Legacy metadata remains unavailable. The compiled catalogue includes inline-hook observations, service
metadata, signer current sets and rotation history, window observations, and root/context observations.
Canonical schema 1, revision 9 declares 73 Android and 52 iOS identities, with catalogue ID
`2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d`.
Identity has nine expected outputs; malformed signer sources remain present error observations. Real-JVM caller
and attached-worker fixtures exercise the actual identity dispatcher through this immutable cycle handoff. See the durable
[signer observation contract](android-signer-observations.md) and
[capability/binding rules](check-capabilities.md).
Cycle metadata adds no observation rows or catalogue revision. Every later builtin
source change still requires an exact catalogue update.

Real device execution, suspension, storage failures, iOS toolchain/obfuscation and
supported compiler CI remain necessary validation; host execution is no device
health evidence. Session/run generation does not depend on installation storage.


The combined runtime preserves RT10's ordinary merge of the exact approved RT09 parent. Canonical schema 1, revision 9 declares **73 Android/52 iOS**
identities, catalogue `2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d`. The ten opt-in window outputs consume one bounded FIFO drain per selected actual
measurement cycle through the same production builtin dispatcher; disabled selection does not drain. Legacy and
additive callbacks retain the same immutable snapshot, including interval/loss metadata and observations, across
later drains and Context destruction. Real-JVM caller and attached-native-worker tests exercise that handoff.
`complete` means all expected metadata/count rows are present, including observer error or unknown coverage; it
does not certify an active observer, uninterrupted ownership, delivered touches or overlay absence.

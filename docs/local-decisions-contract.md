# Local decision evidence, version 1

The existing Android and iOS `CycleMonitor` publishes report-only interpretation
in `CycleSnapshot::local_decisions`. It does not terminate a process, repair hooks,
authorize an operation, download policy, transmit results or establish server
authority. Every result carries `LocalEvidenceTrust::kUnverifiedClient`.

Per-rule verdict, severity, limited/unavailable confidence, stable reason, version
and evidence indices belong to the same immutable snapshot. There is no aggregate
clean/compromised verdict or score. Threat means a reported indicator matched;
benign means only that a supported indicator was absent. Neither identifies malware.

## Ownership and provenance

```text
┌─────────────────────────────────────────┐
│ Existing Android / iOS CycleMonitor      │
└────────────────────┬────────────────────┘
                     ▼
┌─────────────────────────────────────────┐
│ Retain builtins; save producer prefix    │
│ Append bounded plugin observations      │
└────────────────────┬────────────────────┘
                     ▼
┌─────────────────────────────────────────┐
│ Final metadata → pure builtin evaluator │
│ One shared_ptr<const CycleSnapshot>     │
└────────────────────┬────────────────────┘
                     ▼
┌─────────────────────────────────────────┐
│ Existing Context key / on_cycle callback│
│ Consumer retains the entire owning unit│
└─────────────────────────────────────────┘
```

Decisions are final before any callback and never mutate on later runs. Evidence
indices reference only retained builtins: plugin collisions cannot fill missing
measurements, replace facts, or enter comparisons. This is process bookkeeping,
not a boundary against a compromised process. All raw plugin evidence is preserved.

Compiled native integrations use the existing `Plugin::on_cycle` callback,
synchronously on the monitoring worker under the dispatch lock. Retain the owning
pointer for asynchronous use; do not retain spans or individual row references.
Do not recursively dispatch on the same monitor/Context. The compiled
`runtime/plugins/example/example.cpp` consumer retains the same owner in its
plugin-local Context. This is not a Kotlin/Swift SDK; C++ objects must not cross
the iOS framework's private-libc++ boundary. Legacy `run_plugins` has no owned cycle
and produces no decisions. `on_observations` still receives mixed raw observations.

## Availability and counts

- `rows.size()` includes disabled, missing and unavailable rows.
- `predicates_evaluated` counts successfully typed predicates, excluding disabled,
  missing, failed, unsupported and malformed inputs. Empty selection has zero
  evaluated predicates and explicitly unknown disabled rows, never a clean verdict.
- `coverage` describes retained selected outputs. Complete retention can coexist
  with unsupported/error statuses; it never means successful protection.
- Whole-report `reason` identifies catalogue/metadata/envelope unavailability.
  `issues` keeps missing/extra/loss/unknown-group/status/clock conditions separate
  from supported indicator facts. Device time does not establish freshness.

Report schema, reason vocabulary, native metadata and rule semantic versions are
independent. `local_reason_name` returns stable lowercase names (`unknown` for an
invalid enum). Absent config yields `config_unknown`; disabled groups yield
`config_disabled`; enabled missing outputs yield `missing_observation`. These are
unknown/unavailable. Non-OK statuses remain `status_unavailable` even with forged
positive payloads. Wrong variants/digests are `invalid_value`; duplicate tuples
invalidate their predicate/comparisons. No first/last-wins, coercion or default zero.

The pure API receives final metadata, retained builtin span and actual dispatcher
catalogue. It validates definitions as well as digest/platform and checks bounded
counts against retained evidence. Forged API arguments grant no authority.

## Explicit semantic adoption

The registry explicitly adopts canonical schema 1 revision 8, 73 Android / 26 iOS outputs,
digest `479cfeb318a4ddaa70fa7be5986d0f46ec45dcc9377b281da811a5dae667466a`,
from approved RT15 `2d396b83292dcd978cc1f7675afade24b45859d4`.
`core/src/decision_registry.h` pins it independently from generated definitions.
Future/unsupported catalogues cannot inherit fallback predicates; adoption needs
explicit semantic review and fixtures.

The 43 overlapping `native.*` rules preserve BE13 version-1 semantics at
`1d6d4571d6a63e62a0dc831b19820cd234b0c977`. The unmodified 289-case fixture is
`runtime/tests/core/assessment_vectors.json`, SHA-256
`a8dc088888c9560d68574dd9bc1045c87a03d5321638bde6336ca5d589362307`.
Transport-only cases remain server checks. Two oversized fixture values hit native
retention limits and explicitly remain unknown with loss. Wrong platform/source
never selects a similar rule.

The other 35 tuples have explicit local dispositions: 7 typed second sources,
6 baseline-required identities/digests, 2 filtered hook indicators, 10 overlay
context fields, 2 always-unavailable developer-setting outputs, 8 uninterpreted
context outputs. They do not claim server registry coverage. No client result,
severity, version or platform can override backend-owned application assessment.

The 21 added Android screenshot/recording identities have explicit unknown /
`unregistered_rule` dispositions. They have no semantic predicate, severity or
available confidence and never increment `predicates_evaluated`, even for positive
or malformed bounded OK payloads. Disabled/config-unknown/missing/duplicate and
non-OK eligibility is checked first. They do not enter source comparisons or imply
capture, malware, active control or sensitive exposure. The original 78 rule
semantics and BE13 fixture bytes are preserved. Other digests, including the older
revision 7, and definition mismatches still refuse the entire report.

SHA-256 requires exactly 64 lowercase ASCII hex characters; CDHash requires 40.
Unique OK same-cycle file/memory digests yield a separate mismatch observation
when unequal. Equality remains `hashes_equal_untrusted`; identical file/memory
patches evade detection. There is no authenticated expected baseline. Encrypted
iOS file text remains unsupported. Legacy first signer, full concurrent signer
sets and signing history are never equated or treated as signature verification.

Only closed comparable-source pairs can corroborate/disagree, without increasing
confidence. Read timing, native caps, authorized instrumentation and hookable APIs
limit interpretation. List order is ignored for set comparisons. Pairs with
evaluated prerequisites are emitted; unavailable inputs stay explicit in their
per-source rows. No arbitrary same-name comparison runs.

TalkBack, keyboards, password managers, VPNs, CAs, proxies, RWX memory, root-manager
packages and sharing context do not establish malicious activity. Structured
service/proxy/mount fields stay uninterpreted; only outer variants and bounds are
validated. No embedded capability or active control is inferred. Overlay context
requires all ten records with consistent observer/loss/count closure. Positive
obscured-touch context remains unknown; zero events do not prove absence of overlays.

## Finite resources and validation limits

Native input limits: 256 observations, 96-byte names/sources, 1024-byte string/list
entry, 64 list entries, 65536 total text bytes. Dispatch drops oversized records
whole; direct oversized pure-API input returns unavailable. Metadata is bounded to
64 groups and 256 missing identities. No recursion, unbounded pair expansion,
counter wrapping, effects or independent monitor is introduced.

The adopted tables produce at most 75 rows, 8 Android / 3 iOS source relations,
and 7 coverage issues. Native rows reference one input, integrity two, overlay ten.
Heap allocations and work are bounded by fixed tables and checked input sizes.
Same-process allocation failure is not crash isolation.

Tests cover pinned parity, invalid inputs, selection/coverage, plugin collisions,
retained cycles, real platform dispatch and changed-byte collector fixtures.
Host/sanitizer/cross-build/artifact gates do not establish physical-device efficacy,
false-positive rates, Apple execution or policy denial. HD02 owns subsequent
explicitly opted-in operation policy; report-only remains the default.

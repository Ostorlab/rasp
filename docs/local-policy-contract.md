# Embedded local policy and adapted host operations

**Embedded local policy** is an optional, offline, bounded set of rules the packer
writes into a protected build. It lets the host gate a named operation on the runtime's own typed
measurements immediately before that operation. Without `local_policy`, the packer
writes the same legacy config bytes and the runtime remains report-only. Check
selection, required identity checks and capture opt-in keep their existing behavior.

A policy in `gate` mode affects only an operation whose host source calls the gate
and checks its result immediately before doing the work. It cannot intercept an
arbitrary unadapted call, revoke completed work, or refuse a server transaction.
There is no process termination, delayed panic, signal takeover or hook repair.

The gate reads the actual immutable `LocalDecisionReport` owned by a completed
native cycle. It does not accept a caller report, score, time, policy replacement
or reusable permit.

Every result remains unverified client evidence. A matching
policy/config hash establishes equality, not authenticity, a trusted baseline,
device health, malware classification or server authorization. An attacker who
controls the app can patch its gate and caller. The backend authorizes server
operations; this gate cannot grant that authority. It does not provide signed remote
policy delivery or hardware-key attestation.

## Configure and pack an embedded local policy

Run the commands below from the repository root with a packer installation containing
the matching native artifacts. The platform examples are [Android](fixtures/local-policy-android-v1.json) and
[iOS](fixtures/local-policy-ios-v1.json). Each selects a versioned debugger predicate
for the harmless `append_demo_receipt` host operation. They are examples, not a
default policy or recommendation to reject authorized debugging.

```sh
rasp pack demo.apk --platform android --build-id demo-1 --checks debugger \
  --local-policy docs/fixtures/local-policy-android-v1.json --output protected.apk
```

For an unprotected iOS IPA, the matching CLI form is:

```sh
rasp pack demo.ipa --platform ios --build-id demo-1 --checks debugger \
  --local-policy docs/fixtures/local-policy-ios-v1.json --output protected.ipa
```

The output is unsigned. Host adaptation must exist in the source that produced
the input app; injection does not add business-operation call sites. An app that
already loads or embeds the runtime is rejected as already protected.

```python
import pathlib

from rasp_packer import local_policy
from rasp_packer import packer
from rasp_packer import platforms

policy = local_policy.load(pathlib.Path("docs/fixtures/local-policy-android-v1.json"))
result = packer.pack(
    app=pathlib.Path("demo.apk"),
    platform=platforms.Platform.ANDROID,
    output=pathlib.Path("protected.apk"),
    build_id="demo-1",
    checks=["debugger"],
    local_policy=policy,
)
assert result.policy_sha256 == policy.sha256
```

Compile `policy.sha256` into the host before building/packing it. Learning the
expected hash from runtime info would not detect a downgraded configuration.
`PackResult` also exposes effective config hash, mode and per-artifact policy
bindings. These are configuration/build metadata, not proof of host adaptation
or runtime execution. CLI status states this scope explicitly.

Policy schema, engine, gate reason vocabulary and facade ABI are version 1.
Report schema/reason vocabulary/native metadata version are separately pinned to
1. Each selector pins its exact rule identifier and semantic version. The catalogue
is exactly revision 9, ID
`2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d`.
Future catalogues or rule versions require explicit adoption; there is no latest
or signal/source alias fallback. Policy version is a positive uint32 deployment
version, 1 through 4294967295, not a trusted rollback counter.

`mode` is `report_only` or `gate`; `scope` must be `host_calls_only`. Gate operations
and their rule lists must be nonempty. All selected groups must already be enabled
in the actual effective checks; a policy never enables a group automatically.
Unknown fields, unsupported actions, unknown/context/baseline-required rules and
unsupported versions are errors, never warning-and-skip mandatory requirements.

The closed selector inventory is
`packer/src/rasp_packer/local_policy_selectors_v1.json`. Native selectors are generated
from that same file by `runtime/tools/local_policy_header.py`. Its 20 exact rules
are predicates capable of both a typed indicator and a typed absent indicator.
Context, identity/digest baselines, source relations and all uninterpreted capture
rows cannot become absence predicates. In particular, the 21 Android and 26 added
iOS capture identities retain explicit unknown/unregistered dispositions.

## Results and unknowns

Call status and action are independent. Non-OK status never permits an operation.
For a successful call, action is DENY=0, REPORT=1 or ALLOW=2. Zero/error output denies.
REPORT is an explicit advisory path and never means clean, allowed by enforcement,
or safe. An application that chooses report-only must handle that branch explicitly.

Caller/request failures and invalid or unsupported configured policy pins fail closed
before report-only selection. An expected-policy-hash mismatch is also strict in both
modes: status OK, final DENY, candidate DENY, reason HASH_MISMATCH. In contrast, a
completed publication whose report schema/reason/native metadata version, catalogue,
platform or evidence-trust binding is incompatible is an evidence limitation: it
returns OK with final DENY in gate mode or REPORT in valid report-only mode, candidate
DENY and reason BINDING_MISMATCH. Pack-time native support bindings are validated
separately and cannot be converted into advisory runtime results.

In this table, candidate means the numeric candidate action (DENY or ALLOW), not a
second authorization. The separate primary reason describes missing publication,
binding, coverage, freshness or clock limitations. Call status OK alone never admits.

| Condition | Gate mode | Valid report-only mode |
|---|---|---|
| All selected typed predicates absent, coherent complete cycle, valid age | OK, ALLOW; candidate ALLOW | OK, REPORT; candidate ALLOW |
| Any selected supported indicator present | OK, DENY; candidate DENY | OK, REPORT; candidate DENY |
| Missing/duplicate/malformed/disabled/unsupported/error/timeout selected input | OK, DENY; candidate DENY; exact row diagnostics retained | OK, REPORT; candidate DENY; exact row diagnostics retained |
| Invalid/unsupported configured policy, empty gate operations/rules or unsupported mandatory selector/action | Packing error; runtime non-OK, DENY | Invalid explicit policy remains non-OK, DENY |
| Bad request/ABI or internal API failure | Non-OK, DENY; candidate DENY | Non-OK, DENY; candidate DENY |
| Initialization has not completed | NOT_READY, DENY; candidate DENY | NOT_READY, DENY while policy itself is unknown |
| Valid policy but no completed cycle | NOT_READY, DENY; candidate DENY; reason NO_PUBLICATION | OK, REPORT; candidate DENY; reason NO_PUBLICATION |
| Unknown operation | OK, DENY; candidate DENY; reason OPERATION_UNKNOWN | OK, REPORT; candidate DENY; reason NO_SELECTION or OPERATION_UNKNOWN |
| Expected policy hash mismatch | OK, DENY; candidate DENY; reason HASH_MISMATCH | OK, DENY; candidate DENY; reason HASH_MISMATCH |
| Publication report-binding mismatch | OK, DENY; candidate DENY; reason BINDING_MISMATCH | OK, REPORT; candidate DENY; reason BINDING_MISMATCH |
| Lost/incomplete coverage, stale or slow cycle, invalid clock | OK, DENY; candidate DENY; actual limitation reason | OK, REPORT; candidate DENY; actual limitation reason |
| Store contention or more than eight concurrent evaluations | BUSY, DENY; candidate DENY | BUSY, DENY; candidate DENY |

ALLOW requires every selected exact row to have OK collection status, an evaluated
predicate, limited confidence, the expected rule version and benign/indicator_absent.
Zero evaluated rules never allow. Unselected baseline/context rows remain unknown
without vetoing a separately supported selector. Structural completeness is
checked separately; non-OK statuses can coexist with complete retained coverage.

Primary reasons distinguish bad argument, invalid/unsupported policy, hash/binding,
unknown operation, missing publication, coverage, clock, stale/slow cycle, required
unavailable, indicator present and all absent. Selected details preserve underlying
verdict/reason/status and evidence indices when available, including when a stale
or incomplete publication prevents operation admission. Indices are diagnostics
into the internally retained snapshot, not accessible native pointers.

## Ownership, startup and freshness

The existing monitor publishes the same `shared_ptr<const CycleSnapshot>` before
plugin callbacks. Builtin provenance and the typed report stay together. Plugins
cannot fill missing builtins through colliding raw observations. Later cycles or
source attachment cannot mutate an earlier report. Legacy `run_plugins` does not
publish gate evidence, and no second monitor is started.

One initialized service is intentionally retained for process lifetime. Atomic
installation is one-shot; duplicates cannot replace it. Its lifetime does not
depend on an installer stack or a cancellable worker staying alive. The runtime
must remain loaded while any facade call is possible; unloading it is unsupported.
If monitoring stops, the last publication ages out. No result getter refreshes age.

The service retains one publication and at most eight in-flight evaluation owners.
The gate makes one store try-lock attempt, copies an owner, and evaluates outside
the lock. Replacement destruction occurs outside the lock. It never takes Context's
dispatch lock, waits for a cycle, invokes host code, scans synchronously, accesses
storage/network or dispatches to main. C/Java/Swift results own copies, with no release
handle. Copy ownership does not turn an old ALLOW into a reusable permit.

Freshness uses a private suspend-inclusive clock: Android CLOCK_BOOTTIME and iOS
mach_continuous_time with checked timebase conversion. Existing telemetry clocks
and wire version stay unchanged. Age is current time minus **cycle start**, covering
the oldest measurement; cycle duration is completion minus start. Missing,
negative, backward, future or overflowing clock data cannot allow. Failure/regression
latches the current publication unavailable until a new ordered completed cycle.
Wall time, UUID or sequence never establishes age. Clocks remain hookable.

Compare exact nanoseconds without flooring: equality at a configured millisecond
bound is valid; one nanosecond beyond is stale/slow. The examples use 75000ms age
and 5000ms duration. Those are explicit example choices, not new defaults or efficacy
guarantees. Monitoring still runs every 60 seconds; tighter age limits can produce
DENY gaps. Startup or late capture/context attachment can wait for the next real
cycle. Capture/window opt-in and recovery have their own source/state/lifecycle
contracts; a fresh observer does not repair a previously published report.

Gate on the final execution thread. If an operation queues, yields, retries, resumes
or changes inputs, discard its earlier result and gate again immediately before
the actual operation. The API is reentrant and bounded, not hard real-time or an
allocator/OOM/crash-isolation boundary.

## Primitive C and platform consumers

Installed header: `rasp/local_policy_host.h` for native Android, or
`<RaspRuntime/local_policy_host.h>` in the iOS framework. Exactly two policy exports
exist: `rasp_local_policy_info_v1` and `rasp_local_policy_gate_v1`. Android preserves
JNI_OnLoad; iOS preserves the six capture C exports for an exact total of eight.
All private C++ symbols stay hidden. No STL or private-libc++ object crosses iOS's ABI.

Requests/results use fixed-width integers, fixed arrays, presence bits and exact
version/size checks. Request is 112 bytes, detail 204, gate result 2104, info 6532.
The public header and every target assert layout; callers provide valid aligned
memory and exact sizes. Arbitrary invalid pointers cannot be contained by a C ABI.
Policy version remains uint32 in C, UInt32 in Swift (widen with UInt64 for display),
and Java `long` (zero-extended with Integer.toUnsignedLong).
Sequence's Java getter explicitly returns raw uint64 bits as `sequenceBits()`.
Swift uses the header's typed `kRaspLocal*` constants; C callers retain the
`RASP_LOCAL_*` macros. The header-only `int32_t` constants have internal linkage
and preserve the same values without adding framework exports.

The full working C/ObjC/C++/ObjC++ probe is
`runtime/tests/host/local_policy_host.c`; Swift is in
`runtime/tests/ios/local_policy/host.swift`. A caller must check status and the known
action before its adapted operation. Info reports config and support, never permits work.

Android Java/Kotlin callers use RuntimeBridge.localPolicyInfo() and
RuntimeBridge.gateLocalOperation(operation, expectedPolicySha256). Results and detail
arrays are immutable owned copies. Null/linkage/JNI failure is unavailable, never
ALLOW. Use `decision != null && decision.allows()` for status OK plus final ALLOW;
REPORT never admits, and candidate ALLOW alone does not satisfy this accessor.
It reads the owned historical
decision and does not revalidate freshness; call the gate again at actual execution.

The actual compile-only jar comes from `runtime/android/stub/build.sh`:
use it as compileOnly, and do not put a duplicate RuntimeBridge class in the host APK.
The actual packed stub provides that class. Source/header copies are staged with
native resources; API jar and stub.dex must come from the matching source build.

Harmless complete source hosts are `runtime/tests/android/local_policy/device/`
and `runtime/tests/ios/local_policy/host/`. Their in-memory receipt operation returns
before mutation on denial/error. Host tests verify the actual receipt count; they
do not substitute a mock gate or call a delayed termination transaction denial.

## Bounded parser and support compatibility

| Resource | Limit |
|---|---|
| Existing embedded section | 4096 bytes, <=4095 JSON bytes, NUL and zero padding |
| External/canonical policy | <=2048 bytes; bounded file read uses limit+1 |
| Parsing | <=8 nesting levels; native fixed heap arena <=128KiB; iterative validation |
| Operations/selectors | <=4 operations, <=8 selectors total and per operation |
| Identifiers | operation <=32, policy_id <=64, rule_id <=128 ASCII grammar bytes |
| Explicit effective checks/build ID | <=64 unique known groups <=96 bytes; build ID <=256 UTF-8 bytes |
| Age/duration | age 1000..120000ms; duration 1..10000ms and <=age |
| Gate/native evidence | existing 256 observations, 65536 text bytes, bounded rows/relations/indices |

Duplicate/unknown keys, wrong types, bool-as-int, floats/exponents, signed/overflow
versions, escaped NUL/control identifiers and unsupported semantic pins are rejected.
Canonical identity sorts object keys, operations and selectors, uses compact UTF-8
JSON and hashes normalized policy. Config hash includes build ID, actual sorted
checks and normalized policy, excludes install identity, and distinguishes unknown
selection from an empty selection. Invalid whole config cannot establish absent policy.

Observation catalogue identity alone cannot prove policy support: an older runtime
can share that catalogue and ignore a new JSON field. Every policy-enabled native
build emits `<binary>.local-policy.json` next to the existing capabilities sidecar.
It binds exact pristine bytes, platform/ABI/floor, policy/facade/report versions and
the generated selector-table digest. The packer checks every injected artifact
before config insertion, requires matching capability binding and actual policy
exports, and refuses missing/old/mixed/foreign/corrupt support for any explicit policy,
including explicit report_only. Missing support stays legacy/unknown only when policy
is absent. Support metadata is not signed attestation or proof of source adaptation.

After packing, the verifier compares exact embedded config and injected artifact
bytes across every ABI/slice. No new observation catalogue revision, collector
predicate, trusted baseline or server assessment field is introduced.

Native fixtures, sanitizers and cross-builds establish only their exercised behavior.
Actual Apple SDK compilation/linkage/export/header/floor/Swift/UIKit tests remain
mandatory platform gates. Physical Android/iPhone/iPad operation/lifecycle/suspend
tests require recorded device outcomes; compile/fixture checks do not establish
device efficacy or false-positive rates.

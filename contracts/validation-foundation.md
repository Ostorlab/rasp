# Validation foundation v1

The initial design through “Minimal file list and acceptance handoff” is
historical, including its source and dispatch restrictions. Root subsequently
accepted implementation; the [accepted implementation addendum](#accepted-implementation-addendum)
records that authorization and supersedes corresponding historical details.

Source is exactly `e7886a8598ad0dc369ee01835ba5a8b7b4bb3850`, tree
`1780520ac0ba0f45b4f778a12d30d3e070609881`. This contract authorizes no implementation.
Root must assign the later clean parent, passing exact-parent CI and implementation
dispatch. Sibling test-only correction `69107e15` is for root publication; do not
compose it locally. Frozen HD02 `9d9755c3cac6383af6a3e8e20d821dec05f9aad7` documents
are reference prose, not replacement source or build provenance.

## Small implementation boundary

One standard-library Python 3.14 script, `validation/run.py`, provides `run --plan
PLAN --inputs INPUT_DIR --output NEW_DIR [--lab LAB_ID]` and `verify --plan PLAN --bundle DIR`.
Two hard-coded routes are `host_c` and `android_adb`; there is no adapter discovery,
imported executable, command template, scheduler, service, backend model or database.
The plan supplies identities and expected cells, never shell commands. `verify`
recomputes hashes, phase bindings, counts and outcomes; a producer's success flag
has no authority. Only runner/format conformance is locally testable without a lab.

Initial runnable scenarios are `host_startup_unavailable`, `android_clean_receipt`
and `android_policy_hash_mismatch`. Android scenarios exercise configuration and
host integration, not attacks. Benign contexts are labelled `clean`, `vpn`,
`accessibility`, `ime`, `support`; no context alone denotes malware or a bypass.
Later VAL02/VAL03 own framework, performance collection and attack adapters.

## Closed records and bounds

- **JSON:** All dictionaries below have exactly the named required keys.
  Unknown/missing or duplicate JSON keys, duplicate IDs/paths, unsupported versions,
  trailing documents, NaN/Infinity, floats/exponents, booleans as integers, control
  characters and excess depth/size are rejected. JSON is UTF-8 without BOM;
  maximum nesting is 12. Arrays retain order unless a hash rule below explicitly
  sorts them. No free-form metadata.
- **IDs and labels:** `ID` is `[a-z][a-z0-9_]{0,47}`; `HASH` is 64 lowercase hex
  characters; Git identities are 40 lowercase hex characters. General labels are
  printable ASCII, 1..128 bytes.
- **Paths:** Paths are relative ASCII components `[A-Za-z0-9_.-]+`, total <=240
  bytes, with no empty, `.` or `..` component. Reject symlinks, hard links,
  devices/FIFOs/sockets, absolute paths, escapes, file replacement during reading
  and nonregular inputs. The caller must prevalidate and trust the root and its
  ancestor chain. The bounded reader refuses a symlink in the root’s final
  component or any relative descendant; it does not verify ancestors above that
  root.
- **Reading:** Open bounded files below that root without following links, check
  identity before/after reading, snapshot into a new private directory and execute
  only the checked snapshot.

| Record | Exact keys and values |
|---|---|
| Plan | `version=1`, `source_head`, `source_tree`, `build_receipt_sha256`, `suite_sha256`, `files`, `cells` |
| File | `id:ID`, `path`, `role`, `bytes`, `sha256:HASH`; role is `host_executable`, `native_pristine`, `native_injected`, `apk_signed`, `stub`, `bridge_jar`, `capabilities`, `policy_support`, `policy`, `config`, `registry`, `build_receipt`, `suite_source`, `fixture_source`, `tool`, `lab_descriptor`, `provisioning_receipt` |
| Cell | `id:ID`, `adapter` (`host_c/android_adb/ios_unavailable`), `scenario` (three initial names above or `ios_receipt`), `context` (five benign labels above), `facility` (`host/physical/emulator`), `target:Environment`, `required:bool`, `artifact_ids:[ID]`, `expected` (`error/benign/business_denial/not_run`) |
| Build receipt | `version=1`, `source_head`, `source_tree`, `tool_ids:[ID]`, `flags:[label]`, `plugins:[]`, `registry_file:ID`, `products:[ID]`; product entries refer to File records |
| Bundle | `version=1`, `run_id`, `plan_sha256`, `suite_sha256`, `source_head`, `source_tree`, `build_receipt_sha256`, `results`, `evidence`, `measurements`, `summary` |
| Result | `cell_id:ID`, `nonce`, `environment`, `baseline:Phase`, `setup:Phase`, `execution:Phase`, `cleanup:Phase`, `observation`, `operation`, `outcome`, `reason` |
| Environment | `os` (`linux/android/ios`), `os_version:label or null`, `api:uint or null`, `model:label or null`, `abi` (`x86_64/x86/arm64-v8a/armeabi-v7a/arm64/unknown`), `page_size` (`4096/16384/65536/null`), `facility`, `device_id:HASH or null`, `channel` (`host_native/preinstalled_lab/unavailable`) |
| Phase | `state` (`verified/failed/not_run`), `evidence_ids:[ID]`, `reason` |
| Evidence index entry | `id:ID`, `path`, `bytes:uint`, `sha256:HASH`, `run_id`, `cell_id:ID`, `nonce`, `phase` (`baseline/setup/execution/cleanup`), `kind` (`host/adb/fixture`) |
| Observation | `state` (`present/absent/unavailable/unsupported/not_run`), `rule_id:label or null`, `rule_version:uint or null`, `status:uint or null`, `evidence_ids:[ID]` |
| Operation | `state` (`completed/denied/unknown/not_run`), `api_status:uint or null`, `action:uint or null`, `gate_reason:uint or null`, `before:uint or null`, `after:uint or null`, `policy_sha256:HASH or null`, `config_sha256:HASH or null`, `evidence_ids:[ID]` |
| Summary | `planned:uint`, `by_outcome` (all eight outcome keys below, uint counts), `missing_cells:[ID]`, `conformance` (`pass/fail`), `release_gate` (`pass/fail/not_requested`), `effectiveness_gate=not_run`, `performance_gate=not_run` |

`run_id` is runner-generated UUIDv4 lowercase text; each cell gets a fresh random
32-character lowercase hex `nonce`. Optional information uses explicit null, never
zero/empty as unknown. Unsigned integers are 0..2^63-1 unless restricted above;
API/status/action/reason/rule version are uint32, rule version is >=1. Before/after
receipt counts are 0..2. `facility` must equal its planned value; unavailable values
do not prove an environment match. `api` is required for executed Android cells.
Host/Android/iOS adapters accept only their corresponding scenarios and OS/channel;
host context/facility is clean/host. iOS v1 only emits not_run with null probe fields.
Executed cells must match every nonnull target field; Android targets require
nonnull OS version/API/model/ABI/page size/device identity. No wildcard device cell.
V1 executes Android only in clean context; other context cells stay
not_run/adapter_unavailable until a reviewed independently verified context route.

| Resource | Hard ceiling; exceeding it is never truncation-as-success |
|---|---|
| Plan / bundle JSON | 1 MiB / 2 MiB, read limit+1 |
| Cells / files / evidence | 8 / 96 / 256 entries; 1..8 unique planned cells, 1 result per cell |
| Input bytes | 64 MiB/file, 256 MiB total; receipt 64 KiB, policy 2048, config 4096 |
| Captured evidence | 256 KiB/file, 16 MiB total; stdout/stderr included |
| Process execution | Serial; 256 child invocations/suite, 15s/command, 120s/cell, 900s/suite |
| Native host limits | 5s CPU, 256 MiB address space, 32 open FDs, 1 MiB file size, no core dumps |
| Polling / cleanup | At most 45 polls at 2s spacing; cleanup gets a reserved 20s/cell inside suite budget |
| Strings / references | <=128 bytes/label, <=96 artifact refs/cell, <=32 evidence refs/phase, <=64 flags/tool IDs; fixture/receipt records <=64 KiB |

The POSIX supervisor uses a new process group, drains pipes with byte caps and a
monotonic deadline, kills/reaps the owned group on timeout/overflow, then attempts
cleanup. A command may finish earlier but may never extend the cell/suite deadline.
When the suite budget cannot reserve cleanup for another cell, that cell and the
remaining cells become `not_run/budget_exhausted`. ADB client limits do not bound
all work on a remote device: lab provisioning must supply device resource/egress
limits. The orchestrator is not a security sandbox and cannot contain hostile code.

## Hash domains and exact source/artifact binding

File `sha256` is SHA-256 of exact bytes, including signed APK bytes; never hash an
extracted filename or a mutable in-memory image in place of the artifact. Canonical
JSON `C` sorts dictionary keys, uses compact separators, ASCII escaping, unsigned
decimal integers and no newline. Plan hash is SHA256(`val01.plan.v1\0` || C(plan)).
Suite hash is SHA256(`val01.suite.v1\0` || C(sorted File records of roles
`suite_source/fixture_source`, sorted by path))). Its own value and build outputs
are excluded, avoiding recursion. Build receipt hash is raw-file SHA-256. All
receipt file IDs resolve through the Plan; receipt never contains its own digest.
Evidence hashes are raw-file SHA-256; bundle has no self-hash. UUID/time are not
artifact identities or freshness proof. Store timestamps only in private logs.

Use production `rasp_packer.local_policy.parse(...).sha256` and `effective_hash`
semantics for policy/config equality, with the exact source's selector catalogue;
do not replace these with the validation domain or invent a catalogue revision.
Host startup has no initialized policy/config: those operation fields are null,
even though its compiled expected-policy constant is recorded in fixture source.
Android requires exact policy file, host-compiled expectation, extracted injected
config, runtime info and gate results to agree. Mismatch scenario changes only the
request expectation by flipping its first hex digit, never the packaged policy.

The root-approved build receipt must bind clean Git head/tree, compiler/tool bytes,
flags and every executed native/APK product. Reject dirty/unassigned source,
unlisted outputs, mixed ABI or sidecar bindings and any hash change between
preflight, baseline, execution and cleanup. Pristine native SHA differs from
config-injected SHA: record both and verify packer config insertion/extraction
using production `runtime_library`, `runtime_config`, `verification` and
`local_policy.bind`; require capability and policy-support sidecars for each ABI.
Check APK zip members with existing bounded archive validation; reject duplicate
names and excess expansion; do not extract arbitrary paths. Require matching stub
and compile-only bridge jar source/build receipts; no duplicate bridge in host DEX.

V1 accepts exactly `plugins=[]`, built with `RASP_PLUGINS` empty. Record the actual
generated `rasp_plugins.cpp` file and digest in the build receipt, checked against
the approved build's empty ordered registry. This binds plugin configuration and
binary together; an empty claimed list beside an unrelated binary fails. Network
reporting/plugin variants require a separately reviewed contract change. Equality
and an unsigned receipt are reproducibility checks, not authenticated attestation;
root's reviewed build/source association remains an external prerequisite.

## Real host-native route

Add `validation/fixtures/host.c` and a single test executable target
`rasp_validation_host` in `runtime/tests/CMakeLists.txt`, following the existing
`rasp_local_policy_c_host`: link shipping `core/src/local_policy_host.cpp` and
`rasp_core`, include the actual public `rasp/local_policy_host.h`, use C17 layout
assertions and no mock gate. This is a built native artifact containing production
code, not an installed Android library or a device execution claim.

Its sole process takes the runner nonce as one argument and prints exactly three
newline-separated closed JSON events: baseline keys `nonce`, `phase=baseline`,
`before=0`, `after=1`; setup keys `nonce`, `phase=setup`, `info_status=3`;
execution keys `nonce`, `phase=execution`, `api_status=3`, `action=0`,
`info_status=3`, `before=0`, `after=0`. First append one harmless receipt
without a gate in an independent control counter. Then immediately call
`rasp_local_policy_gate_v1` on a valid ABI/size/operation request in a fresh process
with no installed policy, and append to the scenario counter only on OK+ALLOW.
Call `rasp_local_policy_info_v1`; require NOT_READY and unchanged scenario count.
The supervisor verifies all values, exit 0, nonce, executable hash and no survivors
or files in the private scratch directory. Any extra stdout field/document fails.

The outcome is **error/runtime_unavailable**, observation unavailable and operation
unknown, even though its expected startup behavior conforms. No business-denial,
detection, clean-device or effectiveness credit is possible. Invalid-argument and
child-crash/timeout paths are meaningful runner tests, not extra attack scenarios.

## Actual Android lab adapter route

No implicit device discovery/use. Without an explicit operator-provisioned owned
lab descriptor, selected serial and preinstalled harmless signed fixture, emit
`not_run/facility_missing` before calling ADB. A descriptor is private input, exact
keys `version=1`, `owned_lab=true`, `serial:label`, `device_id:HASH`,
`apk_file_id:ID`, `provisioning_receipt_sha256:HASH`. Root/lab owner must have reviewed
the referenced provisioning receipt for disposable state, no real accounts/data,
disabled customer networking and resource limits. A boolean alone cannot establish
ownership or setup. The receipt is opaque externally reviewed bytes, hash-pinned
in the plan; the descriptor is selected only by explicit `--lab LAB_ID`, never by
finding a file or environment variable. Present credentials do not authorize their use. No cloud,
provider, key, signing, enrollment, install/uninstall or settings-toggle commands.

Use an owned fixture at fixed package `fixture.validation`, Activity `.MainActivity`,
derived from `runtime/tests/android/local_policy/device/`. Build it with the actual
compile-only bridge jar, pack with the production API/CLI and pinned Android policy
as documented there. Offline fixture preparation/signing/provisioning belongs to
the lab owner, outside runner execution; never sign or reenroll on real hardware.
New fixture source/build manifest lives only in `validation/fixtures/android/`.
It declares no network permission or fixture JNI and exports only its launcher.
Preparation generates a compile-time expected-policy constant in the private build
directory using production `local_policy.load(policy_path).sha256`, records that
generated source digest and compiles it with the fixture. Do not learn the expected
hash from runtime info. At this exact parent the policy/selector catalogue is
revision 10, ID `fce392826ee1d9e5bab8046ca1584e2755af0eb3fd26922769eb20c64e32f736`;
the Android policy hashes to
`174e5db59a8f1bd3a657d8263d971b1507c66017b2513a2acda442deaa798cb0`,
while the existing sample Activity embeds `5685df69…`. Reuse its API pattern,
not its stale constant. The host startup fixture's uninitialized check does not
depend on a configured policy. Frozen HD02's revision-9 prose supplies no v10 pin.

The runner's fixed argv sequence uses `adb -s SERIAL`: `get-state`, `shell getprop
ro.build.version.sdk`, `ro.build.version.release`, `ro.product.model`,
`ro.product.cpu.abi`, `ro.kernel.qemu`, `ro.build.fingerprint`, and `shell getconf
PAGESIZE`; each getprop is a separate command. Verify the supplied device identity
against SHA256(`val01.device.v1\0` || UTF8(serial + LF + fingerprint)), keep serial
and fingerprint private, and match emulator/physical, API>=31, ABI and actual page
size. Missing properties are error, never default emulator=false or page size=4096.
Use `shell pm path fixture.validation`; require one base APK and no splits, stream
it through `exec-out cat` under the artifact byte cap and compare signed APK and
per-ABI injected runtime/config bytes with the plan. Do not accept version labels
or a package-name match as artifact evidence.

Before each cell force-stop only this fixture, verify no running fixture process,
and require no existing runner XML file. Launch via `shell am start -W -n
fixture.validation/.MainActivity --es validation_nonce NONCE --es
validation_scenario SCENARIO --es validation_phase baseline`. The singleTop fixture
handles a second same-nonce intent with `validation_phase execution` after the
runner has captured and verified baseline output. It rejects other/duplicate phases
or nonce changes without a fresh process. The fixture initializes using the real
`RuntimeBridge.initialize(getApplication())`, obtains `localPolicyInfo()`, waits
boundedly for a real monitor publication, and immediately calls
`gateLocalOperation("append_demo_receipt", COMPILED_HASH)` before the actual
in-memory receipt append. No injected observations, fake clocks or fixture-only
native collector. A clean positive control must return OK+ALLOW and increment
exactly once, with matching policy/config and actual evaluated rule details.

For `android_clean_receipt`, repeat with a separate counter and correct hash:
require OK+ALLOW, 0->1. For `android_policy_hash_mismatch`, use the altered expected
hash: require OK+DENY and reason HASH_MISMATCH=3, 0->0. INFO and raw owned decision
fields are read through the actual bridge. Setup verification checks nonce,
compiled scenario, unchanged package/config and clean control, not a fixture's
`setup_ok` claim. Neither scenario attaches a debugger or changes system settings.

Collect bounded UI XML with `shell uiautomator dump /sdcard/val01_NONCE.xml`, then
`exec-out cat` of that exact file. Parse without DTD/entities; require one status
view containing one JSON object with exact keys `nonce`, `scenario`, `phase`
(`baseline/execution`), `policy_sha256`, `config_sha256`,
`status`, `action`, `reason`, `before`, `after`,
`rule_id`, `rule_version`, `rule_status`, `rule_evaluated`, `rule_verdict`.
Pin rule/status/verdict to the exact production selector and typed-decision enums;
reject missing details, unknown numeric values or unevaluated baseline predicates.
Rule fields may be null and `rule_evaluated=false` for the hash-mismatch execution,
which rejects before predicate evaluation; never copy baseline details into it.
Capture each phase once as its own evidence file; setup uses independent ADB
environment/package probes. Repeat dumps may poll availability but never add samples.
This is instrumented fixture output cross-checked against ADB artifact/state and
receipt counts, not cryptographic evidence or a mocked security pass.

In `finally`, force-stop the fixture, remove only `/sdcard/val01_NONCE.xml`, verify
it is absent and no fixture PID remains, and rehash the installed base APK. Verify
the nonce-bound fixture startup reset its in-memory counters; no persistent fixture
data/settings may be written. A refused cleanup command, disconnected device or
unverifiable post-state is `error/cleanup_failed`, invalidating success and stopping
later device cells. Preserve the bundle for manual lab recovery. No broad deletion.

## Outcomes, evidence and denominators

Eight exclusive outcomes are `observed_detection`, `business_denial`, `bypass`,
`benign`, `crash`, `error`, `unsupported`, `not_run`. Observation and operation are
also retained independently: detection can coexist with a completed operation.
Only verified setup, clean control, exact matching artifacts and verified cleanup
permit benign/detection/denial/bypass outcomes. Expected outcome is checked after
derivation and cannot override evidence. Missing setup or baseline is error.

Derive in order: unstarted facility/adapter -> not_run; failed required phase or
binding -> error; signalled child/verified app death -> crash; valid positive
unsupported platform/API evidence -> unsupported; verified attack operation
completion -> bypass; independently observed explicit OK+DENY before unchanged
operation -> business_denial; registered typed present observation ->
observed_detection; verified completed clean operation -> benign; otherwise error.
Timeout/non-OK/REPORT/unknown action, no callback or lost connectivity cannot mean
business_denial. Raw benign VPN/accessibility/IME/support context never becomes a
typed malware observation. V1 has no attack adapter: bypass and attack detection
are reserved and rejected from its producers. Android hash rejection may yield
business_denial only for this harmless configuration scenario, never attack credit.

Closed reasons are `none`, `runtime_unavailable`, `facility_missing`,
`adapter_unavailable`, `budget_exhausted`, `unsupported_environment`, `invalid_input`,
`artifact_mismatch`, `source_mismatch`, `evidence_mismatch`, `duplicate_evidence`,
`baseline_failed`, `setup_failed`, `cleanup_failed`, `timeout`, `resource_limit`,
`process_crash`, `operation_mismatch`, `policy_hash_mismatch`, `collection_unavailable`.
Successful phases use none; skipped phases inherit the unavailability reason.
When several failures occur, cleanup failure is primary, then artifact/source,
evidence, baseline/setup, crash, timeout/resource, operation/collection failure;
other failure evidence remains indexed. Hash mismatch is an expected scenario
reason only after production reason/status and unchanged receipt are verified.

Every index entry binds run/cell/nonce/phase; every reference must resolve once to
that binding. Phase files embed the same binding plus bounded raw host/ADB/fixture
output; adapter-specific raw formats are exactly those described above, not an
arbitrary claim dictionary. One file cannot stand in for two phases/cells. Reject
duplicate IDs, paths, digests, reused nonce/result, stale evidence, missing files,
or unreferenced files. A repeated verification of the same immutable bundle is
idempotent; it never adds samples. Failed cleanup preserves evidence and blocks
release even when a detection/denial was observed beforehand.

Captured phase files are closed envelopes: `run_id`, `cell_id`, `nonce`, `phase`,
`kind`, `probe`, `data` (raw UTF-8 string <=240 KiB), `exit_code` (0..255 or null),
`signal` (1..64 or null), `elapsed_ms` (0..120000). Probe is `host_event`, `get_state`,
`environment`, `package_path`, `apk_hash`, `process_state`, `launch`, `ui_dump`,
`remove_xml`, `scratch_state`. Host/fixture data parses to the exact events above;
ADB raw values parse according to the fixed command, never a submitted success
boolean. Exit and signal are mutually exclusive. The local supervisor records
process/scratch cleanup and remote command results; a fixture cannot attest to
its own process termination. Bundles are private mode 0700/0600, contain no keys,
accounts or public device serials, and are explicitly deleted by their lab owner
after review; no upload or automatic erasure of failure evidence.

Summary is recomputed over all planned cells, including not_run/unsupported/crash/
error; counts sum to planned. Missing result records are invalid, not omitted.
`missing_cells` lists planned cells without verified execution, including unsupported
and unrun cells. `conformance=pass` means valid format plus all expected behaviors
and cleanup for started cells; it does not mean security or release success.
Release is `not_requested` if no cells are required; otherwise pass requires every
required cell to execute with verified phases and match benign/detection/denial
expectation. Expected error/unsupported/not_run can never satisfy release. No
effective-denominator filtering, zero-cell suite or host-only device substitution.
Report attack detection, denial and bypass counts separately; attack denominator
is zero in v1 and effectiveness remains not_run, with no rate/market ranking.

`run` and `verify` exit 0 only for conformance pass with release_gate not fail;
exit 1 means valid bundle with failed conformance/requested gate, 2 means rejected
input/evidence format or binding, 3 means runner I/O/internal failure. Invalid input
causes no adapter calls. Once execution starts, best-effort bounded cleanup and
an atomic complete bundle are required; write failure returns 3 and leaves the
private partial directory explicitly unusable, never a success-shaped result.

## Paired measurements: validation only

`measurements` is [] or <=8 closed Pair records with exact keys `cell_id`, `metric`,
`unit`, `conditions_sha256`, `baseline_artifact_id`, `protected_artifact_id`,
`expected_pairs`, `samples`, `missing_indices`. Metric is `cold_start`, `warm_start`,
`scan`, `dex_first`, `dex_later` (unit `ns`) or `rss` (unit `bytes`). Expected pairs
is 30..300. Sample keys are exactly `index` (0..expected_pairs-1), `baseline`,
`protected` (integer 1..2^53-1), `baseline_evidence_id`, `protected_evidence_id`.
Each role has a different nonce-bound measured evidence file, with exact keys
`run_id`, `cell_id`, `nonce`, `phase=execution`, `metric`, `index`, `role`
(`baseline/protected`), `value`, `unit`, `conditions_sha256`, `artifact_id`.
Reject zeros, nulls, NaN, negative/overflow, duplicate indices/evidence and
unmatched values. Missing indices must exactly complement complete pairs.
Conditions hash binds same fixture revision/device/OS/ABI/page size/channel,
foreground state, temperature/power policy, metric procedure and run order;
only protected artifact/config differs. Preserve separate provenance for the
baseline artifact. A complete comparison requires >=30 measured pairs and no
missing indices; absent/partial collections remain explicitly incomplete. V1
validates imported evidence only and always leaves performance_gate=not_run;
VAL03 must define collectors, conditions schema and approved budgets before any
performance acceptance or public figures. No fabricated sample/example results.

## Minimal file list and acceptance handoff

After root approval only: add `validation/run.py`, `validation/tests/run_test.py`,
`validation/suite.json`, `validation/fixtures/host.c`,
`validation/fixtures/android/{AndroidManifest.xml,MainActivity.java,build.sh}`;
modify only `runtime/tests/CMakeLists.txt` for the fixture target. Add
`docs/validation.md` (protocol, detector review checklist and reproduction limits)
and `docs/research/index.md` (release/evidence links, scope, redaction/disclosure
review; reference SECURITY.md). Reuse existing test/tool conventions; no new
package, catalogue, persisted model, workflow matrix or historical framework port.

Acceptance sequence, using the later root-assigned clean parent and private build:

1. Write failing runner tests for forged setup boolean vs missing measured proof,
   changed APK/native/registry after baseline, wrong source/policy, duplicate or
   cross-phase evidence, missing clean control and cleanup, cleanup disconnect,
   unknown fields/types/status, byte/depth/process limits and killed/reaped children.
2. Add known benign VPN/accessibility/IME/support records: context remains context;
   unavailable/unsupported collection never becomes absent. Assert exact planned
   counts/missing cells, zero samples/denominator failure and unequal or duplicate
   paired samples; serializer checks do not stand in for device measurements.
3. Implement the fixed script and host fixture. Run serial
   `python3.14 -m pytest -p no:cacheprovider validation/tests/run_test.py`;
   configure a private host build, build `rasp_validation_host --parallel 2`, run
   through the CLI and independently verify the bundle. Assert startup ERROR is
   expected conformance and cannot pass required release/effectiveness gates.
4. Implement Android argv/fixture; test protocol errors with labelled transport
   fixtures (no security credit). With no lab descriptor assert zero ADB calls and
   explicit not_run. Actual provisioned device execution is a separate gate; record
   signed-artifact, baseline, real API decision, receipt and cleanup evidence or
   leave every device cell not_run. Apple physical execution remains not_run.
5. Run appropriate format/type checks for the new Python and native fixture; root
   owns exact-parent CI, later integration and any required platform checks. Add a
   detector review checklist covering threat/source/status/version, benign/attack
   fixture references, limitations, owner/reviewer and real evidence links. Index
   methodology only until measurements exist; external research proves publication,
   not current-runtime efficacy. Stop for root code review before publication.

Design-stage verification is document/source consistency only. No device access,
build, runtime test, signing, numerical benchmark or production efficacy is claimed.

## Accepted implementation addendum

The preceding design remains historical. Root subsequently accepted it with the
six implementation clarifications in `validation-foundation-root-amendment.md`
(private root dispatch), and assigned passing parent
`69107e15a26f2e4a78d975ef584cd06be2773c04`, tree
`ee2e830ffa1e275466078c598e881ce30375bee7`. The software below implements that
authorization. Actual ADB/server/device/sign/install/provider operations remain
unauthorized in this implementation stage and all device cells are NOT_RUN.

These concrete representations supersede corresponding historical details above:

- Build receipt adds required `dependency_manifest` (File ID or null for static
  host). Bundle adds required `artifacts`, an array of at most
  `96 - len(plan.files)` retained binary stream records. Each is exactly
  `{path,bytes,sha256,file_id,run_id,cell_id,nonce,phase}`. Its `file_id` resolves to
  the pinned signed APK; byte count/hash must equal both the retained binary and
  the source inventory. Aggregate input plus streamed bytes remain <=256 MiB;
  every binary stream remains <=64 MiB. Binary stdout never enters textual data.
- Phase envelope has exactly `run_id,cell_id,nonce,phase,kind,probe,data,stderr,
  exit_code,signal,elapsed_ms,artifact`. `artifact` is null or that exact binary
  record. Exit code is 0..255 or null, signal is 1..64 or null, exactly one present.
  `probe` belongs to the fixed `PROBES` set in the runner, not a submitted command.
  The supervisor captures server ownership/startup and cleanup with matching PID
  and private endpoint. All ordinary text remains bounded by 256 KiB/16 MiB.
- ADB uses one supervised `-L localfilesystem:/tmp/v01-PRIVATE/server.sock
  --one-device SERIAL server nodaemon` process. Every client carries the same
  `-L` endpoint and `-s` serial. Clients cannot fork (RLIMIT_NPROC=0); v1 rejects
  root clients and tool shapes that require extra client threads/processes. The
  fixed pinned help version is 35.0.2-12147458. This software restriction is tested
  locally; USB behavior is not claimed. V1 supports isolated USB labs, with emulator
  routes explicitly NOT_RUN. No default server discovery/start/kill occurs.
- Lab descriptor has exactly `version,owned_lab,serial,device_id,apk_file_id,
  provisioning_receipt_sha256,adb_file_id,transport,network_isolation,
  preauthorized,adb_home`. Version is 1, ownership/isolation/preauthorization are
  true, transport is `usb`, serial is `[A-Za-z0-9_-]{1,64}`. The private provisioned
  ADB home must differ from the user's home, contain existing authorized keys and
  remain unchanged. The runner never generates keys or enrolls a device. This is
  a future explicit owned-lab prerequisite, not ambient credential authorization.
- Installed Android preflight is mandatory before ADB. It reuses the actual
  installed policy/config/archive/resource/export/artifact APIs, never source
  PYTHONPATH or a fixture success flag. `dependency_manifest` is <=1 MiB, exactly
  `{version,python,prefix,files,distributions}`. `files` has <=1024 closed records
  `{path,bytes,sha256}`, absolute resolved regular singleton files <=64 MiB each
  and <=256 MiB total. `python` equals the resolved interpreter and `prefix` its
  installed environment. Each distribution is `{name,version,wheel_id}`; the
  actual packer wheel is mandatory and byte-compared to installed contents.
  Third-party dependency wheel IDs may be null only when every installed file
  is pinned in the manifest. The installer-rewritten RECORD is pinned as an
  installed file instead of compared to the wheel RECORD. Loaded native mappings
  and the ADB ELF dependency closure must be bound; files are rehashed at lifecycle
  boundaries. Existing shared hardlinked installs must first be copied into a
  private environment, never modified or accepted through a link exception.
- File roles additionally include `dependency_manifest,wheel,injection_manifest,
  injected_entry,apk_unsigned`. Unsigned APKs are accepted only by the programmatic
  offline preparation check; the runnable lab route requires `apk_signed` and
  exact preinstalled byte equality. Empty installed module files retain valid
  hashes; native/artifact/measurement semantics cannot pass on empty content.
  Safe path components additionally permit `+` for actual `libstdc++` filenames.
- Injection manifest is exactly `{version,entries,runtimes,stub_file,bridge_file,
  compiled_policy_sha256,compiled_expectation_file,build_id,checks,policy_file}`.
  `entries` has <=96 records `{name,file_id}`. `runtimes` has 1..4 records
  `{abi,pristine_file,injected_file,capability_file,support_file}`. All references
  resolve to checked inputs. The generated compile-time expectation source must
  exactly contain the production parser's policy hash. The approved build receipt
  binds that source and bridge jar to the actual APK; hashes are not attestation.
- New fixture status views use separate baseline/execution intents and receipt
  counters. Cleanup proves the recorded fresh baseline and actual fixture process
  termination, exact XML deletion and post-state APK identity. It never launches a
  second app to inspect memory after force-stop. Fifteen UI polls per phase stay
  within the original 45-poll/32-evidence ceilings. Failures cannot pass conformance.
- Paired measurements require 30..64 expected pairs and <=64 actual pairs across
  the suite. Each pair has distinct <=8 KiB measured evidence files. Partial sets
  retain exact missing indices. Performance acceptance remains NOT_RUN: VAL02 owns
  performance collection/budgets, VAL03 the broader benign/false-positive matrix.
- Limit setup occurs in a fresh exec helper, avoiding `preexec_fn` in a potentially
  threaded interpreter. Process ownership cleanup begins immediately after Popen,
  including binary output acquisition and all pipe/selector partial failures.
  Output uses exclusive creation; an open failure kills/reaps the child/group and
  preserves prior output. Completed result publication is atomic without overwrite.

See [the runnable protocol](../docs/validation.md) for actual build/plan commands,
limits and detector review, and [the evidence index](../docs/research/index.md) for
reproduction/disclosure scope. Root owns code review and later publication/CI.


## Independent review correction clarifications

The retained unique `config` input must equal the canonical bytes emitted by the
actual installed production `RuntimeConfig` used for injection and effective hash
verification. Offline Android success reuses the pure live lab/probe predicates
and requires the ordered setup, launch/dump/read and cleanup sequence. It does not
read live keys or contact devices. Absence requires exit 1 and empty stdout/stderr.
Both APK stream slots and their pinned byte sizes are reserved within the existing
96-file/256-MiB aggregate before acquisition; a failed attempt keeps its budget.
Remote cleanup requires admitted identity/environment/APK and a touched fixture;
XML deletion also requires prior absence and our own creation attempt. Local
process-group ownership persists until the last signal, followed by reaping.


Root’s XML/public-reproduction correction places nonce XML ownership at successful
dump process acquisition, after all local alive, budget and acquisition refusals,
inside the command’s ownership cleanup. Failed launched dumps retain cleanup;
local refusals acquire none. The existing twenty-second cleanup reserve remains.
`validation.prepare` is the separate offline SDK/installed-production input
producer for the same closed formats, not a third execution route. The serial
Runtime workflow consumer reuses existing host/four-ABI build artifacts and runs
the full Python suite with genuine prepared inputs and zero prerequisite skips.
No actual ADB invocation, signing/install, live lab or device proof is introduced.

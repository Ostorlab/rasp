# Opt-in scoped signing companion

The shared companion implements bounded application-owned signing requests and
key lifecycle state. It is a separately linked host SDK foundation. It is not
linked into the injected runtime or stub. Without a reviewed platform attachment,
its real public C facade returns `RASP_SK_CALL_NOT_READY`, with no key, signature
or advertised hardware capability. Android Keystore/JNI/private-storage/UI and
Apple Keychain/Secure Enclave/Objective-C++/Swift attachments are separate reviewed
followups; host fixture providers are not those implementations.

Build explicitly with `-DRASP_BUILD_KEY_COMPANION=ON` and target
`rasp_scoped_keys`. Host test builds include the companion tests automatically.
Do not add another RuntimeBridge class, loader constructor, monitor, private
runtime C++ call, packaged payload-key import or new injected-runtime export.

<a id="public-contract"></a>

## What does the public contract guarantee?

**[scoped_key.h](../runtime/companion/include/rasp/scoped_key.h)** defines ABI1's four
companion functions, complete primitive layouts and fixed enum values:

- `rasp_scoped_key_client_open_v1`: explicit worker-thread host opt-in.
- `rasp_scoped_key_submit_v1`: bounded owned admission for CREATE, REOPEN,
  DESCRIBE, SIGN, DELETE or RESET_NAMESPACE.
- `rasp_scoped_key_take_v1`: nonblocking progress or a single owned completion.
- `rasp_scoped_key_control_v1`: CANCEL, RELEASE_KEY or CLOSE_CLIENT.

Check C call status and operation status separately:

| Layer and value | Number | Meaning |
| --- | ---: | --- |
| C call `RASP_SK_CALL_OK` | 0 | A valid typed answer; inspect its operation/state fields. |
| Operation `RASP_SK_OP_UNAVAILABLE` | 0 | Unavailable, including zero-initialized failure; never success. |
| Operation `RASP_SK_OP_OK` | 1 | Operation success, subject to its state/value and durability fields. |

**Admission ACCEPTED** is not completion, authorization or a durability acknowledgment.
Unknown versions, values, nonzero reserved bytes, unused union arms/tails and bad
lengths are failures. Exact sizes, alignment 8, valid readable/writable memory and
nonoverlapping input/output are required; no API can validate arbitrary pointers.
All public scalars are fixed width. C++ objects never cross this interface.

Submit is 4384 bytes and SignInput is 4336 bytes. Allocate these on an aligned heap or
bounded caller arena, pass pointers and retain no borrowed memory after return.
TakeResult 2600 and gate result 2104 must not be stacked together in shipping SDK
functions. Completion 2560 contains the full owned gate diagnostic projection.
No native frame may exceed 4096 bytes. Public caller-owned results may be retained;
they cannot be submitted as permits or used to revoke a returned signature.

Namespaces bind one exact application, public signing scope, purpose, named gate
operation/hash, advisory/mandatory mode and minimum key profile. The application
identity is obtained from the attached platform. Callers cannot select arbitrary
existing aliases, access groups, packages or another app's keys. Handles and request
tokens are process/session-local lookup identities, not secrets or capabilities
against a compromised host. Public KeyIds reopen only exact owned manifest entries;
missing keys are never silently regenerated or adopted after restore/reinstall.

The only algorithm is P-256 ECDSA over a complete message using SHA256, with strict
X9.62 DER signatures. No raw-digest signing, key import/export, arbitrary bearer
storage, encryption, ECDH or attestation is implemented. Per-key backend/security
level, export policy, lock, authentication, accessibility and backup properties
are distinct; unknown facts remain unknown and required minima never fall back.
Software Keychain storage must not be described as Secure Enclave protection.

<a id="message-binding-and-local-gate"></a>

## How is the signed message bound?

Integers in the canonical encoding are unsigned big-endian 32; LP means a 32-bit
byte length followed by those exact bytes. No JSON normalization, padding, C NUL
terminator, host endianness or ABI structure representation enters these hashes.

```text
app_scope = LP(package_or_bundle_id) || LP(public_signing_scope)
profile = "Ostorlab.RASP.KeyProfile" || 00 || u32(1) || u32(algorithm=1)
 || LP(app_scope) || u32(selector) || LP(namespace) || LP(purpose)
 || LP(gate_operation) || expected_policy_sha256[32] || u32(gate_mode)
 || u32(backend_requirement) || u32(auth_requirement) || u32(lock_requirement)
message = "Ostorlab.RASP.ScopedSign" || 00 || u32(1) || u32(algorithm=1)
 || LP(app_scope) || LP(namespace) || LP(purpose) || LP(gate_operation)
 || expected_policy_sha256[32] || u32(gate_mode) || SHA256(profile)[32]
 || key_id[16] || uncompressed_public_key[65] || LP(audience)
 || transaction_id[16] || challenge[32] || LP(transaction)
```

The frozen [golden vectors](../runtime/companion/tests/golden.h) contain exact
184-byte profile and 391-byte message encodings. Their SHA256 digests are
`0b4738f29470f97a90f083498124b82b0b685fe0061159d49449f38a2672f726` and
`235973893a722d9b923e7fe2428b3178ebc1ed1836b468218b9834dfc6608d01`.
The fixture's published P-256 generator point is public data, not a generated or
production key. Maximum profile/message lengths are 581/4958 bytes.

SIGN calls the existing actual `rasp_local_policy_gate_v1` before auth, immediately
before the primitive after any yield, and before successful delivery. REQUIRE_ALLOW
needs status OK and ALLOW. Explicit advisory mode also accepts REPORT while retaining
its actual candidate/reasons; it never overrides DENY, a hash mismatch, non-OK or
unknown action. The expected hash is host-compiled, never learned from runtime info.
Unknown, expired or clock-invalid evidence cannot become a mandatory permit.
The gate is a historical local decision, not backend authority or attestation.

CREATE validates platform prerequisites without gate/auth UI; REOPEN/DESCRIBE are
noninteractive. DELETE/RESET and cancel/release/close need no gate or auth prompt.
Only explicit interactive SIGN may start one system biometric prompt for its exact
retained crypto context. No public auth-success/decision continuation is exposed.
A biometric result does not prove the user understood or approved the transaction.
Server authorization, challenge expiry and replay defense remain server-owned.

<a id="ownership-bounds-and-durability"></a>

## What are the ownership, bounds and durability limits?

One constinit, explicitly `clang::no_destroy` process-stable registry owns the
single service, native full-entry read/write lock, active pointer, never-reset
optional service and one 4096-byte child adapter reservation. Its complete `sizeof`
is statically checked against 131072 bytes; no list of abandoned clients or
per-request heap/thread/timer is allocated.

The mutex has process lifetime on every libc++; no registry constructor or exit
destructor runs. Descriptor/adapter release is a separate exclusive quiescence
transition.

The fixed arenas have the following budget:

| Arena | Count | Bytes each |
| --- | --- | ---: |
| Request | Eight | 6144 |
| Completion | Eight | 4096 |
| Physical job | Two | 8192 |
| **Total arena bytes** | | **98304** |

The remaining 32768 bytes are the total allowance for all nonarena SDK state,
including registry metadata and the child adapter reservation. They are not free
Android adapter memory; all such state remains charged to the aggregate ceiling.

SHA-256 uses the exact pinned TF-PSA-Crypto stateless primitive, without PSA wrapper
heap copies, key slots or RNG initialization; its existing configuration is
unchanged. Each signing job arena has typed disjoint 4960-byte message, 2104-byte
gate, 32-byte hash, 72-byte DER and 1024-byte context fields.

Each job uses an explicit two-alternative variant for file or signing phases; its
finite discriminator counts as metadata. File bytes never alias a live typed
gate/auth context.

This is an SDK-state ceiling, not a process RSS, OS/provider-buffer or thread-stack
measurement. Caller-owned inputs/transferred outputs are outside the SDK's control.

Limits are four namespaces, eight owned keys per namespace/32 total (including
reservations/tombstones), 16 handles, eight retained requests/callback leases, two
physical jobs and one auth prompt. Existing-key operations serialize per key;
manifest mutations serialize globally. Failure of a provider to finish quarantines
its original slots/context; no replacement workers are spawned. Handle leases
expire at 300 seconds and explicit request deadlines at most 60 seconds, including
suspension. Exact expiry is invalid; clock regression/read failure latches the
client domain. Reopening cannot reset the runtime gate's separate publication latch.

Public/UI entry tries a native read lease without waiting before loading the active owner.
Worker `run_job`/`authenticated` entries wait for that lease. `end_delivery` first touches
only permanent atomic slots/counters; its fold/post pins the native owner before any
platform access. The owner/mutex is constructed once and never destroyed or replaced.
Detach is a nonblocking exclusive upgrade only when fully closed.
The closing worker waits for whole-entry quiescence before releasing platform
storage/descriptors. UI/public entries never perform that wait. End-delivery records
its acknowledgment atomically even if the state mutex is contended; the next bounded
state access folds it into the tables without requiring another end-delivery call.
Only stale callbacks can be rejected during an exclusive closed-state transition.

If a worker open fails after acquiring storage and its first close also fails, the
original operation failure is returned without a client. One bounded closing job
retries release; a later worker open may post another attempt and returns CLOSING.
Repeated failure or scheduler rejection retains ownership without a repost loop.
Main-thread open remains refused, and replacement/detach waits for quiescence.

CLOSE returns DRAINING while jobs, OS/UI continuations, native entries, callback
leases or cleanup retain ownership. Repeated control observes progress; a hung
borrower can keep the same bounded owner draining indefinitely. Replacement opens
are refused. CLOSED means quiescence, not key deletion. Release/close retain live
persistent keys. Cancellation cannot retract an already delivered signature or
guarantee a physical primitive was aborted; results report actual/unknown effects.

Persistent KeyIds and installation generations use full 16-byte CSPRNG outputs.
Key allocation checks current records and rejects after at most four zero/collision
attempts; it never substitutes a predictable identity after RNG failure.

Process-local request/job/handle lookup tokens use a non-reused allocation ordinal.
They are not cryptographic capabilities against the host.

The dedicated manifest contains only generation/app/profile/key identities,
public keys/properties and reserved/live/delete-pending states. Its fixed 8192-byte
codec validates version, closed states, padding, duplicate identities and corruption
digest. A digest is equality/corruption evidence, not authenticated storage or a
rollback counter. Transactions, challenges, signatures, accounts, tokens and private
keys are never persisted. Platform children own private directory/file validation,
backup exclusion, exclusive process/storage locks and file/rename/directory fsync.
There is no dependency on a host-context storage-capability API or a cross-libc++
PrivateStorage ABI.

DELETE/RESET admission invalidates targeted key use in memory. Reservation
durability must precede OS generation; verified live durability precedes a usable
handle.

DELETE/RESET must acknowledge durable tombstones before OS deletion. Actual absence
plus durable retirement is required before confirming deletion.

Ambiguous publication/effects stay UNKNOWN. Any uncertain write latches the client,
refuses further key admissions/uses, and closes without rewriting stale memory.

Reopen validates the actual durable file and retries only its recorded
reservation/tombstone identities; cancel/expiry never fabricates rollback. Cleanup
captures exact KeyIds, not recyclable record indices or a later wider namespace.

Lost undurable reset intent cannot be reconstructed; host retry must preserve its
original identities. Reinstall never adopts old-generation Apple Keychain orphans
or claims uninstall securely erases them.

Owned mutable message/signature/context buffers are wiped after the last borrower.
Quarantined in-flight buffers remain bounded until safe release. This cannot hide
plaintext from a compromised process, caller/GC/OS copies, dumps or prior observation.
There is no release telemetry/logging, malware verdict, process scanning/termination,
legal-hold feature or widening of an unrelated deletion request.

## Private child adapter and validation

The [internal platform boundary](../runtime/companion/src/platform.h) is not installed
or exported. Android and Apple attachments construct at most one adapter in
`platform_storage()` and
retain it until exclusive detach succeeds. Provider methods implement actual public
OS key/store/UI behavior; none has a success stub or weaker fallback. OS callbacks
post bounded copied job identities to SDK workers before `authenticated`; they do
not call blocking shared-state methods on UI/OS callback queues. Scheduling never
invokes `run_job` inline. Full job identity and owned context survive early/later,
duplicate, cancelled and retired callbacks; release acknowledges no remaining OS
borrowers. Every platform key/storage/UI call is outside the service state mutex.

Host tests use actual C entry points, actual local-policy CycleMonitor publication/gate,
owned fixture keys and independently reconstructed/verified OpenSSL P-256 outputs.
Controllable providers are test-only and absent from the production archive. Their
properties are simulated contract inputs, not Android Keystore, Apple Keychain,
hardware, lock, biometric, restore or physical-device evidence. Actual child
platform implementations, Apple SDK/Swift/NDK consumers and supported physical
device outcomes must be recorded independently before claiming platform support.

## Callback contention and prompt revalidation

Private `run_job` and `authenticated` run on the two existing executor workers and
wait for a native read lease before loading the installed owner. Public C calls
continue to try the lease and return BUSY without waiting; a failed attachment
writer cannot consume a valid worker callback.

`end_delivery` never waits for a registry writer or service mutex. Its stable
pointer is published once, never reset, and permits only an atomic full-token
acknowledgment in never-destroyed request slots and monotonic release counters.

That pointer cannot access a platform, descriptor or releasable mutex. Every
fold/post first acquires a native read pin; entry/writer exits kick a bounded
eight-pass drain.

Counters are never reset on close/reopen, so a late or duplicate token cannot
release a replacement lease. The same two job arenas and bounded scheduler remain
in use.

SIGN revalidates before committing authentication in this order:

1. Complete provider lookup.
2. Recheck the actual request, handle, clock, deadline and cancellation state.
3. Obtain the real local gate.
4. Sample the clock again.
5. Recheck eligibility.
6. Commit authentication only if all checks pass.

Cancellation, close, request expiry or handle expiry during lookup cannot start a
prompt. The existing early-auth handshake and post-yield/preprimitive/take gates
remain required.

## Build and validate the companion

From the repository root, build the existing host fixtures and run their registered
CTest cases:

```sh
cmake --preset host -S runtime -B /tmp/rasp-scoped-key-host -DRASP_BUILD_KEY_COMPANION=ON
cmake --build /tmp/rasp-scoped-key-host --parallel 2 --target rasp_keys_test rasp_keys_c_consumer rasp_keys_hash_allocation_probe
ctest --test-dir /tmp/rasp-scoped-key-host --parallel 2 --output-on-failure --no-tests=error -R '^Scoped'
```

See the [companion build targets](../runtime/companion/CMakeLists.txt),
[public-C Service tests](../runtime/companion/tests/service_test.cpp),
[ABI tests](../runtime/companion/tests/abi_test.cpp), and
[encoding tests](../runtime/companion/tests/encoding_test.cpp) with their
[frozen golden vectors](../runtime/companion/tests/golden.h).

The installed [Android C/C++ consumer check](../runtime/companion/tests/consumers/check_android.sh)
and [Apple C/Objective-C++/Swift consumer check](../runtime/companion/tests/consumers/check_apple.sh)
are exercised by the [platform CI workflow](../.github/workflows/runtime.yml).
Android and Apple attachments remain separately reviewed followups through the
[private child adapter boundary](#private-child-adapter-and-validation); actual
provider/device evidence is required before claiming their support.

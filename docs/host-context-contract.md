# Local host sensitive-operation context v1

This source adapter tracks a finite host-declared flow before calling the
[existing local operation gate](local-policy-contract.md). Applications must
explicitly compile it and adapt their call sites. Packing alone does not add
input semantics or intercept business operations.

Context is always an **unverified host declaration**. Readiness is flow coherence,
not a benign-device predicate, user-intent proof, authentication or backend
authorization. The native gate still evaluates the actual owning measurement
cycle with the compiled exact operation/policy hash. Host context can prevent an
adapted operation; it cannot make the native gate more permissive.

## Data and bounds

Version1/reason1 are local source versions with no network encoding. The adapter
accepts no timestamps, text, arbitrary labels, raw URLs or variable-length blobs.

| Fact | Values |
| --- | --- |
| purpose | UNKNOWN0, CREDENTIAL1, OTP2, PAYMENT_CONFIRMATION3, BENEFICIARY_CHANGE4, SESSION_CHANGE5, OTHER_SENSITIVE6 |
| secure_entry | UNKNOWN0, CONFIGURED1, NOT_CONFIGURED2, UNSUPPORTED3, NOT_APPLICABLE4 |
| lifecycle | UNKNOWN0, FOREGROUND_ACTIVE1, INACTIVE2, BACKGROUND3, DESTROYED4 |
| completion | NONE0; END only local FINISHED1 or FAILED2 |
| refs | Exactly16 random opaque bytes each for session/action; zero when unused |
| generation/sequence | Nonzero1..INT64_MAX, never wrapped or wall clocks |
| attempts |1..3, initial BEGIN1, explicit RETRY increments |
| ages | Session300s; action120s from original BEGIN; last event30s. Equality accepted; +1ns expires. |

Use fresh UUID/SecureRandom references, scoped to this app and selected tenant.
They must not be customer/account IDs, real auth sessions, challenges, cookies,
keys, transaction IDs, amounts, beneficiaries or hashes of business content.
They confer no authority. The host replaces/disposes owners on logout or scope
change. The SDK cannot authenticate the host's claimed scope.

The host compiles an immutable binding: existing gate operation name1..32 ASCII
bytes, exact64-lowercase-hex policy expectation, and `require_secure_input`0/1.
Never learn the expectation from runtime policy info. The optional requirement
accepts only CREDENTIAL/OTP with CONFIGURED at gate time; default0 does not add
a secure-entry denial. UNKNOWN purpose cannot begin an action. NOT_APPLICABLE
is only for actions with no input control.

## Ownership and source APIs

Compile [the host source package](../runtime/host_context/README.md) into the app.
All entry points are main-thread confined; no owner may be copied, shared across
threads, reinitialized to reset counters or used after freeing its storage.
One owner tracks one selected flow/action/control. It retains no View/Activity/
scene, registry, history, worker, timer or event queue. Multiple windows require
explicit host handoff; no automatic scene/window selection is performed.

C entry points in `rasp/host_events.h` initialize a zeroed caller-owned owner,
apply one finite event, synchronously gate a current tuple, and dispose. Native
state is at most512 bytes with no heap allocation. The header/implementation are
compiled together; internal owner layout is not an inter-binary ABI. Event/View/
Binding sizes are80/120/116 bytes with natural alignment. Event/View align to4
on Android x86 and8 on arm64/armv7/x86_64; Binding aligns to4. No packing or forced
alignment is used. Real compiler gates check these layouts on supported targets.

Java `HostOperationContext.Binding`, `Event`, `View` and `GateResult` are owned
values. Ref arrays are copied on input/access. The reducer delegates through the
existing `RuntimeBridge.gateLocalOperation` Java/JNI/C route. No caller can supply
a PolicyDecision. Swift owns a single C owner and returns copied C values, using
the header's typed `kRaspLocal*` native constants. No C++ object crosses the
framework boundary.

The event fields, in order, are uint32 version,size,kind,purpose,secure_entry,
lifecycle,attempt,completion; uint64 generation,sequence; uint8 session[16],
action[16]. For START use lifecycle1, zero action/attempt/purpose/secure/completion
and sequence1. For BEGIN/INPUT/RETRY use known immutable purpose, secure state,
action/attempt, lifecycle/completion0. BEGIN attempt1; RETRY previous+1.
LIFECYCLE has zero purpose/secure/completion and the current action/attempt or
zero if none. END has completion1/2 and zero purpose/secure/lifecycle. CANCEL has
zero purpose/secure/lifecycle/completion. STOP has zero refs and facts; generation
and sequence identify the owner. All versions/sizes/ranges/shapes are validated.

The caller supplies valid, aligned, distinct storage for the exact-sized C
arguments. Non-OK status never permits an operation. The C ABI cannot contain
arbitrary invalid pointers, OOM or a compromised host process.

## State and admission

START explicitly replaces a session using the next generation and a fresh ref.
A repeated exact START is NO_CHANGE, not refresh/repair. BEGIN starts a fresh
action from READY or a terminal action state. INPUT replaces configuration,
including UNKNOWN/UNSUPPORTED; it cannot retain an earlier CONFIGURED value.
INACTIVE/BACKGROUND/DESTROYED/UNKNOWN lifecycle closes the session. Resume needs
fresh START/BEGIN. END records a local result; CANCEL closes the action. STOP
closes the session. No client completion claims server authentication or success.

Only retry-eligible FAILED retains the action ref/purpose/start; FINISHED/CANCELED
erase them and retain a minimal terminal tombstone. A valid repeat matching its
generation/sequence/kind/attempt/completion is NO_CHANGE without accepting refs
or readiness. This intentionally does not detect payload conflicts after erasure.
Live/retry-eligible duplicates compare the exact event. STOP's canonical zero-ref
event can be retained; lifecycle termination/fault/expiry erase it. NO_CHANGE
never samples a new age or refreshes timestamps. Error/terminal readouts redact
refs; timing_present0 numbers must not mean fresh age0.

Validation order is deliberate:

1. Wrong thread, disposed owner, null/short/incompatible/aliasing framing rejects
   without changing the owner. Decodable malformed events fault only the matching
   current generation/session and matching action/attempt when action-scoped.
   Old/foreign/unidentifiable malformed envelopes cannot poison a newer flow.
2. Fully well-formed old/foreign identities reject before clock or sequence
   mutation. Exact duplicates/tombstones short-circuit before RETRY's next-attempt
   check. A smaller current sequence rejects; conflicting same-sequence or gaps
   fault the attributable flow. Valid expected transitions then sample time and
   apply. Invalid current transitions fault; no old good state is restored.
3. Gate validates the exact generation/last-sequence/attempt. Every mismatch
   leaves current facts, clocks and consumption untouched. A duplicate admitted
   gate sees ATTEMPTED and cannot return/reuse its prior result.
4. The exact ACTIVE gate checks its private clock, ages and finite context.
   Configuration rejection does not consume. Clock faults latch FAULT; expiry
   becomes EXPIRED; neither invokes native code or consumes an attempt.
5. After every pre-check passes, ACTIVE becomes ATTEMPTED immediately before the
   real native call. This is the single consumption point. Native DENY/ALLOW/
   REPORT/BUSY/error/null all consume. Explicit RETRY/new sequence and fresh input
   declaration are required before another gate. Retry cannot reset action age.

Android uses elapsedRealtimeNanos; native Android uses CLOCK_BOOTTIME; Apple uses
checked mach_continuous_time conversion. No public event can provide clock data.
Negative/unavailable/backward/overflowing samples fault; wall time is ignored.
New valid START is required for recovery. Age sampling is lazy; foreign/error
framing/duplicate short circuits do not alter clock health or extend lifetime.

The host checks context status OK **and** native status OK and known action at
the actual side-effect boundary. ALLOW may perform one immediate adapted effect.
REPORT is advisory and requires an explicit separate host branch. DENY/error/
unknown/null produces no effect. For a C native call not made, gate ABI/size0,
status NOT_READY/action DENY are an unavailable sentinel, not a valid native reason.
Java uses null. A returned result is historical evidence, never a reusable token.

Final sample -> gate -> effect must run on the owner thread with no await,
queueing, host callback or run-loop pumping between them. After intervening work,
discard the result and establish a new admissible attempt. Worker/network
operations require customer serialization and server authorization; this adapter
does not make them atomic with UI state. Host business idempotency remains
necessary, especially when an already-executed remote operation returns unknown.

## Input and platform behavior

Android's explicit `secureEntry(selected)` samples only an exact standard
EditText's inputType and transformation configuration. Password/number-password
semantics plus standard password masking map CONFIGURED; visible/revealed or
unmasked fields do not. Custom editors/subclasses/frameworks are unsupported.
It never reads text, length, selection, autofill data, keystrokes or clipboard.
The host calls it after deliberately configuring the field and immediately
before gating on the same thread; the adapter never changes input behavior.

Use appropriate host password types; an IME no-personalized-learning flag is only
a request that an IME can ignore. Ordinary apps cannot ban third-party Android
keyboards through this adapter. DevicePolicyManager restrictions require managed/
privileged authority and are outside scope. A third-party keyboard/password
manager is not malware. [InputType](https://developer.android.com/reference/android/text/InputType),
[EditorInfo](https://developer.android.com/reference/android/view/inputmethod/EditorInfo#IME_FLAG_NO_PERSONALIZED_LEARNING),
[managed input policy](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPermittedInputMethods(android.content.ComponentName,%20java.util.List)).

Apple's explicit sampler accepts exact UITextField and reads only isSecureTextEntry.
Custom controls/UITextView/WKWebView/framework surfaces are unsupported. The host
sets password secure entry before use; UIKit secure input excludes custom keyboard
extensions. Apps can separately reject `.keyboard` in their existing application
delegate, preserving other extension policies. No delegate takeover or implicit
extension restriction occurs. Secure entry is not blanket screenshot prevention
or resistance to a compromised app/OS. [Secure entry](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry),
[keyboard restrictions](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/CustomKeyboard.html).

Numeric keyboard/oneTimeCode content type alone is not secure entry. OTP/Password
AutoFill, reveal toggles, hardware keyboards, accessibility and dictation require
real customer UX tests. Do not silently change OTP fields to password behavior.
The examples use a selected Activity and a legacy single-window UIKit application;
scene-based apps must route their explicitly selected scene lifecycle themselves.

## Privacy, defaults and validation limits

No content is accepted, even hashed/truncated: passwords, OTP/SMS/notifications,
clipboard, screen contents, account names/IDs, amounts, beneficiaries, credentials/
keys/tokens, arbitrary labels or raw touch/key streams. The SDK cannot detect a
host deliberately stuffing a secret into an opaque ref; integration review must
prohibit it. No release or development logging/serialization of these refs/facts.

No database, storage capability, spool, queue, backup, restore or hold API is
introduced. End/cancel/stop/replacement/dispose clear SDK-owned live facts under
the specified retry/tombstone exceptions. Expired unused owners are cleared at
the next attributable time-sampling call or process death; this is not timed
physical erasure. Caller-owned copies and crash dumps cannot be revoked. Java
immutable input objects may remain with the caller; dropping SDK references is
logical cleanup, not forensic zeroization. Existing deletion scope is unchanged.

Catalogue revision9,20 selectors, gate ABI/export set, telemetry and report-only
defaults are unchanged. There is no producer or server-admission protocol for
these facts. Any future transport/persistence requires separate consent, finite
queue/lifetime limits, exact native/transport/backend parents, catalogue admission
and retention/hold/erasure/restore review before activation.

The tests run real CycleMonitor publication -> native typed gate -> actual receipt
mutation, with shared independent C/Java boundary vectors and OS/clock seams.
NDK/C/JNI host tests are distinct from physical devices. Actual Apple SDK/Swift/
UIKit compilation and physical lifecycle/keyboard/AutoFill/UX must be reported
separately. No keylogger/OTP theft detection, device-health, transaction-proof,
efficacy or certification claim follows from a compile or local declaration.

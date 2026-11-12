# Explicit entry-point validation

This optional **host source integration** validates selected app entry points
before their adapted effects. Compile the source into the app, map each intended
handler to a reviewed literal rule, and keep the real local-policy gate directly
before the effect. Packing alone does not adapt handlers or authorize actions.
A `MATCH` is route classification. It is never caller/user authentication, a
reusable permit, replay protection, trusted device evidence or server authority.

The [source package](../runtime/entrypoint_validation/README.md) and
[actual reference apps](../runtime/tests/entrypoint_validation/README.md) show the
complete route -> boundary check -> real gate -> closed dispatch path. Unadapted
handlers and generic Binder/XPC traffic receive no interception or protection.

## Rules and supported effects

Compile 1..16 immutable routes with unique IDs 1..16, exact delivery/method,
scheme/authority/path, dispatch class and existing native operation/hash.
Malformed or duplicate configuration rejects the whole table. The policy hash
is a reviewed compiled expectation, never copied from runtime policy info.
C source rules/checks are 676/32 bytes, natural alignment 4; they are not additions
to the injected runtime ABI. Java owns defensive profile/table copies; Swift and
C use borrowed bounded input and owned finite readouts. Compiled configuration
is capped at 24 KiB; Java checks aggregate UTF16/primitive/pin payload before
copying the validated table, excluding VM object overhead. The fixed C/Swift
rule table is at most 16*676 bytes.

| Input | Accepted v1 grammar |
| --- | --- |
| URL | 1..1024 delivered ASCII bytes; absolute hierarchical URL; no whitespace, controls, high bytes, NUL, backslash or plus |
| Scheme | Exact lowercase `https`, app-compiled custom literal beginning `app.` (total <= 32), or provider-only `content` |
| Authority | Exact lowercase LDH domain <= 253; labels 1..63, at least 2; final label 2..63 ASCII letters; no IPs, trailing dot, userinfo, colon/port, IDNA/A-labels or wildcards |
| Path | Exact case-sensitive path 1..256; root or 1..16 nonempty segments <= 64 of letters/digits/`._~-`; no dot segments or trailing/repeated slash |
| Encoding | Every percent escape, raw Unicode, query or fragment (even empty) rejects; no decoding, repair, redirect, prefix/suffix matching or fallback |
| Method | Local OPEN for links, fixed QUERY_STATUS for provider, separately compiled parameter-free Binder demo method; no HTTP-method inference/override |

This is deliberately narrower than general URL syntax. It validates the
representation delivered by the platform; it cannot reconstruct a launch string
already transformed by an OS parser. Apple extraction uses bounded CFString
characters before copying ASCII bytes, rather than allocating an arbitrary
`absoluteString` byte array. Platform-delivery and PackageManager allocations
can occur before adapter bounds are checked; no total RSS/OOM containment is
claimed. C classification uses no heap, recursion, regex, I/O, DNS or network.

Public navigation may navigate again when repeated. Empty confirmation entry
may show a fixed screen only. Direct sensitive/replay-sensitive payment,
beneficiary, session, credential/OAuth/magic-link redemption and parameterized
business actions refuse. A separate deliberate authenticated host flow and
server-bound single-use challenge/atomic idempotent consume are required for
remote sensitive operations. RT20 references, local sequence numbers, native
cycle ordinals, a local nonce cache and previous ALLOW do not provide that protocol.

## Android invocation boundaries

`checkBinder` obtains the live transaction UID using getCallingUidOrThrow at the
actual synchronous method, before clearing identity, forwarding or scheduling.
The reference Service never acts from onStartCommand and never treats onBind as
authorization of later methods. Local/own UID calls, isolated/non-application
UIDs, other users, shared UIDs, missing/unknown callers and API failures refuse.
A worker/Messenger/oneway/forwarded invocation needs a separately reviewed adapter;
copying the UID to another thread cannot preserve the original transaction.

Restricted routes require a full current UID/package association (exactly one
package, matching ApplicationInfo.uid), 1..2 compiled SHA256 signing-history pins
via PackageManager, and the host's declared signature permission granted to that
caller. The helper checks the permission's owner, exact signature protection and
absence of additional flags. Pins explicitly accept platform-verified signer
history/rotation, not current-signer-only equality. No TOFU, signing inventory,
positive authorization cache or broad package query is used. These platform APIs
remain hookable in a compromised app/OS.

Activity restricted identity is conditional on API 35 ComponentCaller sharing.
Initial launch uses getCaller with its original Intent; onNewIntent uses that
callback's getCurrentCaller. Never pair a new Intent with an earlier caller.
Null/INVALID_UID remains unavailable; API 31..34 restricted paths are unsupported.
Public routes have no caller requirement and do not pretend to authenticate a
browser, accessibility tool, launcher or password manager.

The Intent envelope requires ACTION_VIEW/data, absent MIME/selector/ClipData,
no URI-grant flags, only optional DEFAULT/BROWSABLE categories and own explicit
target when present. Extras, referrers, sender text and PendingIntent creator
identity never authorize, and extras are never read or forwarded. Dispatch
receives only the compiled route. Explicit Intents bypassing resolver filters
still pass the same validation.

The provider implements only the fixed non-sensitive status query, through all
three query overloads. No SQL, projection/filter/Bundle interpretation, database,
file descriptor or asynchronous cursor exists. It obtains verified
getCallingPackage and the live transaction UID, then checks the same profile and
real native gate before returning its fixed cursor. Call/write/batch/file APIs
refuse. Cancellation is sampled before the gate and before publishing the result;
it cannot roll back an effect already committed.

Keep customer App Links filters, assetlinks association and user preferences.
Verified domains route to an app; they do not authenticate a link's author or
user, validate arguments or grant business/replay authorization.

## UIKit lifecycle and effects

The Swift reference app explicitly routes iOS 12 application URL/continuation
callbacks and iOS 13+ scene connection/openURLContexts/continuation callbacks.
A scene checks its own activation state/window identity; another active scene
does not substitute. Multiple or mixed deliveries reject together, without
choosing an unordered Set.first or partially dispatching. BrowsingWeb can also
represent Handoff; sourceApplication and associated domains are not caller proof.
Only public navigation/empty confirmation entry is supported on iOS.

A selected Activity/scene retains at most one **public route enum**, private
receipt tick and nonwrapping generation before foreground activation. Its pending slot retains
no URL/Intent, caller, permission or native decision. Platform/caller launch
objects and returned copies are outside SDK cleanup. Lifetime 30 s including sleep;
equality is accepted, +1 ns/missing/backward/overflowing clock clears/rejects.
Replacement, malformed delivery, pause/inactive/background/destroy/disconnect,
cancel/logout/scope change/dispose invalidates pending work. No saved-state or
disk restoration. Cleanup is logical/lazy at expiry, not forensic timed erasure.

On activation the host consumes that slot and calls the real native gate afresh
immediately before a closed public navigation. Restricted authorization never
defers. Active handlers mark reentrancy/consumption, require call/result OK and
known final ALLOW, then immediately perform one mapped effect without await,
callback, run-loop pumping or queuing. DENY/REPORT/BUSY/stale/missing/hash mismatch/
unknown/null/linkage fails with no effect. Existing runtime report-only defaults
are preserved; these examples deliberately execute no advisory REPORT branch.

A confirmation screen's button demonstrates a **new deliberate local demo action**
using the unchanged [RT20 context](host-context-contract.md) and real gate. It
neither authenticates a user nor commits a remote transaction. Context status
must be accepted before the next event/tuple is committed; failed events close
and disarm the flow while preserving the actual receipt count. No action or
context ages/retries are reset by URL routing. Binder threads never use this
main-thread context. After async work, discard prior results and authorize/gate
again at the actual effect boundary, with server checks on the server.

## Privacy and unchanged runtime contracts

The adapter emits **zero telemetry/cycle fields**, no producer, serializer,
persistent model, spool, storage capability, retention/hold/restore or deletion
scope change. Never log/export raw/truncated/hashed URLs or paths, extras,
package/UID/PID/signer/sourceApplication, arbitrary labels, account data, tokens,
amounts or business-body digests, including development logs and breadcrumbs.
Only finite local diagnostics remain with the host. No new runtime export, JNI
registration, RuntimeBridge class, catalogue/selector/schema, backend protocol,
key enrollment, dependency or DEX/PK02 budget is introduced.

UIKit/SDK compilation, unsigned packing, native/JVM OS-seam fixtures, Foundation
URL tests, simulator and physical-device/caller tests are distinct evidence.
No efficacy, fraud/theft detection, certification, installed caller proof or
customer-flow protection follows from an unsigned build. Real device/domain and
customer dispatch/UX acceptance require explicitly authorized facilities.

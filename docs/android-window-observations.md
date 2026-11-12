# Android received-touch observations

`overlay` is an **opt-in** Android builtin, using the host's public Activity/window callbacks on API 31+.
It counts MotionEvent obscuration flags received by this app. It does not identify another app, classify fake login
screens, prevent taps, or prove malware. Legitimate overlays and system windows are context too. Android can block
some obscured touches before delivery; such touches are outside this observer's coverage.

Introduced in schema 1, revision 6 and retained unchanged in canonical schema 1, revision 9,
**73 Android/52 iOS** outputs, catalogue
`2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d`. The ten rows generate both native cycle identities and compiled expectations from the same manifest.
All prior signer/service/inline/iOS rows are preserved exactly; the temporary selector is removed.

## Host setup

Build the [stub and compile-only bridge](../runtime/android/stub/README.md) with an API31+ SDK (SDK35 verified), ship
that exact stub.dex with matching native libraries, and preserve **all** `RuntimeBridge$*` nested classes with R8.
Use `compileOnly`, never bundle a second copy in host DEX. The existing `initialize(Context)` API is unchanged.

Call from the main thread in the attached Application's `onCreate`, after `super.onCreate()`:

```java
int initialized = RuntimeBridge.initialize(this);
if (initialized == RuntimeBridge.INITIALIZED || initialized == RuntimeBridge.ALREADY_INITIALIZED) {
    int started = RuntimeBridge.startWindowObservation(this);
    // Record/check the result in the host's own diagnostics.
}
```

An unpacked host using compileOnly can lack the class entirely; handle `LinkageError` around source integration as
shown in the stub guide. Native registration failure returns UNAVAILABLE, never an initialized or clean result.
Each process must opt in independently. Starting the adapter does not select the builtin: pack with `--checks overlay`
(the existing required identity group still applies). Selecting the group alone reports `never_started`.

`Application.ActivityLifecycleCallbacks.onActivityPostResumed` attaches each Activity window after the host's resume;
`onActivityPrePaused` detaches before pause. Stop/destroy provide additional cleanup. Multiple resumed activities each
have their own slot; rotating creates a new observation segment. No private ActivityThread lookup, permissions,
reflection, or host security flag changes are used by this adapter. `initialize` retains the supported Application;
the separate older signer fallback remains unchanged.

Activities already resumed before starting are not enumerated. Call `attachWindow(activity.getWindow())` on the main
thread for each currently active Activity. Call `attachWindow(dialog.getWindow())` after showing a Dialog, and
`detachWindow(window)` before its dismissal or its owner's pause. Manual windows are the host's responsibility;
they are not guessed from a global inventory. All adapter APIs require the main thread; worker calls return
WRONG_THREAD without changing state. Automatic lifecycle callbacks follow Android's main-thread contract.

`stopWindowObservation()` releases the observer under these rules:

- It disables every retained wrapper **before** releasing entries and unregistering lifecycle callbacks.
- It restores the previous callback only while the window still directly owns that wrapper; a later host callback remains untouched.
- An old wrapper retained inside a newer host chain remains an inert delegate, including after restart.
- Stop is idempotent and should be called during host teardown.
- Adapter construction, scheduling/removal and lifecycle window-lookup exceptions trigger error teardown without escaping the lifecycle callback. A queued task left by failed Handler removal stays inert and never reschedules.
- All wrappers are disabled and native window state is cleared even if unregister/removal/restoration fails. A duplicate attach that fails during restoration returns `JNI_ERROR`, with fault metadata, rather than a clean ownership-loss result.
- Exceptions from the delegated `Window.Callback` are forwarded unchanged.

The Application Context retained by `initialize` has process lifetime and is not cleared by stopping window observations.

| Return | Meaning |
|---|---|
| INITIALIZED (0) | Started/attached/detached/stopped successfully. |
| ALREADY_INITIALIZED (1) | Same Application already started, window already attached/absent, or already stopped. |
| INVALID_CONTEXT (2) | Null Application/window, or window without a host callback. |
| UNAVAILABLE (3) | Native methods absent or incompatible. |
| DIFFERENT_APPLICATION (4) | Application differs from initialized/active Application. |
| JNI_ERROR (5) | Registration, JNI, native epoch exhaustion, Handler or window operation failed. |
| WRONG_THREAD (6) | Main thread required. |
| UNSUPPORTED (7) | SDK below 31; no lifecycle observer installed. |
| NOT_INITIALIZED (8) | Supported Context missing, or attach/detach called without an active adapter. |
| WINDOW_LIMIT (9) | 32 window slots or session window-token space exhausted; explicit loss recorded. |
| OWNERSHIP_LOST (10) | Window callback was replaced or no longer owned; it is not overwritten. |

## Bounds, ownership and forwarding

There are 32 weak window/wrapper slots and a native 128-record FIFO. The slot value does **not** strongly retain a
window, its callback, or Activity. Each Window owns its wrapper and the wrapper owns its original callback, just as
the existing chain does. Destroy/pause/manual detach removes the slot. Collected windows are removed at the next
probe and reported lost. A single Handler task checks slots nominally every second while active, on lifecycle
resume, and a wrapper checks direct ownership before each received touch. A stalled main looper delays probes.

Public callback ownership and forwarding have these limits:

- Replacement and restoration between probes cannot be observed reliably through public APIs. A host wrapper above ADR counts as lost ownership even when it delegates to ADR.
- Reattach explicitly to begin a new segment after loss. A probe never reinstalls an observer over a newer host callback, and no output claims uninterrupted coverage.
- All 25 public `Window.Callback` methods, including defaults and ActionMode/search overloads, forward once with their original arguments, results and exceptions.
- Touch telemetry runs before the host's `dispatchTouchEvent`; it never consumes, blocks, modifies or redispatches the `MotionEvent`.

No event allocation or JNI reference is queued. Native ingress validates session, token, event kind and flag mask.
Old-session, malformed and unknown-window inputs are rejected and counted. Tokens are positive, ephemeral,
process/session-local integers; they are neither class/view names nor exported observations. Session tokens never
wrap. Only the two public obscuration bits cross JNI; other MotionEvent flags are masked out in Java.

The FIFO and interval rules are:

- Overflow drops the newest record and increments a saturating drop counter while retaining current window-state/loss accounting. Open/close/loss/fault records also occupy the 128 slots, so fewer than 128 touches may fit.
- Retained touches are exact; after drops they are lower bounds for that interval.
- Native writes and drains share a mutex, with no Java call under that lock.
- Each selected drain consumes records once in FIFO order and resets interval counters. Disabled selection does not drain; bounded events can accumulate drops.
- Repeated explicit collector calls each consume a new interval. Monitor integration drains once per selected pass and reuses the owned observations for reporting and plugins.

## Exact outputs

Every selected Android drain emits these ten identities, each once, source `window_callback`. Metadata values have
`ok` status because they successfully describe observer state, including failure. An `ok` metadata row is **not** a
clean security verdict. Off Android each row is `unsupported` with no value. iOS has no new group.

| Signal | Value type | Meaning |
|---|---|---|
| overlay.observer_state | string | Snapshot: `never_started`, `active`, `deactivated`, `error`, `unsupported`. |
| overlay.coverage | string | `loss_detected` if interval drops/losses/invalid inputs; otherwise `best_effort` only with active adapter and ≥1 current window, otherwise `unknown`. Never a continuity guarantee. |
| overlay.active_windows | integer | Snapshot: registered window tokens at drain, 0–32. |
| overlay.touch_events | integer | Retained dispatchTouchEvent records since previous selected drain, 0–128. Includes normal touches and all actions, not gestures. |
| overlay.obscured_touch_events | integer | Retained touches with FLAG_WINDOW_IS_OBSCURED (bit 1). |
| overlay.partially_obscured_touch_events | integer | Retained touches with FLAG_WINDOW_IS_PARTIALLY_OBSCURED (bit 2). A touch with both bits increments both. |
| overlay.dropped_events | integer | Dropped FIFO records in interval; saturates at INT64_MAX. |
| overlay.lost_windows | integer | Detected lost window ownership/collection or adapter/slot failures in interval; saturates. May include repeated failures, not unique windows. |
| overlay.invalid_events | integer | Rejected malformed, stale or unknown-token JNI inputs in interval; saturates. |
| overlay.interval_ms | integer | Monotonic time since previous selected drain; first drain is -1 (no prior boundary). Subsequent zero is a measured short interval. |

Cycle `complete` requires all ten expected rows to be returned. An error or inactive observer can still supply
complete metadata; completeness does not establish continuous touch coverage or a clean verdict.

The first delta includes retained events since native handoff initialization, including sessions before the first
selected drain, but its elapsed duration is unknown. Subsequent deltas include **all** session segments since the
previous drain, while availability and window count describe only the final snapshot. Start/stop do not erase
pending evidence; changing sessions cannot relabel a delta as current-only. No adapter, no active windows, no touches,
unsupported/error, or zero obscured counters cannot establish overlay absence. Consumers must keep metadata and
counters together; loss in a previous interval is not a promise of recovery or continuity in the next.

## Privacy and scope

Only coarse counts and finite availability strings are exported. No touch coordinates, timestamps per touch,
MotionEvent objects, text, keystrokes, views, screenshots, accounts, credentials, or arbitrary package inventory are
collected. Counts are observations rather than attestation. Optional blocking, screenshot API34, recording API35,
sensitive-input semantics, and iOS adapters are separate future tasks; no speculative listeners are installed here.

## Verified public contracts and tests

Primary API references checked for this implementation:
[ActivityLifecycleCallbacks](https://developer.android.com/reference/android/app/Application.ActivityLifecycleCallbacks),
[Window.Callback](https://developer.android.com/reference/android/view/Window.Callback),
[Window.getCallback/setCallback](https://developer.android.com/reference/android/view/Window),
[AOSP callback implementation](https://android.googlesource.com/platform/frameworks/base/+/7bee686ef7193eb0dcef28c6af46bc6f86c0aaa5/core/java/android/view/Window.java),
[MotionEvent flags](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_OBSCURED), and
[Looper.getMainLooper](https://developer.android.com/reference/android/os/Looper#getMainLooper()). The obscured flag
marks a delivered touch that passed through the obscured area; partial marks obscuration elsewhere in the window.
These flags provide no package attribution and cover only events actually delivered to the wrapped callback.

Run `runtime/tests/android/context_bridge/run.sh` for real JVM + compiled production JNI and native queue checks.
The JVM Android classes simulate the public framework boundary, not ART or a device. Production Java also compiles
against the real SDK35 android.jar and d8. See the [device fixture](../runtime/tests/android/context_bridge/device/README.md)
for repeatable actual-Android pause/resume, rotation, manual-window and legitimate-overlay checks. Hardware/ADB
execution, OEM behavior, minified host and device efficacy are not established by host or SDK compilation.

For SDK/NDK packaging integration, build the device fixture and stage four ABI runtime artifacts, then run from
`packer/` (use a Python environment with the locked packer test dependencies):

```sh
RASP_WINDOW_STUB=/tmp/rt10-stub/stub.dex \
RASP_WINDOW_HOST_APK=/tmp/rt10-device/host-unsigned.apk \
RASP_WINDOW_NATIVE_DIRECTORY=/tmp/rt10-stage-android/rasp_packer/android/resources/lib \
PYTHONPATH=src python -m pytest -q tests/rasp_packer/android/window_bridge_integration_test.py
```

These tests use the SDK-compiled host APK and the repository's real InsecureBankv2 AAB, the actual splitter and
post-pack verifier, and the built native libraries. They assert one bridge/nested wrapper definition and exact
native configuration bytes for all four ABIs. These fixture tests also cover the unknown capability path with no sidecars. Release validation additionally builds
an isolated installed wheel with exact revision 9 sidecars and exercises the public APK/AAB path and real post-pack
verifier, including mismatched artifacts and malformed staged-output controls. No installed Android behavior is implied by successful archive verification.


## How the monitor drains and reports window observations

The actual Android monitor selects builtins through `CycleMonitor.run` once per cycle. `run_checks` drains this
FIFO once only when `overlay` is selected. Its ten observations and interval/availability/loss fields remain together
inside the immutable cycle snapshot retained by both legacy and additive plugin callbacks. A later cycle or Context
cleanup cannot overwrite that retained interval. The real-JVM fixture exercises these production paths on the caller and an attached native worker, including a
second zero-touch drain and retained prior run/session/sequence metadata. No separate window-specific cycle header
or expectation append exists: both generated native headers use the one canonical manifest.

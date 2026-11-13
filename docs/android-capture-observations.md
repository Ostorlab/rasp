# Android screenshot and recording observations

The optional `screenshot` and `screen_recording` groups report public Android notifications.
Screenshot notifications belong to registered host Activities. Recording visibility has UID
scope and cannot identify which Activity was recorded. Neither observation prevents capture,
attributes a recorder, detects remote control, or proves malware. Legitimate screen sharing
has the same observation semantics.

| Source | Minimum Android API | Normal manifest permission | Public API |
|---|---|---|---|
| Screenshot | 34 | `android.permission.DETECT_SCREEN_CAPTURE` | `Activity.registerScreenCaptureCallback` / `unregisterScreenCaptureCallback` |
| Recording | 35 | `android.permission.DETECT_SCREEN_RECORDING` | `WindowManager.addScreenRecordingCallback` / `removeScreenRecordingCallback` |

Both permissions are install-time normal permissions; no dangerous-permission prompt is needed.
The packer adds each declaration only when its corresponding group is selected. Existing host
permissions are preserved. A selected declaration restricted by attributes such as maxSdkVersion
causes a packing error rather than a silent policy change. Selection does not raise the runtime's
minimum API31 or the host's target SDK. API31/33 expose unsupported data; API34 supports only the
screenshot source. Permission declaration, effective grant, registration and event receipt are
separate facts.

Native collection checks the [public device API-level function](https://developer.android.com/ndk/reference/group/apilevels)
before host opt-in or Java bridge binding, so early native monitor runs also report unsupported
sources on older OS versions. A failed availability query remains an error.

The [Android screenshot guide](https://developer.android.com/about/versions/14/features/screenshot-detection)
documents hardware-button screenshots on Android14, rather than ADB or instrumentation captures.
The callback arrives after the event, supplies no pixels and has no unique screenshot identifier.
Android shows a notice when it detects a screenshot; explain that notice in the host UI. The
[callback contract](https://developer.android.com/reference/android/app/Activity.ScreenCaptureCallback)
excludes windows using the host's FLAG_SECURE. This adapter does not alter that flag.

The [recording API](https://developer.android.com/reference/android/view/WindowManager#addScreenRecordingCallback(java.util.concurrent.Executor,%20java.util.function.Consumer%3Cjava.lang.Integer%3E))
returns an initial state and later reports visibility changes. Its documented scope includes
Activities owned by the registering process's UID. `visible` means that scope is visible in
recording; `not_visible` is a platform notification about that scope, not a device-wide absence
of recording, sharing or mirroring. Unspecified OEM paths and external cameras are outside its
guarantees. No MediaProjection session, accessibility service or capture contents are collected.

## Host integration

Build and ship the matching [stub and compile-only bridge](../runtime/android/stub/README.md)
using public SDK35 or newer and d8 minimum API31. Keep every `RuntimeBridge$*` nested class with
the documented shrinker rules. The host uses `compileOnly`; it must not bundle a second bridge.

After `super.onCreate()` in the attached Application, call on the main thread:

```java
try {
    int initialized = RuntimeBridge.initialize(this);
    if (initialized == RuntimeBridge.INITIALIZED || initialized == RuntimeBridge.ALREADY_INITIALIZED) {
        int capture = RuntimeBridge.startCaptureObservation(this, true, true);
        // Handle INITIALIZED, PARTIAL, UNSUPPORTED or the explicit integration error in host diagnostics.
    }
} catch (LinkageError unavailableInUnpackedBuild) {
    // An unpacked compileOnly host may have no bridge class.
}
```

Select `screenshot`, `screen_recording`, or both in the packer's check configuration. The two
booleans opt in to callbacks independently of group selection. Selecting a group without host
opt-in reports `never_started` on a supported OS. An unrequested source reports `not_requested`.
Both false is invalid. Changing options requires stop/start; repeating identical options for
the same Application is safe. Each process must initialize and opt in separately.

The capture adapter verifies the exact Application already retained by `initialize`. It adds
its own lifecycle listener to that Application and leaves the touch observer, Window.Callback
delegate chain, signing/service observations and private storage integration unchanged.

Automatic registration occurs after Activity resume and detaches before pause; stop/destroy
provide redundant cleanup. This is narrower than all visible Activities: a paused Activity may
remain visible in multi-window mode. Activities already resumed at startup are not enumerated.
For each such Activity, call `attachCaptureActivity(activity)` after opt-in, then
`detachCaptureActivity(activity)` before pause. The Activity must belong to the retained
Application. Dialogs and Window objects are not accepted as Activity registrations.

There are at most 32 weak Activity entries, including unresolved cleanup entries. Screenshots
use one callback per Activity. Recording uses one consumer, owned through the actual WindowManager
of an eligible resumed Activity. Other eligible Activities share that consumer; they do not
multiply UID transition counts. When the owner detaches, invalidate its state, remove its exact
consumer, and register through another eligible Activity if available. That handover counts as
a coverage gap. Rotating starts a new segment. No Activity identifiers are exported.

Call `stopCaptureObservation()` during host teardown. Old callbacks become inert before public
removal; already scheduled work cannot become evidence for a replacement registration. Failed
removal keeps bounded cleanup bookkeeping across stop/start. A screenshot Activity's failed
registration/removal leaves unrelated valid screenshot registrations usable, with explicit
partial/loss metadata. Global source/executor failures invalidate that source. Recording cleanup
failure invalidates the one recording consumer and prevents replacement until cleanup succeeds.
Irrecoverable removal failure can require process restart before that source can register again.

The monitor can sample between lifecycle primitives. Opening another screenshot registration
preserves partial/error availability until an explicit valid aggregate update confirms recovery.
Recording owner close immediately makes availability and visibility unknown, retaining internal
eligible memberships for transfer. The exported recording Activity count stays zero until a
fresh initial state establishes a healthy owner; that initial sample is not a transition.

All host methods, Activity access and registration/removal require the main thread. Callbacks use
a main-thread Executor; callback work updates fixed primitive counters and enums. No collection
or report transport runs on that thread. Public Android calls can involve Binder and cannot
promise a hard real-time bound. Registration never occurs during monitor collection.

| Return code | Meaning |
|---|---|
| INITIALIZED (0), ALREADY_INITIALIZED (1) | Successful operation or safe repeated start/absent detach/stop. |
| INVALID_CONTEXT (2), DIFFERENT_APPLICATION (4) | Null/invalid argument or wrong Application owner. |
| UNAVAILABLE (3), JNI_ERROR (5) | Bridge missing/incompatible, binding or adapter failure. |
| WRONG_THREAD (6), NOT_INITIALIZED (8) | Main thread or explicit initialized Application/session is required. |
| UNSUPPORTED (7) | Requested APIs are unsupported on this OS. |
| ACTIVITY_LIMIT (11) | Activity slots or attachment token space exhausted; loss is explicit. |
| PERMISSION_REQUIRED (12) | No requested supported source has the required declared/effective permission. |
| PARTIAL (13) | Requested sources have mixed availability. |
| INVALID_OPTIONS (14) | Neither source requested, or options changed without stopping. |

## Output and interval semantics

Each selected group emits its table below once per monitor cycle, in table order. Names and
sources are fixed. All values are scalar; integers are signed int64 and must retain compatible
cycle telemetry's typed-long precision in transport. The following are native semantics, not a new
wire envelope or delivery guarantee.

The [semantic examples](fixtures/android-capture-observations-v1.json) show unsupported data,
registered/stopped intervals and partial Activity teardown failure. They are synthetic examples.

| Group `screenshot`: signal | Source | Value kind | Exact value semantics |
|---|---|---|---|
| `capture.screenshot.observer_state` | `activity_screen_capture` | string | Availability enum below, final snapshot. |
| `capture.screenshot.permission` | `activity_screen_capture` | string | Permission enum below, last checked state. |
| `capture.screenshot.coverage` | `activity_screen_capture` | string | `unknown`, `best_effort`, `loss_detected`. |
| `capture.screenshot.active_activities` | `activity_screen_capture` | integer | Successful currently owned screenshot registrations, 0..32; never number of captured Activities. |
| `capture.screenshot.callback_events` | `activity_screen_capture` | integer | Accepted notifications in all segments since previous selected source drain. Not unique screenshots. |
| `capture.screenshot.lost_registrations` | `activity_screen_capture` | integer | Detected loss/failure counter for that interval. |
| `capture.screenshot.invalid_events` | `activity_screen_capture` | integer | Rejected native inputs for that interval. |
| `capture.screenshot.counter_overflow` | `activity_screen_capture` | boolean | A source interval counter saturated and an additional increment was attempted. |
| `capture.screenshot.interval_ms` | `activity_screen_capture` | integer | Checked monotonic drain-to-drain duration, or -1 when unavailable. |

| Group `screen_recording`: signal | Source | Value kind | Exact value semantics |
|---|---|---|---|
| `capture.recording.observer_state` | `window_manager_recording` | string | Availability enum below, final snapshot. |
| `capture.recording.permission` | `window_manager_recording` | string | Permission enum below, last checked state. |
| `capture.recording.coverage` | `window_manager_recording` | string | `unknown`, `best_effort`, `loss_detected`. |
| `capture.recording.active_activities` | `window_manager_recording` | integer | Eligible resumed host Activities while the shared recording registration is healthy, 0..32; zero on failure/no registration. Not recorded-Activity count. |
| `capture.recording.visibility` | `window_manager_recording` | string | `visible`, `not_visible`, `unknown`; UID visibility from current registration's initial/latest accepted state. Unknown after registration-owner/final eligible detach or registration failure. |
| `capture.recording.initial_samples` | `window_manager_recording` | integer | Successful initial state returns accepted since previous source drain. |
| `capture.recording.callback_events` | `window_manager_recording` | integer | Accepted later callbacks, including repeated identical states. Initial return is excluded. |
| `capture.recording.visibility_changes` | `window_manager_recording` | integer | Accepted later states differing from the current known state within the same registration. Reattachment's initial state is not a transition. |
| `capture.recording.lost_registrations` | `window_manager_recording` | integer | Detected loss/failure/handover counter for that interval. |
| `capture.recording.invalid_events` | `window_manager_recording` | integer | Rejected native inputs for that interval. |
| `capture.recording.counter_overflow` | `window_manager_recording` | boolean | Counter increment exceeded signed-int64 capacity in this interval. |
| `capture.recording.interval_ms` | `window_manager_recording` | integer | Checked monotonic drain-to-drain duration, or -1 when unavailable. |

Availability values are `never_started`, `not_requested`, `unsupported`, `no_application`,
`permission_absent`, `permission_denied`, `no_active_activity`, `active`, `partial`,
`registration_error`, `teardown_error`, `error`, `deactivated`. Active describes last successful
registration ownership, not synchronous fresh OS sampling. Permission values are `unknown`,
`not_applicable`, `absent`, `denied`, `granted`; only this app's manifest metadata is inspected,
bounded to 1024 permission entries. Unknown/query failure is distinct from denial.

On Android, the state/permission/coverage rows have `ok` status with finite availability strings,
including an explicit unsupported/error state. Their status is not a security verdict. Below a
source's minimum API, its remaining rows are `unsupported` with no value. Off Android every row
is unsupported with no value. On supported Android, counters and unknown visibility are reducer
facts with `ok` status, even after stop/failure. A failed data acquisition would be `error` with
no value. Non-ok observations never carry zero, false or another fabricated value.

Counters include accepted evidence from all segments since that source's previous selected
drain. Stop/start, rotation and registration failures do not discard pending evidence. Current
registration/visibility fields describe only the final snapshot. Recording initial samples
are separate from later callbacks and transitions; repeated same-state callbacks count as
callbacks, but not transitions. Screenshot callbacks are notifications, not unique screenshots.

There is no event FIFO. Direct counters saturate at INT64_MAX; an additional increment sets
`counter_overflow`, making affected counts lower bounds. `lost_registrations` counts detected
failures/gaps, not exact missed captures or unique Activities. `invalid_events` counts rejected
native ingress. Neither can quantify OS-suppressed callbacks or a stalled main looper.

Coverage is `loss_detected` for interval losses, rejected ingress or saturation; otherwise
`best_effort` only for a currently active source with live registration, and `unknown` otherwise.
No coverage value promises continuity or capture absence. The first interval, unavailable or
backwards monotonic clock has duration -1; measured zero stays zero. Two fresh valid samples
are required after clock failure. No per-event timestamp or recording duration is inferred.

Each selected source drains independently. A disabled source retains bounded deltas; draining
one source never consumes the other source or touch evidence. Both selected sources can use
one common cut. The actual shared CycleMonitor owns these values together with its immutable
cycle metadata; legacy/additive consumers must retain that same owner for asynchronous work.
Later cycles cannot overwrite earlier deltas. Structural cycle completeness does not mean
capture continuity: retain source availability/loss/overflow rows with the cycle.

No screenshot pixels, captured contents, view text, keystrokes, coordinates, accounts, arbitrary
package inventory, Activity names or recorder identity are retained or exported. Source values
are untrusted client observations, not cryptographic attestation.

## Verification and device limits

The native reducer and real-JVM fixture exercise the shipped Java/JNI/dispatcher/CycleMonitor,
with public Android boundaries simulated. They cover version and permission availability,
initial states, duplicate callbacks, partial failures, inert callbacks, bounded quarantine,
ownership transfer and independent immutable interval retention. Public SDK compilation checks
API signatures and d8 output; these checks do not establish Android/ART or OEM callback efficacy.

Run [the context bridge runner](../runtime/tests/android/context_bridge/run.sh) and follow the
[harmless device fixture](../runtime/tests/android/context_bridge/device/README.md). Physical
API31/33/34/35+ devices, multi-window behavior and minified packed hosts require actual results.
Use hardware screenshot buttons as a positive screenshot check, and explicit user consent for
system screen recording. Do not use an ADB screenshot as proof that the callback works.

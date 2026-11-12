# iOS screenshots and selected-scene capture observations

The optional `screenshot` and `screen_recording` groups require explicit host source integration.
Packing alone does not install UIKit observers. Both groups remain disabled by default;
identity-only defaults, iOS 12.0 / arm64 and Android API31 support are preserved.

A notification or capture flag does not prevent capture, identify a recorder, attribute another
app's recording, detect remote control, prove malware or attest a device. Legitimate screen
sharing produces the same observations. No screen image, screenshot file, view text, URL,
scene title, account identifier, scene session identifier or object address is collected.

## Public APIs and scope

| Source | Public API / minimum iOS | Observation boundary |
|---|---|---|
| Selected scene | `UIWindowScene` / 13; `traitCollection.sceneCaptureState`, `UITraitSceneCaptureState`, `registerForTraitChanges:withHandler:` / 17 | Exactly the host-selected scene; active, inactive and unspecified stay distinct. Registration is followed by an explicit initial read. |
| Legacy display | `UIScreen.isCaptured`, `UIScreenCapturedDidChangeNotification` / 11 | Used only on iOS 12–16, through selected scene.screen or an explicit non-scene UIWindow.screen. This is display scope, not scene-specific capture. |
| Screenshot | `UIApplicationUserDidTakeScreenshotNotification` / 7 | Application notification after capture, without userInfo, scene/window attribution, pixels or unique screenshot ID. Delivered callbacks are not unique screenshots. |

Apple documents scene capture in the [trait collection](https://developer.apple.com/documentation/uikit/uitraitcollection/scenecapturestate),
[trait registration protocol](https://developer.apple.com/documentation/uikit/uitraitchangeobservable-7qoet),
and [capture enum](https://developer.apple.com/documentation/uikit/uiscenecapturestate).
The [window scene](https://developer.apple.com/documentation/uikit/uiwindowscene) supplies the
actual scene traits and screen. The [screen flag](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured)
means recording, mirroring, AirPlay or other screen cloning; its current metadata deprecates it
in iOS 27, recommending the scene trait. The [screen notification](https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification)
has the changed screen as object and main-actor delivery. The [screenshot notification](https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification)
is after capture and has no userInfo. These APIs need no capture permission, entitlement or
usage-description prompt. Unspecified capture paths and external cameras are outside their guarantees.

Modern iOS 17+ requires an actual selected UIWindowScene for capture state. A true non-scene
host on those versions has no capture-state path in this integration; screenshot observation
can work independently. On iOS 13–16, a legacy UIWindow is accepted only when its windowScene
is nil. No connectedScenes enumeration, implicit first/key scene or main-screen fallback occurs.
Simulators, extensions, Catalyst and non-iOS targets are unsupported. Simulator compilation or
synthetic notifications do not establish physical-device efficacy.

## Host API

Use the matching framework's `Headers/ios_capture.h` (`#include <RaspRuntime/ios_capture.h>`).
It declares exactly six fixed C exports; the framework carries its own libc++, so the boundary
contains fixed-width integers and borrowed opaque pointers, never C++ strings or containers.
Call every function on main after normal UIApplication initialization. A pointer must be a live
object of the documented UIKit type; this API cannot validate an arbitrary forged address.

```objective-c
int32_t started = rasp_ios_capture_start(RASP_IOS_CAPTURE_SCREENSHOTS | RASP_IOS_CAPTURE_RECORDING);
if (started == RASP_IOS_CAPTURE_OK || started == RASP_IOS_CAPTURE_NO_CHANGE) {
  if (__builtin_available(iOS 13.0, *)) {
    // Obtain the scene from the host's own scene delegate or window, not an enumeration.
    int32_t selected = rasp_ios_capture_select_scene((__bridge void *)hostWindowScene);
    // Surface the status through the host's development diagnostics as appropriate.
    (void)selected;
  } else {
    (void)rasp_ios_capture_select_legacy_window((__bridge void *)hostWindow);
  }
}
```

The host additionally selects `screenshot`, `screen_recording`, or both in the packer's check
configuration. Source opt-in and group selection are independent. Without host integration,
a selected supported group reports never_started and measured state remains error/absent.
A host may use the C symbols through dlsym for an unpacked build; absence is integration absent,
not success. Do not install another runtime or pretend an absent function succeeded.

| Function | Ownership behavior |
|---|---|
| `rasp_ios_capture_start(options)` | Nonzero screenshot/recording bit set; identical active options are idempotent, changed options require stop/start. |
| `rasp_ios_capture_select_scene(scene)` | Replaces the one weak selected scene after invalidating/removing old ownership. Same selection is NO_CHANGE, not a refresh. |
| `rasp_ios_capture_select_legacy_window(window)` | Explicit non-scene display fallback on iOS 12–16 only. |
| `rasp_ios_capture_clear_selection(object)` | Clears only the identical current selection. Another scene's teardown cannot clear a newer selection. |
| `rasp_ios_capture_refresh()` | Confirms current activity/selection and reads state on main; no selection/discovery or drain. |
| `rasp_ios_capture_stop()` | Makes callbacks inert before removal; pending deltas survive stop/start. |

Return codes are defined in the header: OK=0, NO_CHANGE=1, INVALID_ARGUMENT=2,
WRONG_THREAD=3, NOT_STARTED=4, OPTIONS_CONFLICT=5, UNSUPPORTED_TARGET_OR_MODE=6,
NOT_REQUESTED=7, REGISTRATION_ERROR=8, CLEANUP_ERROR=9, EXHAUSTED=10, UNAVAILABLE=11.
Reentrant host entries during an in-progress operation return UNAVAILABLE without replacing ownership.
Successful operations confirm integration work, not a capture state or future delivery guarantee.
A setup failure in one source preserves the other source. Shared process lifecycle/timer failures
invalidate both. Repeating start is not a retry of a failed registration; stop/start is explicit.

## Ownership, lifecycle and freshness

The adapter keeps one weak scene/window, a weak fallback screen, and fixed token slots: at most
nine NotificationCenter observers, one trait token and one timer. No scene map grows over time.
UIKit work, weak loads/releases and registration/removal stay on main. Wrong-thread host calls
return without UIKit mutation. Blocks never retain a scene; captured primitive epochs reject
old callbacks. Cleanup failures retain only inert fixed slots, blocking replacement until cleanup
succeeds. Persistent failure or exhausted non-wrapping epoch space can require process restart.
Foundation exception containment is scoped to this adapter translation unit, with no global C++
exception change. There is no invalid-pointer, OOM, arbitrary exception or crash containment promise.

Only a foreground-active selected scene is eligible. On deactivation/background the current
value is invalidated before removal; resume creates a fresh registration/initial sample. A
selected scene disconnect clears selection; reconnect needs explicit selection. Nonselected
scene notifications have no effect. Legacy windows additionally need an active application and
visible window. The host should clear/select/refresh when it changes legacy windows/screens.
The adapter also rechecks screen association on refresh. Paused but visible scenes/windows are
outside this narrower scope; inactivity never becomes a measured negative capture flag.

A main-runloop timer rechecks ownership/activity and samples every 5 seconds. Timer and explicit
refresh reads count as resamples, not callback events. A sample/heartbeat age at most 15,000 ms
is fresh; 15,001 ms is stale. Missing/backwards clocks produce clock_unavailable. Recovery needs
a fresh main-thread sample/heartbeat; a worker clock recovering alone does not restore old evidence.
The worker never calls UIKit, dispatches to main or waits for a main-thread response.

Screenshot blocks do no UIKit work and can accept primitive notifications on the posting thread;
Apple's screenshot documentation does not promise a delivery thread. Last main-confirmed active
application ownership bounds acceptance. Lifecycle/trait handlers reject off-main ingress using
primitives only. No filesystem/network/content-copy work occurs in callbacks. There is no observer
installed by swizzling, the launch constructor or silent scene discovery.

## Scalar output schema

Each selected group emits every row below exactly once per actual measurement cycle. All
integers are signed int64; transport must preserve typed-long precision. Availability/coverage
strings have OK status when the reducer fact was obtained, including an unavailable reason.
That status is not a platform measurement or security verdict. Unsupported target gives every
row unsupported with no value. Failed snapshot acquisition gives every selected row error.

Screenshot rows all use source `uiapplication_screenshot`:

| Signal suffix after `capture.screenshot.` | Kind | Meaning |
|---|---|---|
| observer_state | string | Effective registration/activity/freshness reason |
| coverage | string | unknown, best_effort or loss_detected |
| session_epoch | integer | Local process opt-in ordinal; 0 before start |
| callback_events | integer | Accepted notifications since selected source drain |
| ignored_events | integer | Rejected stale/inactive/invalid ingress |
| loss_events | integer | Detected gaps/failures, not missed screenshot count |
| counter_overflow | Boolean | Additional increment beyond INT64_MAX attempted |
| interval_ms | integer | Selected drain interval, -1 unavailable |
| heartbeat_age_ms | integer | Last main ownership confirmation age, -1 unavailable |

Capture rows use source `uikit_capture_observer` except where stated:

| Signal suffix after `capture.recording.` | Kind | Meaning |
|---|---|---|
| observer_state | string | Effective selected-path availability |
| coverage | string | unknown, best_effort or loss_detected |
| scope | string | none, selected_scene or selected_screen |
| scene_availability | string | Source uikit_scene_trait; unsupported below iOS 17 |
| state | string | Source uikit_scene_trait; fresh active/inactive/unspecified only |
| screen_availability | string | Source uikit_screen_capture; not_selected on modern scene path |
| state | Boolean | Source uikit_screen_capture; fresh selected screen.isCaptured only |
| selection_epoch | integer | Process-local registration segment; no scene identifier |
| sample_age_ms | integer | Last selected-path sample age, -1 unavailable |
| initial_samples | integer | Initial/resume/selection reads, not transitions |
| callback_events | integer | Accepted actual callbacks including duplicates |
| state_changes | integer | Known-state changes inside a generation; no initial/unspecified/gap transition |
| resamples | integer | Timer/explicit refresh reads |
| ignored_events | integer | Rejected old-object/epoch/off-main/invalid ingress |
| loss_events | integer | Detected gaps/failures or resample-discovered changes |
| counter_overflow | Boolean | Saturated interval counter incremented again |
| interval_ms | integer | Selected source interval, -1 unavailable |

Availability reasons are unsupported, never_started, not_requested, exhausted, teardown_error,
registration_error, error, deactivated, no_selection, disconnected, owner_gone, inactive,
clock_unavailable, stale, unavailable_state, not_selected and active. Before host start,
never_started wins over unset request flags. Unsupported API remains unsupported independently.
Unselected supported APIs, missing integration, failures, inactivity and stale state have no
measured value (error status). Fresh unspecified is an actual enum value with OK status, but
unavailable_state and unknown coverage; it is never inactive. Non-OK rows contain no false/zero.

There is no event FIFO or per-event payload. Two fixed reducers coalesce notifications into
counters and keep only latest current state. Counters saturate at INT64_MAX and set overflow;
values then are lower bounds. Detected gaps cannot quantify OS-suppressed events or main stalls.
Callbacks, initial samples and resamples stay distinct. A resample-discovered known-state change
counts a state change and a gap; no duration or number of missed transitions is inferred.

A selected source drains once; a disabled source does not drain/reset or consume another enabled
source's path. Pending bounded deltas survive stop/start. First/invalid/backwards drain intervals
are -1; two fresh ordered ticks restore interval measurement, and equal ticks are measured zero.
Current state describes the final cut while counts include every segment since that source's
last selected drain. Zero notifications never means absence of capture.

The [measurement cycle contract](measurement-cycle-contract.md) owns all these observations with
metadata in the same immutable snapshot. Legacy and additive callbacks retain that same owner.
Later drains, cleanup and Context destruction cannot alter an earlier run. Structural cycle
completeness is independent of observer continuity and source loss; retain the status/loss/age
rows. RT07 retention drops invalidate cycle completeness and are separate from reducer loss.
The [semantic fixture](fixtures/ios-capture-observations-v1.json) and canonical manifest define
all 26 additional identities in schema 1 / revision 9 (73 Android / 52 iOS).
The owned [local decision report](local-decisions-contract.md) explicitly adopts these 26 as
unknown/unregistered, with unknown severity and no predicate count. Disabled/config-unknown,
missing/duplicate and non-OK eligibility takes precedence; capture evidence does not become
a threat/benign predicate. All earlier 99 rules and the 289 assessment-vector bytes are preserved.

## Verification

Portable reducer/dispatcher/cycle tests validate generation interleavings, explicit absent state,
freshness, counters, races and immutable ownership. They do not validate UIKit behavior.
The release/debug iOS CI compiles the actual ObjC++ adapter at deployment floor 12.0, checks
exact exports and public header, links C/ObjC/C++/ObjC++ hosts using the real SDK, and builds the
[harmless host fixture](../runtime/tests/ios/capture/README.md). Physical device execution and
callback efficacy must be recorded separately as not_run until actually performed. No Linux
UIKit stub is treated as an Apple run.

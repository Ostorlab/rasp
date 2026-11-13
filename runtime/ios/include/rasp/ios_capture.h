/// Optional iOS capture integration. Only these six fixed C functions are exported.
#pragma once
#include <stdint.h>

#ifdef __GNUC__
#define RASP_IOS_CAPTURE_API __attribute__((visibility("default")))
#else
#define RASP_IOS_CAPTURE_API
#endif
#ifdef __APPLE__
#define RASP_IOS_CAPTURE_HOST __attribute__((availability(ios_app_extension, unavailable)))
#else
#define RASP_IOS_CAPTURE_HOST
#endif
#ifdef __cplusplus
extern "C" {
#endif

/// Screenshot opt-in bit; check-group configuration is a separate selection.
#define RASP_IOS_CAPTURE_SCREENSHOTS UINT32_C(1)
/// Capture-state opt-in bit for selected-scene traits or supported display fallback.
#define RASP_IOS_CAPTURE_RECORDING UINT32_C(2)
/// Host operation accepted; not a capture or continuity verdict.
#define RASP_IOS_CAPTURE_OK INT32_C(0)
/// Repeated start/select leaves ownership unchanged without retrying setup; never a health verdict.
#define RASP_IOS_CAPTURE_NO_CHANGE INT32_C(1)
/// Null/wrong type, empty or unknown options.
#define RASP_IOS_CAPTURE_INVALID_ARGUMENT INT32_C(2)
/// UIKit ownership requires the main thread; no mutation occurred.
#define RASP_IOS_CAPTURE_WRONG_THREAD INT32_C(3)
/// Explicit opt-in has not started.
#define RASP_IOS_CAPTURE_NOT_STARTED INT32_C(4)
/// Stop before changing the requested source set.
#define RASP_IOS_CAPTURE_OPTIONS_CONFLICT INT32_C(5)
/// Unsupported target or API mode; no automatic fallback.
#define RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE INT32_C(6)
/// Capture-state source was not requested by the host.
#define RASP_IOS_CAPTURE_NOT_REQUESTED INT32_C(7)
/// Observer setup failed; per-source observations retain the exact limitation.
#define RASP_IOS_CAPTURE_REGISTRATION_ERROR INT32_C(8)
/// An inert fixed cleanup slot still requires removal; replacement is blocked.
#define RASP_IOS_CAPTURE_CLEANUP_ERROR INT32_C(9)
/// Non-wrapping generation space is exhausted; process restart required.
#define RASP_IOS_CAPTURE_EXHAUSTED INT32_C(10)
/// Coordinator or integration is unavailable.
#define RASP_IOS_CAPTURE_UNAVAILABLE INT32_C(11)

/// Starts explicit host opt-in on main after UIApplication initialization; identical active options return NO_CHANGE.
/// Repeated start does not repair setup. After registration failure, complete stop successfully before starting again.
/// @param options Nonzero combination of the two opt-in bits; other bits are invalid.
/// @return Status above. Missing integration never means a negative capture observation.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_start(uint32_t options);
/// Selects one weak UIWindowScene on main (iOS 13+); iOS 17+ uses its scene-capture trait.
/// Same selection returns NO_CHANGE without refresh or registration retry.
/// After registration failure, successfully clear that same live object before selecting again, or stop/start.
/// @param window_scene Borrowed live UIWindowScene, bridged to void*; never retained by the worker.
/// @return Status above; a valid inactive selection does not claim an active observer.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_select_scene(void* window_scene);
/// Selects one weak non-scene UIWindow for display-scoped fallback, only on iOS 12–16.
/// Same selection returns NO_CHANGE without refresh or retry; failed registration needs successful clear/reselect or
/// stop/start.
/// @param window Borrowed live UIWindow; on iOS 13+ its windowScene must be nil.
/// @return Status above. Modern non-scene hosts have no capture-state fallback here.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_select_legacy_window(void* window);
/// Clears only the identical currently selected object on main, before host teardown.
/// Removes ownership only after successful cleanup; handle CLEANUP_ERROR before replacement and retry the same clear or
/// stop.
/// @param selected_object Borrowed live scene/window; unrelated objects return NO_CHANGE, null is invalid.
/// @return Status above; pending deltas survive cleanup.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_clear_selection(void* selected_object);
/// Rechecks actual selection/activity and samples on main without selecting or draining.
/// @return Status above; no automatic scene discovery or synchronous main dispatch.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_refresh(void);
/// Invalidates current session before exact observer/timer removal on main; repeated clean stop is safe.
/// @return OK or NO_CHANGE after cleanup completes; handle CLEANUP_ERROR before restarting. Inert failed slots stay
/// bounded.
RASP_IOS_CAPTURE_API RASP_IOS_CAPTURE_HOST int32_t rasp_ios_capture_stop(void);

#ifdef __cplusplus
}
#endif

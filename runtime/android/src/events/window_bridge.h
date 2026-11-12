/// Registration of the opt-in public Java adapter's primitive-only native boundary.
#pragma once

#include <jni.h>

namespace rasp::android::events {

/// Registers all adapter methods separately from Context and stub registration; clears JNI errors.
/// @param env JNI_OnLoad's environment; never retained.
/// @return False on any lookup/registration failure, with native availability marked error.
[[nodiscard]] bool register_window_bridge(JNIEnv* env);

}  // namespace rasp::android::events

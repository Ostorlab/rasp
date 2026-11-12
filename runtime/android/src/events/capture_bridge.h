/// Public capture adapter JNI registration, separate from touch/Application availability.
#pragma once
#include <jni.h>
namespace rasp::android::events {
/// Binds primitive capture ingress and reads the public platform API level without installing callbacks.
/// @param env JNI loading thread environment, never retained.
/// @return Successful complete binding; false clears JNI exceptions and marks availability error.
[[nodiscard]] bool register_capture_bridge(JNIEnv* env);
}  // namespace rasp::android::events

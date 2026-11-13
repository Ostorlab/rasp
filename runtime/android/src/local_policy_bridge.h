/// Optional dynamically registered Java facade; no Application or capture attachment needed.
#pragma once
#include <jni.h>
namespace rasp::android {
/// Bind both fixed primitive methods; partial/failed registration never becomes success.
[[nodiscard]] bool register_local_policy_bridge(JNIEnv* env);
}  // namespace rasp::android

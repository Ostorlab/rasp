/// Test-only capture production-dispatch probes.
#pragma once
#include <jni.h>
/// Registers capture probes in the real JVM fixture.
/// @param env Loading environment.
/// @return Whether probe registration succeeded.
[[nodiscard]] bool register_capture_test(JNIEnv* env);

/// Test-only registration shared with the real-JVM entry point; never shipped.
#pragma once

#include <jni.h>

/// Registers the actual dispatcher probes after production JNI registration.
/// @param env The current JVM environment.
/// @return Whether the test probe registration succeeded.
[[nodiscard]] bool register_window_test(JNIEnv* env);

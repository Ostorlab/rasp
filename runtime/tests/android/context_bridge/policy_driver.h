/// Test-only registration for OS-boundary fixture publication, never shipped in librasp.
#pragma once
#include <jni.h>
/// Register fixture input methods; production gate/evaluator remain unchanged.
[[nodiscard]] bool register_policy_test(JNIEnv* env);

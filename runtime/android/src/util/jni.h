/// Calling Java from the runtime's own thread, shared by the checks that read the app's Java side.

#pragma once

#include <jni.h>

namespace rasp::android::util {

/// The JNI environment of the calling thread, which is attached to the app's Java VM the first time and stays attached:
/// the runtime's thread never ends, so it never has to detach.
///
/// @return The environment, or null when there is no Java VM or the thread can't be attached.
[[nodiscard]] JNIEnv* attached_env();

/// Whether the last JNI call threw. The exception is cleared, so it never reaches the app.
///
/// @param env The thread's JNI environment.
/// @return `true` when the call threw.
[[nodiscard]] bool threw(JNIEnv* env);

}  // namespace rasp::android::util

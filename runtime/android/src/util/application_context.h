/// Explicit Application Context supplied by the host, retained for the lifetime of the monitor's process.

#pragma once

#include <cstdint>
#include <expected>
#include <jni.h>

namespace rasp::android::util {

/// Initialization results, matching RuntimeBridge's public constants.
enum class ContextInitResult : std::uint8_t {
  kInitialized = 0,
  kAlreadyInitialized = 1,
  kInvalidContext = 2,
  kUnavailable = 3,
  kDifferentApplication = 4,
  kJniError = 5,
};

/// Normalizes an attached Context through getApplicationContext and retains only an Application global reference.
/// Concurrent calls never replace the first Application and never wait for the monitor. JNI failures are cleared.
/// @param env The calling thread's environment, never retained.
/// @param context A borrowed Context, or null; neither it nor an Activity is retained.
/// @return The initialization result; failures do not change an existing reference.
[[nodiscard]] ContextInitResult initialize_application_context(JNIEnv* env, jobject context);

/// Obtains an owned local reference on the calling thread; the global Application is never reset or deleted.
/// @param env The calling thread's environment, never retained.
/// @return A local reference the caller must delete, null when not initialized, or kJniError on JNI failure (cleared).
[[nodiscard]] std::expected<jobject, ContextInitResult> application_context(JNIEnv* env);

/// Registers RuntimeBridge's native method in the loading class loader; failure leaves no pending exception.
/// @param env JNI_OnLoad's environment.
/// @return Whether registration succeeded; failure must not prevent the existing loader from registering.
[[nodiscard]] bool register_context_bridge(JNIEnv* env);

}  // namespace rasp::android::util

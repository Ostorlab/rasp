/// PackageManager signer collection shared by the monitor and integration verification.

#pragma once

#include <cstdint>
#include <jni.h>
#include <optional>
#include <vector>

namespace rasp::android::util {

/// Reads the first APK content signer's DER bytes, preserving the existing signer selection policy.
/// Prefers explicit Context, otherwise tries the existing best-effort Application lookup for at most five seconds.
/// This potentially waiting function belongs on the monitor thread, never the UI thread.
/// @param env The calling thread's environment, or null if attaching failed. Never retained.
/// @return Certificate bytes, or nothing on unavailability, lookup/ref failure or cleared Java exception.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_package_manager_certificate(JNIEnv* env);

}  // namespace rasp::android::util

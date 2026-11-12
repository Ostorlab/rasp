/// JNI binding for opt-in capture registration and bounded primitive-only callback ingress.
#include "events/capture_bridge.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <jni.h>
#include <jni_md.h>

#include "events/capture_events.h"
#include "util/application_context.h"
#include "util/jni.h"

namespace rasp::android::events {
namespace {
/// Partial binding cannot enable an adapter before its entire boundary is available.
[[nodiscard]] std::atomic<bool>& capture_binding() {
  static constinit std::atomic<bool> bound{false};
  return bound;
}
/// Validates exact retained Application ownership before starting a fresh callback epoch.
jlong start(JNIEnv* env, jclass /*unused*/, jobject application, jboolean screenshots, jboolean recording) {
  if (!capture_binding().load(std::memory_order_acquire)) {
    return -3;
  }
  const auto context = util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    capture_events().unavailable(CaptureState::kNoApplication);
    return context.has_value() ? -8 : -5;
  }
  const bool same = env->IsSameObject(*context, application) == JNI_TRUE;
  const bool failed = util::threw(env);
  env->DeleteLocalRef(*context);
  if (failed || !same) {
    return failed ? -5 : -4;
  }
  const auto epoch = capture_events().start(screenshots == JNI_TRUE, recording == JNI_TRUE);
  return epoch > 0 ? static_cast<jlong>(epoch) : -5;
}
/// Invalidates the current callback generation before Java attempts public teardown.
void stop(JNIEnv* /*unused*/, jclass /*unused*/, jlong epoch) {
  capture_events().stop(static_cast<std::int64_t>(epoch));
}
/// Validates untrusted primitive ingress without keeping any Java object.
jboolean event(JNIEnv* /*unused*/, jclass /*unused*/, jlong epoch, jint source, const jint token, jint kind,
               const jint value) {
  const auto validated = kind >= 1 && kind <= 7 ? static_cast<CaptureKind>(kind) : CaptureKind::kInvalid;
  return capture_events().push(static_cast<std::int64_t>(epoch), source, token, validated, value) ? JNI_TRUE
                                                                                                  : JNI_FALSE;
}
}  // namespace
bool register_capture_bridge(JNIEnv* env) {
  capture_binding().store(false, std::memory_order_release);
  jclass version = env->FindClass("android/os/Build$VERSION");
  bool failed = util::threw(env);
  jfieldID field = version != nullptr && !failed ? env->GetStaticFieldID(version, "SDK_INT", "I") : nullptr;
  failed = util::threw(env) || failed;
  const int sdk = field != nullptr && !failed ? env->GetStaticIntField(version, field) : 0;
  failed = util::threw(env) || failed;
  if (version != nullptr) {
    env->DeleteLocalRef(version);
  }
  capture_events().platform(sdk);
  jclass bridge = env->FindClass("co/ostorlab/rasp/RuntimeBridge");
  failed = util::threw(env) || failed;
  auto start_name = std::to_array("startCaptureNative");
  auto start_signature = std::to_array("(Landroid/app/Application;ZZ)J");
  auto stop_name = std::to_array("stopCaptureNative");
  auto stop_signature = std::to_array("(J)V");
  auto event_name = std::to_array("captureEventNative");
  auto event_signature = std::to_array("(JIIII)Z");
  const std::array methods{
      JNINativeMethod{
          .name = start_name.data(),
          .signature = start_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&start),
      },
      JNINativeMethod{
          .name = stop_name.data(),
          .signature = stop_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&stop),
      },
      JNINativeMethod{
          .name = event_name.data(),
          .signature = event_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&event),
      },
  };
  if (!failed && bridge != nullptr) {
    const auto result = env->RegisterNatives(bridge, methods.data(), static_cast<jint>(methods.size()));
    failed = util::threw(env) || result != JNI_OK;
  } else {
    failed = true;
  }
  if (bridge != nullptr) {
    env->DeleteLocalRef(bridge);
  }
  if (failed) {
    capture_events().unavailable(CaptureState::kError);
  }
  capture_binding().store(!failed, std::memory_order_release);
  return !failed;
}
}  // namespace rasp::android::events

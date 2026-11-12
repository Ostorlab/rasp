#include "events/window_bridge.h"

#include <array>
#include <cstdint>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif

#include "events/window_events.h"
#include "util/application_context.h"
#include "util/jni.h"

namespace rasp::android::events {
namespace {

jlong start_native(JNIEnv* env, jclass /*bridge*/, jobject application) {
  const auto context = util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    window_events().unavailable(ObserverState::kError);
    return context.has_value() ? -8 : -5;
  }
  const jboolean same = env->IsSameObject(*context, application);
  const bool failed = util::threw(env);
  env->DeleteLocalRef(*context);
  if (failed || same != JNI_TRUE) {
    window_events().unavailable(ObserverState::kError);
    return failed ? -5 : -4;
  }
  const std::int64_t session = window_events().start();
  return session > 0 ? static_cast<jlong>(session) : -5;
}

void stop_native(JNIEnv* /*env*/, jclass /*bridge*/, jlong session, jint reason) {
  if (reason == 0 || reason == 1) {
    window_events().stop(static_cast<std::int64_t>(session),
                         reason == 0 ? ObserverState::kDeactivated : ObserverState::kError);
  } else if (reason == 2 && session == 0) {
    window_events().unavailable(ObserverState::kUnsupported);
  } else {
    static_cast<void>(window_events().push(static_cast<std::int64_t>(session), 0, 0, 0));
  }
}

jboolean event_native(JNIEnv* /*env*/, jclass /*bridge*/, jlong session, jint window, jint kind, jint flags) {
  return window_events().push(static_cast<std::int64_t>(session), window, kind, flags) ? JNI_TRUE : JNI_FALSE;
}

}  // namespace

bool register_window_bridge(JNIEnv* env) {
  jclass bridge = env->FindClass("co/ostorlab/rasp/RuntimeBridge");
  const bool lookup_failed = util::threw(env);
  if (lookup_failed || bridge == nullptr) {
    if (bridge != nullptr) {
      env->DeleteLocalRef(bridge);
    }
    window_events().unavailable(ObserverState::kError);
    return false;
  }
  auto start_name = std::to_array("startWindowsNative");
  auto start_signature = std::to_array("(Landroid/app/Application;)J");
  auto stop_name = std::to_array("stopWindowsNative");
  auto stop_signature = std::to_array("(JI)V");
  auto event_name = std::to_array("windowEventNative");
  auto event_signature = std::to_array("(JIII)Z");
  const std::array methods{
      JNINativeMethod{
          .name = start_name.data(),
          .signature = start_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&start_native),
      },
      JNINativeMethod{
          .name = stop_name.data(),
          .signature = stop_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&stop_native),
      },
      JNINativeMethod{
          .name = event_name.data(),
          .signature = event_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&event_native),
      },
  };
  const jint result = env->RegisterNatives(bridge, methods.data(), static_cast<jint>(methods.size()));
  const bool failed = util::threw(env);
  env->DeleteLocalRef(bridge);
  if (result != JNI_OK || failed) {
    window_events().unavailable(ObserverState::kError);
    return false;
  }
  return true;
}

}  // namespace rasp::android::events

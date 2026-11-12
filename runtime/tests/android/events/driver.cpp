#include "android/events/driver.h"

/// Test-only adapter probes: production dispatch/registration, not a mirrored observation implementation.
#include <array>
#include <cstddef>
#include <jni.h>
#include <jni_md.h>
#include <string>
#include <vector>

#include "builtin.h"
#include "events/window_bridge.h"
#include "rasp/config.h"
#include "rasp/observation.h"
#include "util/jni.h"

namespace {

jobjectArray read(JNIEnv* env, jclass /*test*/, jboolean enabled) {
  const rasp::Config config{
      .build_id = "window-test",
      .checks = std::vector<std::string>{enabled == JNI_TRUE ? "overlay" : "unknown"},
  };
  const auto observations = rasp::android::run_checks(config);
  jclass string_class = env->FindClass("java/lang/String");
  jobjectArray result = env->NewObjectArray(static_cast<jsize>(observations.size()), string_class, nullptr);
  for (std::size_t index = 0; index < observations.size(); ++index) {
    jstring value = env->NewStringUTF(rasp::describe(observations[index]).c_str());
    env->SetObjectArrayElement(result, static_cast<jsize>(index), value);
    env->DeleteLocalRef(value);
  }
  env->DeleteLocalRef(string_class);
  return result;
}

jclass missing_class(JNIEnv* /*env*/, const char* /*name*/) { return nullptr; }

jint reject_registration(JNIEnv* env, jclass /*type*/, const JNINativeMethod* /*methods*/, jint /*count*/) {
  jclass error = env->FindClass("java/lang/NoSuchMethodError");
  static_cast<void>(env->ThrowNew(error, "injected registration failure"));
  env->DeleteLocalRef(error);
  return JNI_ERR;
}

jboolean registration_failure(JNIEnv* env, jclass /*test*/) {
  const auto* original = env->functions;
  auto table = *original;
  table.FindClass = missing_class;
  env->functions = &table;
  const bool registered = rasp::android::events::register_window_bridge(env);
  env->functions = original;
  const bool lookup_cleared = !rasp::android::util::threw(env);
  table = *original;
  table.RegisterNatives = reject_registration;
  env->functions = &table;
  const bool rejected = rasp::android::events::register_window_bridge(env);
  env->functions = original;
  return !registered && lookup_cleared && !rejected && !rasp::android::util::threw(env) ? JNI_TRUE : JNI_FALSE;
}

}  // namespace

/// Called by the existing real-JVM driver after production registration.
[[nodiscard]] bool register_window_test(JNIEnv* env) {
  jclass test = env->FindClass("co/ostorlab/rasp/WindowTest");
  auto read_name = std::to_array("read");
  auto read_signature = std::to_array("(Z)[Ljava/lang/String;");
  auto failure_name = std::to_array("registrationFailure");
  auto failure_signature = std::to_array("()Z");
  const std::array methods{
      JNINativeMethod{
          .name = read_name.data(),
          .signature = read_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&read),
      },
      JNINativeMethod{
          .name = failure_name.data(),
          .signature = failure_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&registration_failure),
      },
  };
  if (test == nullptr) {
    return false;
  }
  const jint result = env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size()));
  env->DeleteLocalRef(test);
  return result == JNI_OK;
}

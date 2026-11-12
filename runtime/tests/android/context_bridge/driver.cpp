/// Real-JVM integration of the shipped bridge and PackageManager consumer, with JNI allocation/lookup fault injection.

#include "android/events/driver.h"

#include <array>
#include <cstdint>
#include <jni.h>
#include <jni_md.h>
#include <optional>
#include <thread>
#include <vector>

#include "events/window_bridge.h"
#include "util/application_context.h"
#include "util/jni.h"
#include "util/package_manager.h"

namespace {

/// Reports an assertion failure to the Java test caller.
void check(JNIEnv* env, bool condition) {
  if (!condition) {
    jclass error = env->FindClass("java/lang/AssertionError");
    static_cast<void>(env->ThrowNew(error, "native bridge assertion"));
  }
}

/// Checks that the production consumer reaches the real Java PackageManager boundary.
jboolean read_certificate(JNIEnv* env, jclass /*test*/) {
  const auto certificate = rasp::android::util::read_package_manager_certificate(env);
  return certificate == std::optional(std::vector<std::uint8_t>{1, 2, 3}) ? JNI_TRUE : JNI_FALSE;
}

/// Creates and deletes the accessor's local reference on the caller's own thread.
jboolean has_context(JNIEnv* env, jclass /*test*/) {
  const auto context = rasp::android::util::application_context(env);
  if (!context.has_value() || *context == nullptr) {
    return JNI_FALSE;
  }
  env->DeleteLocalRef(*context);
  return JNI_TRUE;
}

/// Fails a JNI reference creation, like VM reference-table exhaustion, with a pending exception.
jobject fail_reference(JNIEnv* env, jobject /*object*/) {
  jclass error = env->FindClass("java/lang/OutOfMemoryError");
  static_cast<void>(env->ThrowNew(error, "injected reference failure"));
  env->DeleteLocalRef(error);
  return nullptr;
}

/// Fails FindClass, like a class-loader lookup failure, with no reference.
jclass fail_class(JNIEnv* /*env*/, const char* /*name*/) { return nullptr; }

/// Fails registration with a pending linkage exception.
jint fail_registration(JNIEnv* env, jclass /*type*/, const JNINativeMethod* /*methods*/, jint /*count*/) {
  jclass error = env->FindClass("java/lang/NoSuchMethodError");
  static_cast<void>(env->ThrowNew(error, "injected registration failure"));
  env->DeleteLocalRef(error);
  return JNI_ERR;
}

/// Runs the production failure paths before any Application is published.
void test_failures(JNIEnv* env, jclass /*test*/) {
  using rasp::android::util::ContextInitResult;
  const auto* original = env->functions;
  auto table = *original;
  jclass application_class = env->FindClass("android/app/Application");
  jmethodID constructor = env->GetMethodID(application_class, "<init>", "()V");
  jobject application = env->NewObjectA(application_class, constructor, nullptr);
  table.NewGlobalRef = fail_reference;
  env->functions = &table;
  const auto failed = rasp::android::util::initialize_application_context(env, application);
  env->functions = original;
  check(env, failed == ContextInitResult::kJniError && env->ExceptionCheck() == JNI_FALSE);
  check(env, has_context(env, nullptr) == JNI_FALSE);
  table = *original;
  table.FindClass = fail_class;
  env->functions = &table;
  const bool missing = rasp::android::util::register_context_bridge(env);
  env->functions = original;
  check(env, !missing && env->ExceptionCheck() == JNI_FALSE);
  table = *original;
  table.RegisterNatives = fail_registration;
  env->functions = &table;
  const bool registered = rasp::android::util::register_context_bridge(env);
  env->functions = original;
  check(env, !registered && env->ExceptionCheck() == JNI_FALSE);
  env->DeleteLocalRef(application);
  env->DeleteLocalRef(application_class);
}

/// Verifies local-reference exhaustion is reported and cleared by both accessor and consumer.
jboolean reader_failures(JNIEnv* env, jclass /*test*/) {
  const auto* original = env->functions;
  auto table = *original;
  table.NewLocalRef = fail_reference;
  env->functions = &table;
  const auto context = rasp::android::util::application_context(env);
  const auto certificate = rasp::android::util::read_package_manager_certificate(env);
  env->functions = original;
  return !context.has_value() && !certificate.has_value() && env->ExceptionCheck() == JNI_FALSE ? JNI_TRUE : JNI_FALSE;
}

/// Attaches a genuine native reader thread, consumes its own local refs and detaches before it exits.
jboolean native_thread_read(JNIEnv* env, jclass /*test*/) {
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    return JNI_FALSE;
  }
  bool success = false;
  std::thread reader([&success, vm] {
    JNIEnv* thread_env = rasp::android::util::attached_env();
    if (thread_env != nullptr) {
      success = has_context(thread_env, nullptr) == JNI_TRUE && read_certificate(thread_env, nullptr) == JNI_TRUE;
      success = vm->DetachCurrentThread() == JNI_OK && success;
    }
  });
  reader.join();
  return success ? JNI_TRUE : JNI_FALSE;
}

}  // namespace

/// Registers the production bridge and test-only probes; no test API ships in librasp.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  if (!rasp::android::util::register_context_bridge(env)) {
    return JNI_ERR;
  }
  if (!rasp::android::events::register_window_bridge(env)) {
    return JNI_ERR;
  }
  jclass test = env->FindClass("co/ostorlab/rasp/BridgeTest");
  auto read_name = std::to_array("readCertificate");
  auto has_name = std::to_array("hasContext");
  auto failure_name = std::to_array("testFailures");
  auto reader_failure_name = std::to_array("readerFailures");
  auto thread_name = std::to_array("nativeThreadRead");
  auto boolean_signature = std::to_array("()Z");
  auto void_signature = std::to_array("()V");
  const std::array<JNINativeMethod, 5> methods{
      {
          {
              .name = read_name.data(),
              .signature =
                  boolean_signature
                      .data(),  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI method entry.
              .fnPtr = reinterpret_cast<void*>(&read_certificate),
          },
          {
              .name = has_name.data(),
              .signature =
                  boolean_signature
                      .data(),  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI method entry.
              .fnPtr = reinterpret_cast<void*>(&has_context),
          },
          {
              .name = reader_failure_name.data(),
              .signature =
                  boolean_signature
                      .data(),  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI method entry.
              .fnPtr = reinterpret_cast<void*>(&reader_failures),
          },
          {
              .name = thread_name.data(),
              .signature =
                  boolean_signature
                      .data(),  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI method entry.
              .fnPtr = reinterpret_cast<void*>(&native_thread_read),
          },
          {
              .name = failure_name.data(),
              .signature =
                  void_signature
                      .data(),  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI method entry.
              .fnPtr = reinterpret_cast<void*>(&test_failures),
          },
      },
  };
  if (test == nullptr || env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size())) != JNI_OK) {
    return JNI_ERR;
  }
  env->DeleteLocalRef(test);
  return register_window_test(env) ? JNI_VERSION_1_6 : JNI_ERR;
}

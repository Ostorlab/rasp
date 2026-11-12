/// Real-JVM integration of the shipped bridge and PackageManager consumer, with JNI allocation/lookup fault injection.

#include "android/events/driver.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <jni_md.h>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "android/context_bridge/policy_driver.h"
#include "android/events/capture_driver.h"
#include "builtin.h"
#include "events/capture_bridge.h"
#include "events/window_bridge.h"
#include "local_policy_bridge.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "util/application_context.h"
#include "util/jni.h"
#include "util/package_identity.h"
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

/// Owning callback retention verifies that observations and metadata remain one immutable handoff.
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetainedIdentityCycle{"test.identity.cycle"};
/// Confirms both callback forms received the same snapshot object.
constexpr rasp::plugins::Key<bool> kIdentityCyclePaired{"test.identity.paired"};

/// Retains the snapshot only while the production callback span matches its owned observations.
void retain_identity_cycle(std::span<const rasp::Observation> observations, rasp::plugins::Context& context) {
  const auto snapshot = context.get(rasp::plugins::kCycleSnapshot);
  if (snapshot.has_value() && std::ranges::equal((*snapshot)->observations, observations)) {
    context.put(kRetainedIdentityCycle, *snapshot);
  }
}

/// Verifies the additive callback receives the same object already retained by the legacy callback.
void confirm_identity_cycle(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot,
                            rasp::plugins::Context& context) {
  const auto retained = context.get(kRetainedIdentityCycle);
  context.put(kIdentityCyclePaired, retained.has_value() && *retained == snapshot);
}

/// Executes actual identity dispatch through the same finite snapshot/callback path as production monitoring.
[[nodiscard]] std::shared_ptr<const rasp::CycleSnapshot> identity_cycle() {
  const rasp::Config config{.build_id = "identity-fixture", .checks = std::vector<std::string>{"identity"}};
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr rasp::plugins::Plugin kPlugin{
      .init = nullptr,
      .checks = {},
      .on_observations = retain_identity_cycle,
      .on_cycle = confirm_identity_cycle,
  };
  const std::array plugins{&kPlugin};
  const auto catalogue = rasp::cycle_catalogue("android");
  auto snapshot = monitor.run(config, catalogue, plugins, context, [](const rasp::Config& selection, const void*) {
    return rasp::android::run_checks(selection);
  });
  const auto retained = context.get(kRetainedIdentityCycle);
  if (!retained.has_value() || *retained != snapshot || context.get(rasp::plugins::kCycleSnapshot).has_value() ||
      context.get(kIdentityCyclePaired) != true) {
    return nullptr;
  }
  const auto& metadata = snapshot->metadata;
  if (!metadata.complete || !metadata.execution_finished || metadata.expected != 9U || metadata.seen != 9U ||
      !metadata.missing.empty() || metadata.extra != 0 || metadata.dropped != 0 || snapshot->observations.size() != 9 ||
      metadata.catalogue_id != catalogue.catalogue_id) {
    return nullptr;
  }
  return snapshot;
}

/// Calls the actual production group dispatcher and transfers only its serialized observations to Java assertions.
jobjectArray identity_rows(JNIEnv* env, jclass /*test*/) {
  const auto snapshot = identity_cycle();
  if (snapshot == nullptr) {
    check(env, false);
    return nullptr;
  }
  const auto& observations = snapshot->observations;
  jclass string_class = env->FindClass("java/lang/String");
  if (rasp::android::util::threw(env) || string_class == nullptr) {
    return nullptr;
  }
  jobjectArray rows = env->NewObjectArray(static_cast<jsize>(observations.size()), string_class, nullptr);
  if (rasp::android::util::threw(env) || rows == nullptr) {
    return nullptr;
  }
  for (std::size_t index = 0; index < observations.size(); ++index) {
    const auto text = rasp::describe(observations[index]);
    jstring row = env->NewStringUTF(text.c_str());
    if (rasp::android::util::threw(env) || row == nullptr) {
      return nullptr;
    }
    env->SetObjectArrayElement(rows, static_cast<jsize>(index), row);
    env->DeleteLocalRef(row);
    if (rasp::android::util::threw(env)) {
      return nullptr;
    }
  }
  env->DeleteLocalRef(string_class);
  return rows;
}

/// Injects reference, method, frame, and array-copy failures into the compiled public collector.
jboolean identity_faults(JNIEnv* env, jclass /*test*/) {
  const auto* original = env->functions;
  auto table = *original;
  table.NewLocalRef = fail_reference;
  env->functions = &table;
  const auto missing = rasp::android::util::read_package_identity(env);
  env->functions = original;
  if (missing.package_name.has_value() || missing.current.has_value() || env->ExceptionCheck() != JNI_FALSE) {
    return JNI_FALSE;
  }
  table.PushLocalFrame = [](JNIEnv* frame_env, jint) -> jint {
    jclass error = frame_env->FindClass("java/lang/OutOfMemoryError");
    static_cast<void>(frame_env->ThrowNew(error, "injected frame failure"));
    frame_env->DeleteLocalRef(error);
    return JNI_ERR;
  };
  env->functions = &table;
  const auto frame_failed = rasp::android::util::read_package_identity(env);
  env->functions = original;
  if (frame_failed.current.has_value() || frame_failed.package_name.has_value() || env->ExceptionCheck() != JNI_FALSE) {
    return JNI_FALSE;
  }
  table = *original;
  table.GetByteArrayRegion = [](JNIEnv* copy_env, jbyteArray, jsize, jsize, jbyte*) {
    static_cast<void>(fail_reference(copy_env, nullptr));
  };
  env->functions = &table;
  const auto copy_failed = rasp::android::util::read_package_identity(env);
  env->functions = original;
  if (copy_failed.current.has_value() || env->ExceptionCheck() != JNI_FALSE) {
    return JNI_FALSE;
  }
  table = *original;
  table.GetArrayLength = [](JNIEnv* array_env, jarray) -> jsize {
    static_cast<void>(fail_reference(array_env, nullptr));
    return -1;
  };
  env->functions = &table;
  const auto array_failed = rasp::android::util::read_package_identity(env);
  env->functions = original;
  if (array_failed.current.has_value() || env->ExceptionCheck() != JNI_FALSE) {
    return JNI_FALSE;
  }
  table = *original;
  table.GetMethodID = [](JNIEnv*, jclass, const char*, const char*) -> jmethodID { return nullptr; };
  env->functions = &table;
  const auto method_failed = rasp::android::util::read_package_identity(env);
  env->functions = original;
  return !method_failed.current.has_value() && !method_failed.package_name.has_value() &&
                 env->ExceptionCheck() == JNI_FALSE &&
                 !rasp::android::util::read_package_identity(nullptr).current.has_value()
             ? JNI_TRUE
             : JNI_FALSE;
}

/// Exercises current/history collection on an attached native worker and detaches before the worker exits.
jboolean identity_thread_reads(JNIEnv* env, jclass /*test*/) {
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    return JNI_FALSE;
  }
  const auto expected = identity_cycle();
  if (expected == nullptr) {
    return JNI_FALSE;
  }
  bool success = true;
  std::thread reader([&success, vm, expected] {
    JNIEnv* thread_env = rasp::android::util::attached_env();
    if (thread_env == nullptr) {
      success = false;
      return;
    }
    for (std::size_t pass = 0; pass < 1000; ++pass) {
      const auto snapshot = identity_cycle();
      if (snapshot == nullptr || snapshot->observations != expected->observations ||
          thread_env->ExceptionCheck() != JNI_FALSE) {
        success = false;
        break;
      }
    }
    success = vm->DetachCurrentThread() == JNI_OK && success;
  });
  reader.join();
  return success ? JNI_TRUE : JNI_FALSE;
}

/// Registers test-only probes independently of the shipped RuntimeBridge entry.
[[nodiscard]] bool register_identity_test(JNIEnv* env) {
  jclass test = env->FindClass("co/ostorlab/rasp/IdentityTest");
  auto rows_name = std::to_array("rows");
  auto rows_signature = std::to_array("()[Ljava/lang/String;");
  auto faults_name = std::to_array("faults");
  auto faults_signature = std::to_array("()Z");
  auto thread_name = std::to_array("threadReads");
  const std::array<JNINativeMethod, 3> methods{
      {
          {
              .name = thread_name.data(),
              .signature = faults_signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): RegisterNatives requires a void* function entry.
              .fnPtr = reinterpret_cast<void*>(&identity_thread_reads),
          },
          {
              .name = rows_name.data(),
              .signature = rows_signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): RegisterNatives requires a void* function entry.
              .fnPtr = reinterpret_cast<void*>(&identity_rows),
          },
          {
              .name = faults_name.data(),
              .signature = faults_signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): RegisterNatives requires a void* function entry.
              .fnPtr = reinterpret_cast<void*>(&identity_faults),
          },
      },
  };
  const bool success =
      test != nullptr && env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size())) == JNI_OK;
  env->DeleteLocalRef(test);
  return success;
}

}  // namespace

/// Implements only the Android API-level boundary for the host JVM's production dispatcher object.
extern "C" int android_get_device_api_level() {
  JNIEnv* env = rasp::android::util::attached_env();
  if (env == nullptr) {
    return -1;
  }
  jclass version = env->FindClass("android/os/Build$VERSION");
  if (rasp::android::util::threw(env) || version == nullptr) {
    return -1;
  }
  jfieldID field = env->GetStaticFieldID(version, "SDK_INT", "I");
  if (rasp::android::util::threw(env) || field == nullptr) {
    env->DeleteLocalRef(version);
    return -1;
  }
  const jint api = env->GetStaticIntField(version, field);
  const bool failed = rasp::android::util::threw(env);
  env->DeleteLocalRef(version);
  return failed ? -1 : api;
}

/// Registers the production bridge and test-only probes; no test API ships in librasp.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  if (!rasp::android::util::register_context_bridge(env) || !register_identity_test(env)) {
    return JNI_ERR;
  }
  if (!rasp::android::events::register_window_bridge(env)) {
    return JNI_ERR;
  }
  if (!rasp::android::register_local_policy_bridge(env) || !register_policy_test(env)) {
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
  return register_capture_test(env) && rasp::android::events::register_capture_bridge(env) && register_window_test(env)
             ? JNI_VERSION_1_6
             : JNI_ERR;
}

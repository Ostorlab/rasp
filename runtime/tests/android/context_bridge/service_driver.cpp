/// Real JVM entry to the production public Android collectors on calling and attached worker threads.

#include <array>
#include <jni.h>
#include <jni_md.h>
#include <string>
#include <thread>
#include <vector>

#include "builtin.h"
#include "rasp/config.h"
#include "rasp/observation.h"
#include "util/application_context.h"

namespace {
/// Dispatches only public collectors and serializes their actual observation contracts.
std::string collect(jint group) {
  rasp::Config config;
  switch (group) {
    case 0:
      config.checks = {"accessibility"};
      break;
    case 1:
      config.checks = {"input_method"};
      break;
    case 2:
      config.checks = {"notification_access"};
      break;
    default:
      return {};
  }
  const std::vector<rasp::Observation> observations = rasp::android::run_checks(config);
  std::string result;
  for (const auto& observation : observations) {
    if (!result.empty()) {
      result += '\n';
    }
    result += rasp::describe(observation);
  }
  return result;
}
/// Reads the actual dispatch on the JVM caller's thread.
jstring snapshot(JNIEnv* env, jclass /*test*/, jint group) { return env->NewStringUTF(collect(group).c_str()); }
/// Makes the same calls from a real attached native worker and releases thread ownership before exit.
jstring worker_snapshot(JNIEnv* env, jclass /*test*/, jint group) {
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    return nullptr;
  }
  std::string result;
  std::thread reader([&result, vm, group] {
    result = collect(group);
    static_cast<void>(vm->DetachCurrentThread());
  });
  reader.join();
  return env->NewStringUTF(result.c_str());
}
/// Simulates a JNI allocation failure, leaving the same pending exception a VM would set.
jobject fail_reference(JNIEnv* env, jobject /*object*/) {
  jclass error = env->FindClass("java/lang/OutOfMemoryError");
  static_cast<void>(env->ThrowNew(error, "injected reference failure"));
  env->DeleteLocalRef(error);
  return nullptr;
}
/// Simulates local-frame exhaustion with its pending exception.
jint fail_frame(JNIEnv* env, jint /*capacity*/) {
  static_cast<void>(fail_reference(env, nullptr));
  return JNI_ERR;
}
/// Simulates method resolution failure with a pending linkage exception.
jmethodID fail_method(JNIEnv* env, jclass /*type*/, const char* /*name*/, const char* /*signature*/) {
  jclass error = env->FindClass("java/lang/NoSuchMethodError");
  static_cast<void>(env->ThrowNew(error, "injected method failure"));
  env->DeleteLocalRef(error);
  return nullptr;
}
/// Exercises production JNI exception handling, restoring the real VM table before returning to Java.
jstring faulty_snapshot(JNIEnv* env, jclass /*test*/, jint fault_kind) {
  const auto* original = env->functions;
  auto table = *original;
  if (fault_kind == 0) {
    table.NewLocalRef = fail_reference;
  }
  if (fault_kind == 1) {
    table.PushLocalFrame = fail_frame;
  }
  if (fault_kind == 2) {
    table.GetMethodID = fail_method;
  }
  env->functions = &table;
  const std::string result = collect(0);
  env->functions = original;
  if (env->ExceptionCheck() == JNI_TRUE) {
    return nullptr;
  }
  return env->NewStringUTF(result.c_str());
}

}  // namespace
/// Binds the shipped Context bridge plus a test-only snapshot method; no fixture entry ships in librasp.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  if (!rasp::android::util::register_context_bridge(env)) {
    return JNI_ERR;
  }
  jclass test = env->FindClass("co/ostorlab/rasp/ServiceTest");
  auto name = std::to_array("snapshotNative");
  auto worker_name = std::to_array("workerSnapshot");
  auto fault_name = std::to_array("faultySnapshot");
  auto signature = std::to_array("(I)Ljava/lang/String;");
  const std::array<JNINativeMethod, 3> methods{
      {
          {
              .name = name.data(),
              .signature = signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* method entry.
              .fnPtr = reinterpret_cast<void*>(&snapshot),
          },
          {
              .name = worker_name.data(),
              .signature = signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* method entry.
              .fnPtr = reinterpret_cast<void*>(&worker_snapshot),
          },
          {
              .name = fault_name.data(),
              .signature = signature.data(),
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* method entry.
              .fnPtr = reinterpret_cast<void*>(&faulty_snapshot),
          },
      },
  };
  if (test == nullptr || env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size())) != JNI_OK) {
    return JNI_ERR;
  }
  env->DeleteLocalRef(test);
  return JNI_VERSION_1_6;
}

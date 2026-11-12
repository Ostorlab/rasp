/// Real JVM entry to the production public Android collectors on calling and attached worker threads.

#include <algorithm>
#include <array>
#include <jni.h>
#include <jni_md.h>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "builtin.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "util/application_context.h"

namespace {
/// Retained owner proves the actual legacy callback received the same atomic handoff.
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetainedCycle{"test.service.cycle"};

/// Retains metadata and observations together during the synchronous callback.
void retain_cycle(std::span<const rasp::Observation> observations, rasp::plugins::Context& context) {
  const auto snapshot = context.get(rasp::plugins::kCycleSnapshot);
  if (snapshot.has_value() && std::ranges::equal((*snapshot)->observations, observations)) {
    context.put(kRetainedCycle, *snapshot);
  }
}

/// Executes real RT08 collectors through the same finite path as the Android monitor.
[[nodiscard]] std::string collect_cycle(const rasp::Config& config) {
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  constexpr rasp::plugins::Plugin kPlugin{.init = nullptr, .checks = {}, .on_observations = retain_cycle};
  const std::array plugins{&kPlugin};
  const auto snapshot =
      monitor.run(config, rasp::cycle_catalogue("android"), plugins, context,
                  [](const rasp::Config& selection, const void*) { return rasp::android::run_checks(selection); });
  const auto retained = context.get(kRetainedCycle);
  if (!retained.has_value() || *retained != snapshot || context.get(rasp::plugins::kCycleSnapshot).has_value()) {
    return "cycle handoff unavailable";
  }
  const auto& metadata = snapshot->metadata;
  return std::string("cycle complete=") + (metadata.complete ? "true" : "false") +
         " execution_finished=" + (metadata.execution_finished ? "true" : "false") +
         " dropped=" + std::to_string(metadata.dropped) +
         " expected=" + (metadata.expected.has_value() ? std::to_string(*metadata.expected) : "unknown") +
         " seen=" + std::to_string(metadata.seen) + " missing=" + std::to_string(metadata.missing.size()) +
         " retained=" + std::to_string(snapshot->observations.size());
}

/// Dispatches only public collectors and serializes their actual observation contracts.
std::string collect(jint group) {
  rasp::Config config;
  const bool cycle = group >= 10;
  switch (cycle ? group - 10 : group) {
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
  if (cycle) {
    return collect_cycle(config);
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

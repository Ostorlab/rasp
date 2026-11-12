/// Real JVM adapter and finite compiled-in plugin consumer of the production public storage capability.
#include <array>
#include <fcntl.h>
#include <jni.h>
#include <jni_md.h>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/private_storage.h"
#include "util/application_context.h"

namespace {
/// Consumer checks the borrowed descriptor and writes a bounded fixture payload relative to its actual queue owner.
[[nodiscard]] std::string collect() {
  auto storage = rasp::acquire_private_storage();
  if (!storage.has_value()) {
    return storage.error() == rasp::StorageError::kUnavailable ? "unavailable" : "error";
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
  if ((static_cast<unsigned int>(fcntl(storage->native_handle(), F_GETFD)) & FD_CLOEXEC) == 0) {
    return "descriptor not close-on-exec";
  }
  const int payload =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
      openat(storage->native_handle(), "consumer_probe", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (payload < 0) {
    return "payload open failed";
  }
  const std::string identity(storage->install_id());
  const bool written = std::cmp_equal(write(payload, identity.data(), identity.size()), identity.size());
  const bool synced = fsync(payload) == 0;
  const bool closed = close(payload) == 0;
  if (!written || !synced || !closed || !storage->close().has_value()) {
    return "consumer I/O failed";
  }
  return "ready:" + identity;
}
/// Serializes a direct call on a Java-owned attached thread.
jstring snapshot(JNIEnv* env, jclass /*test*/, jint /*unused*/) { return env->NewStringUTF(collect().c_str()); }

/// Verifies the public provider attaches and detaches a fresh native worker, including early unavailable calls.
jstring worker_snapshot(JNIEnv* env, jclass /*test*/) {
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    return nullptr;
  }
  std::string result;
  std::thread worker([&result, vm] {
    void* unused = nullptr;
    if (vm->GetEnv(&unused, JNI_VERSION_1_6) != JNI_EDETACHED) {
      result = "worker unexpectedly attached";
      return;
    }
    result = collect();
    if (vm->GetEnv(&unused, JNI_VERSION_1_6) != JNI_EDETACHED) {
      result = "worker attachment leaked";
    }
  });
  worker.join();
  return env->NewStringUTF(result.c_str());
}

constexpr rasp::plugins::Key<std::string> kStorageResult{"test.storage.result"};
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetainedCycle{"test.storage.retained"};
/// A finite real legacy callback queries the additive provider independently of startup Config/install identity.
void consume_cycle(std::span<const rasp::Observation> /*observations*/, rasp::plugins::Context& context) {
  const auto snapshot_value = context.get(rasp::plugins::kCycleSnapshot);
  if (snapshot_value.has_value()) {
    context.put(kRetainedCycle, *snapshot_value);
  }
  context.put(kStorageResult, collect());
}
/// Keeps a prior immutable snapshot across later provider availability and confirms Config remains unchanged.
jstring cycle_snapshot(JNIEnv* env, jclass /*test*/) {
  const rasp::Config config;
  const rasp::CycleCatalogue catalogue{};
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr rasp::plugins::Plugin kPlugin{.init = nullptr, .checks = {}, .on_observations = consume_cycle};
  const std::array plugins{&kPlugin};
  const auto first = monitor.run(config, catalogue, plugins, context,
                                 [](const rasp::Config&, const void*) { return std::vector<rasp::Observation>{}; });
  const auto retained = context.get(kRetainedCycle);
  const auto result = context.get(kStorageResult);
  if (!retained.has_value() || *retained != first || !result.has_value() || config.install_id.has_value() ||
      !first->observations.empty()) {
    return env->NewStringUTF("cycle mutated");
  }
  const auto second = monitor.run(config, catalogue, plugins, context,
                                  [](const rasp::Config&, const void*) { return std::vector<rasp::Observation>{}; });
  if (second == first || (*retained)->metadata.sequence != first->metadata.sequence ||
      !(*retained)->observations.empty()) {
    return env->NewStringUTF("prior snapshot mutated");
  }
  return env->NewStringUTF(result->c_str());
}

/// Runs an unavailable cycle before the real Java bridge call, then proves late capability without mutating that
/// snapshot.
jstring late_cycle_transition(JNIEnv* env, jclass /*test*/, jobject initialize) {
  const rasp::Config config;
  const rasp::CycleCatalogue catalogue{};
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  constexpr rasp::plugins::Plugin kPlugin{.init = nullptr, .checks = {}, .on_observations = consume_cycle};
  const std::array plugins{&kPlugin};
  const auto collector = [](const rasp::Config&, const void*) { return std::vector<rasp::Observation>{}; };
  const auto first = monitor.run(config, catalogue, plugins, context, collector);
  const std::string first_run = first->metadata.run_id;
  const auto first_sequence = first->metadata.sequence;
  const auto early = context.get(kStorageResult);
  if (!early.has_value() || *early != "unavailable") {
    return env->NewStringUTF("early cycle had storage");
  }
  jclass runnable = env->FindClass("java/lang/Runnable");
  if (runnable == nullptr) {
    return nullptr;
  }
  jmethodID run = env->GetMethodID(runnable, "run", "()V");
  if (run == nullptr) {
    env->DeleteLocalRef(runnable);
    return nullptr;
  }
  env->CallVoidMethodA(initialize, run, nullptr);
  env->DeleteLocalRef(runnable);
  if (env->ExceptionCheck() == JNI_TRUE) {
    return nullptr;
  }
  const auto second = monitor.run(config, catalogue, plugins, context, collector);
  const auto late = context.get(kStorageResult);
  if (!late.has_value() || config.install_id.has_value() || first == second || first->metadata.run_id != first_run ||
      first->metadata.sequence != first_sequence || !first->observations.empty()) {
    return env->NewStringUTF("late availability mutated prior cycle");
  }
  return env->NewStringUTF(late->c_str());
}

/// Leaves an actual pending VM exception for production error handling to clear.
void raise(JNIEnv* env) {
  jclass error = env->FindClass("java/lang/OutOfMemoryError");
  static_cast<void>(env->ThrowNew(error, "injected storage JNI failure"));
  env->DeleteLocalRef(error);
}
/// Models global-to-local ownership allocation failure.
jobject fail_reference(JNIEnv* env, jobject /*object*/) {
  raise(env);
  return nullptr;
}
/// Models local-frame exhaustion.
jint fail_frame(JNIEnv* env, jint /*capacity*/) {
  raise(env);
  return JNI_ERR;
}
/// Models missing public methods without recursively using the replaced method resolver.
jmethodID fail_method(JNIEnv* env, jclass /*type*/, const char* /*name*/, const char* /*signature*/) {
  raise(env);
  return nullptr;
}
/// Models lookup failure without leaving an exception.
jclass fail_class(JNIEnv* /*env*/, const char* /*name*/) { return nullptr; }
/// Models a wrong result object at the platform boundary.
jboolean wrong_type(JNIEnv* /*env*/, jobject /*object*/, jclass /*type*/) { return JNI_FALSE; }
/// Models failed UTF conversion with an actual pending exception.
const char* fail_utf(JNIEnv* env, jstring /*text*/, jboolean* /*copied*/) {
  raise(env);
  return nullptr;
}
/// Models an oversized public File path.
jsize oversized(JNIEnv* /*env*/, jstring /*text*/) { return 4096; }
/// Models platform method exceptions.
jobject fail_call(JNIEnv* env, jobject /*object*/, jmethodID /*method*/, const jvalue* /*args*/) {
  raise(env);
  return nullptr;
}
/// Models absent platform values without throwing.
jobject null_call(JNIEnv* /*env*/, jobject /*object*/, jmethodID /*method*/, const jvalue* /*args*/) { return nullptr; }
/// Models allocation failure without a pending exception.
const char* null_utf(JNIEnv* /*env*/, jstring /*text*/, jboolean* /*copied*/) { return nullptr; }
/// Models an empty path.
jsize empty_path(JNIEnv* /*env*/, jstring /*text*/) { return 0; }
/// Keeps the real JNI boundary per test thread while a fault table is installed.
const JNINativeInterface_*& original_functions() {
  thread_local const JNINativeInterface_* functions = nullptr;
  return functions;
}

/// Models successful acquisition of UTF bytes followed by a pending VM exception.
const char* exceptional_utf(JNIEnv* env, jstring text, jboolean* copied) {
  const char* bytes = original_functions()->GetStringUTFChars(env, text, copied);
  raise(env);
  return bytes;
}
/// Models a throwing length query.
jsize fail_length(JNIEnv* env, jstring /*text*/) {
  raise(env);
  return 1;
}
/// Models a throwing type query.
jboolean fail_type(JNIEnv* env, jobject /*object*/, jclass /*type*/) {
  raise(env);
  return JNI_FALSE;
}

/// Replaces only VM boundary operations on this thread and restores the real table before returning to Java.
jstring faulty_snapshot(JNIEnv* env, jclass /*test*/, jint fault) {
  const auto* original = env->functions;
  original_functions() = original;
  auto table = *original;
  switch (fault) {
    case 0:
      table.NewLocalRef = fail_reference;
      break;
    case 1:
      table.PushLocalFrame = fail_frame;
      break;
    case 2:
      table.GetMethodID = fail_method;
      break;
    case 3:
      table.FindClass = fail_class;
      break;
    case 4:
      table.IsInstanceOf = wrong_type;
      break;
    case 5:
      table.GetStringUTFChars = fail_utf;
      break;
    case 6:
      table.GetStringUTFLength = oversized;
      break;
    case 7:
      table.CallObjectMethodA = fail_call;
      break;
    case 8:
      table.CallObjectMethodA = null_call;
      break;
    case 9:
      table.GetStringUTFChars = null_utf;
      break;
    case 10:
      table.GetStringUTFLength = empty_path;
      break;
    case 11:
      table.GetStringUTFChars = exceptional_utf;
      break;
    case 12:
      table.GetStringUTFLength = fail_length;
      break;
    case 13:
      table.IsInstanceOf = fail_type;
      break;
    default:
      return nullptr;
  }
  env->functions = &table;
  const std::string result = collect();
  env->functions = original;
  original_functions() = nullptr;
  if (env->ExceptionCheck() == JNI_TRUE) {
    return nullptr;
  }
  return env->NewStringUTF(result.c_str());
}
}  // namespace

/// Registers only test fixture methods plus the production public Application bridge.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  if (!rasp::android::util::register_context_bridge(env)) {
    return JNI_ERR;
  }
  jclass test = env->FindClass("co/ostorlab/rasp/StorageTest");
  auto name = std::to_array("snapshotNative");
  auto worker_name = std::to_array("workerSnapshot");
  auto fault_name = std::to_array("faultySnapshot");
  auto cycle_name = std::to_array("cycleSnapshot");
  auto transition_name = std::to_array("lateCycleTransition");
  auto transition_signature = std::to_array("(Ljava/lang/Runnable;)Ljava/lang/String;");
  auto signature = std::to_array("(I)Ljava/lang/String;");
  auto no_args = std::to_array("()Ljava/lang/String;");
  const JNINativeMethod transition_method{
      .name = transition_name.data(),
      .signature = transition_signature.data(),
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* entry.
      .fnPtr = reinterpret_cast<void*>(&late_cycle_transition),
  };
  const std::array methods{
      JNINativeMethod{
          .name = name.data(),
          .signature = signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* entry.
          .fnPtr = reinterpret_cast<void*>(&snapshot),
      },
      JNINativeMethod{
          .name = worker_name.data(),
          .signature = no_args.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* entry.
          .fnPtr = reinterpret_cast<void*>(&worker_snapshot),
      },
      JNINativeMethod{
          .name = fault_name.data(),
          .signature = signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* entry.
          .fnPtr = reinterpret_cast<void*>(&faulty_snapshot),
      },
      JNINativeMethod{
          .name = cycle_name.data(),
          .signature = no_args.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI registration requires a void* entry.
          .fnPtr = reinterpret_cast<void*>(&cycle_snapshot),
      },
      transition_method,
  };
  if (test == nullptr || env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size())) != JNI_OK) {
    return JNI_ERR;
  }
  env->DeleteLocalRef(test);
  return JNI_VERSION_1_6;
}

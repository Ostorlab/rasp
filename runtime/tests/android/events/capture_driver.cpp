/// Actual shipped dispatcher and CycleMonitor exercised with the canonical production catalogue.
#include "android/events/capture_driver.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <jni_md.h>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "builtin.h"
#include "checks/capture.h"
#include "events/capture_bridge.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "util/jni.h"

namespace {
/// Stores a one-time collector probe before any capture Java binding or host opt-in.
bool& cold_support() {
  static bool result = false;
  return result;
}
/// Reports actual production cold-start version semantics to the JVM assertions.
jboolean cold_support_correct(JNIEnv* /*unused*/, jclass /*unused*/) { return cold_support() ? JNI_TRUE : JNI_FALSE; }
constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetained{"test.capture.retained"};
constexpr rasp::plugins::Key<bool> kPaired{"test.capture.paired"};
/// Retains the exact owning snapshot seen by the actual legacy callback.
void retain(std::span<const rasp::Observation> observations, rasp::plugins::Context& context) {
  const auto snapshot = context.get(rasp::plugins::kCycleSnapshot);
  if (snapshot.has_value() && std::ranges::equal((*snapshot)->observations, observations)) {
    context.put(kRetained, *snapshot);
  }
}
/// Confirms the additive callback receives that same immutable owner.
void confirm(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  const auto retained = context.get(kRetained);
  context.put(kPaired, retained.has_value() && *retained == snapshot);
}
/// Uses the actual selected dispatcher exactly once, using canonical generated identities.
std::shared_ptr<const rasp::CycleSnapshot> cycle(rasp::CycleMonitor& monitor, rasp::plugins::Context& context,
                                                 unsigned int mask) {
  rasp::Config config;
  config.checks = std::vector<std::string>{};
  if ((mask & 1U) != 0) {
    config.checks->emplace_back("screenshot");
  }
  if ((mask & 2U) != 0) {
    config.checks->emplace_back("screen_recording");
  }
  constexpr rasp::plugins::Plugin kPlugin{
      .init = nullptr,
      .checks = {},
      .on_observations = retain,
      .on_cycle = confirm,
  };
  const std::array plugins{&kPlugin};
  const auto catalogue = rasp::cycle_catalogue("android");
  auto snapshot = monitor.run(config, catalogue, plugins, context, [](const rasp::Config& selection, const void*) {
    return rasp::android::run_checks(selection);
  });
  std::uint64_t expected = 0;
  if ((mask & 1U) != 0) {
    expected += 9U;
  }
  if ((mask & 2U) != 0) {
    expected += 12U;
  }
  if (!snapshot->metadata.complete || snapshot->metadata.expected != expected || snapshot->metadata.seen != expected ||
      snapshot->observations.size() != expected || context.get(kPaired) != true ||
      context.get(rasp::plugins::kCycleSnapshot).has_value()) {
    return nullptr;
  }
  return snapshot;
}
/// Returns real production observations to the Java assertions.
jobjectArray read_capture(JNIEnv* env, jclass /*unused*/, jint mask) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto snapshot = cycle(monitor, context, static_cast<unsigned int>(mask));
  if (snapshot == nullptr) {
    jclass error = env->FindClass("java/lang/AssertionError");
    static_cast<void>(env->ThrowNew(error, "capture cycle ownership/coverage mismatch"));
    env->DeleteLocalRef(error);
    return nullptr;
  }
  jclass strings = env->FindClass("java/lang/String");
  jobjectArray result = env->NewObjectArray(static_cast<jsize>(snapshot->observations.size()), strings, nullptr);
  for (std::size_t index = 0; index < snapshot->observations.size(); ++index) {
    jstring row = env->NewStringUTF(rasp::describe(snapshot->observations[index]).c_str());
    env->SetObjectArrayElement(result, static_cast<jsize>(index), row);
    env->DeleteLocalRef(row);
  }
  env->DeleteLocalRef(strings);
  return result;
}
/// Retains one complete cycle across a second selected drain and destroyed Context/monitor.
bool retained_pair() {
  std::shared_ptr<const rasp::CycleSnapshot> first;
  std::vector<rasp::Observation> saved;
  std::string run;
  {
    rasp::CycleMonitor monitor;
    rasp::plugins::Context context;
    first = cycle(monitor, context, 3);
    if (first == nullptr) {
      return false;
    }
    saved = first->observations;
    run = first->metadata.run_id;
    const auto second = cycle(monitor, context, 3);
    if (second == nullptr || second == first || first->metadata.sequence != 1U || second->metadata.sequence != 2U ||
        first->metadata.session_id != second->metadata.session_id ||
        first->metadata.run_id == second->metadata.run_id) {
      return false;
    }
  }
  return first->observations == saved && first->metadata.run_id == run && first->metadata.expected == 21U;
}
/// Exercises the same primitive dispatcher on the caller and a native worker.
jboolean paired(JNIEnv* /*unused*/, jclass /*unused*/, jboolean worker) {
  if (worker != JNI_TRUE) {
    return retained_pair() ? JNI_TRUE : JNI_FALSE;
  }
  bool result = false;
  std::thread thread([&result] {
    JNIEnv* env = rasp::android::util::attached_env();
    JavaVM* vm = nullptr;
    if (env != nullptr && env->GetJavaVM(&vm) == JNI_OK) {
      result = retained_pair();
      result = vm->DetachCurrentThread() == JNI_OK && result;
    }
  });
  thread.join();
  return result ? JNI_TRUE : JNI_FALSE;
}
/// Forces the real binding failure boundary, then allows explicit production re-registration.
jboolean rebind(JNIEnv* env, jclass /*unused*/, jboolean reject) {
  const auto* original = env->functions;
  auto table = *original;
  if (reject == JNI_TRUE) {
    table.RegisterNatives = [](JNIEnv* /*env*/, jclass /*bridge*/, const JNINativeMethod* /*methods*/,
                               jint /*count*/) -> jint { return JNI_ERR; };
    env->functions = &table;
  }
  const bool registered = rasp::android::events::register_capture_bridge(env);
  env->functions = original;
  return registered == (reject != JNI_TRUE) && !rasp::android::util::threw(env) ? JNI_TRUE : JNI_FALSE;
}
}  // namespace
bool register_capture_test(JNIEnv* env) {
  jclass version = env->FindClass("android/os/Build$VERSION");
  auto* const field = env->GetStaticFieldID(version, "SDK_INT", "I");
  const int sdk = env->GetStaticIntField(version, field);
  env->DeleteLocalRef(version);
  const auto cold = rasp::android::checks::capture(true, true);
  cold_support() =
      std::ranges::find(cold, rasp::observed("capture.screenshot.observer_state", "activity_screen_capture",
                                             std::string(sdk < 34 ? "unsupported" : "never_started"))) != cold.end();
  jclass test = env->FindClass("co/ostorlab/rasp/CaptureTest");
  if (test == nullptr) {
    return false;
  }
  auto read_name = std::to_array("read");
  auto read_signature = std::to_array("(I)[Ljava/lang/String;");
  auto pair_name = std::to_array("paired");
  auto pair_signature = std::to_array("(Z)Z");
  auto rebind_name = std::to_array("rebind");
  auto rebind_signature = std::to_array("(Z)Z");
  auto cold_name = std::to_array("coldSupportCorrect");
  auto cold_signature = std::to_array("()Z");
  const std::array methods{
      JNINativeMethod{
          .name = read_name.data(),
          .signature = read_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&read_capture),
      },
      JNINativeMethod{
          .name = pair_name.data(),
          .signature = pair_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&paired),
      },
      JNINativeMethod{
          .name = rebind_name.data(),
          .signature = rebind_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&rebind),
      },
      JNINativeMethod{
          .name = cold_name.data(),
          .signature = cold_signature.data(),
          .fnPtr =
              // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          reinterpret_cast<void*>(&cold_support_correct),
      },
  };
  const auto result = env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size()));
  env->DeleteLocalRef(test);
  return result == JNI_OK;
}

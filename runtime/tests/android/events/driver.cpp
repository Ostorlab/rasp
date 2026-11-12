#include "android/events/driver.h"

/// Test-only adapter probes: production dispatch/registration, not a mirrored observation implementation.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <jni_md.h>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "builtin.h"
#include "events/window_bridge.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "util/jni.h"

namespace {

constexpr rasp::plugins::Key<std::shared_ptr<const rasp::CycleSnapshot>> kRetainedWindowCycle{"test.window.cycle"};
constexpr rasp::plugins::Key<bool> kWindowCyclePaired{"test.window.paired"};

void retain_window_cycle(std::span<const rasp::Observation> observations, rasp::plugins::Context& context) {
  const auto snapshot = context.get(rasp::plugins::kCycleSnapshot);
  if (snapshot.has_value() && std::ranges::equal((*snapshot)->observations, observations)) {
    context.put(kRetainedWindowCycle, *snapshot);
  }
}

void confirm_window_cycle(const std::shared_ptr<const rasp::CycleSnapshot>& snapshot, rasp::plugins::Context& context) {
  const auto retained = context.get(kRetainedWindowCycle);
  context.put(kWindowCyclePaired, retained.has_value() && *retained == snapshot);
}

/// Same production dispatcher/cycle path as the monitor; selecting no groups must not consume window records.
[[nodiscard]] std::shared_ptr<const rasp::CycleSnapshot> window_cycle(rasp::CycleMonitor& monitor,
                                                                      rasp::plugins::Context& context, bool enabled) {
  const rasp::Config config{
      .build_id = "window-cycle-fixture",
      .checks = enabled ? std::vector<std::string>{"overlay"} : std::vector<std::string>{},
  };
  constexpr rasp::plugins::Plugin kPlugin{
      .init = nullptr,
      .checks = {},
      .on_observations = retain_window_cycle,
      .on_cycle = confirm_window_cycle,
  };
  const std::array plugins{&kPlugin};
  const auto catalogue = rasp::cycle_catalogue("android");
  auto snapshot = monitor.run(config, catalogue, plugins, context, [](const rasp::Config& selection, const void*) {
    return rasp::android::run_checks(selection);
  });
  const auto retained = context.get(kRetainedWindowCycle);
  const std::uint64_t expected = enabled ? 10U : 0U;
  const auto& metadata = snapshot->metadata;
  if (!retained.has_value() || *retained != snapshot || context.get(kWindowCyclePaired) != true ||
      context.get(rasp::plugins::kCycleSnapshot).has_value() || !metadata.complete || !metadata.execution_finished ||
      metadata.expected != expected || metadata.seen != expected || !metadata.missing.empty() || metadata.extra != 0 ||
      metadata.dropped != 0 || metadata.catalogue_id != catalogue.catalogue_id ||
      snapshot->observations.size() != expected) {
    return nullptr;
  }
  return snapshot;
}

jobjectArray read_window(JNIEnv* env, jclass /*test*/, jboolean enabled) {
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  const auto snapshot = window_cycle(monitor, context, enabled == JNI_TRUE);
  if (snapshot == nullptr) {
    jclass error = env->FindClass("java/lang/AssertionError");
    static_cast<void>(env->ThrowNew(error, "window cycle metadata/observation handoff mismatch"));
    env->DeleteLocalRef(error);
    return nullptr;
  }
  const auto& observations = snapshot->observations;
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

[[nodiscard]] bool has_counter(const rasp::CycleSnapshot& snapshot, std::string_view signal, std::int64_t count) {
  return std::ranges::find(snapshot.observations, rasp::observed(signal, "window_callback", count)) !=
         snapshot.observations.end();
}

/// The first immutable owner must survive its Context and a later drain, including the original run metadata.
[[nodiscard]] bool retained_cycles() {
  std::shared_ptr<const rasp::CycleSnapshot> first;
  std::string run_id;
  {
    rasp::CycleMonitor monitor;
    rasp::plugins::Context context;
    first = window_cycle(monitor, context, true);
    if (first == nullptr || !has_counter(*first, "overlay.touch_events", 1) ||
        !has_counter(*first, "overlay.obscured_touch_events", 1) ||
        !has_counter(*first, "overlay.partially_obscured_touch_events", 1)) {
      return false;
    }
    run_id = first->metadata.run_id;
    const auto second = window_cycle(monitor, context, true);
    if (second == nullptr || first == second || first->metadata.sequence != 1U || second->metadata.sequence != 2U ||
        first->metadata.session_id != second->metadata.session_id || run_id == second->metadata.run_id ||
        !has_counter(*second, "overlay.touch_events", 0)) {
      return false;
    }
  }
  return first->metadata.run_id == run_id && first->metadata.expected == 10U && first->metadata.seen == 10U &&
         first->metadata.complete && has_counter(*first, "overlay.touch_events", 1);
}

jboolean cycle_probe(JNIEnv* env, jclass /*test*/, jboolean worker) {
  if (worker != JNI_TRUE) {
    return retained_cycles() ? JNI_TRUE : JNI_FALSE;
  }
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK) {
    return JNI_FALSE;
  }
  bool success = false;
  std::thread reader([&success, vm] {
    if (rasp::android::util::attached_env() != nullptr) {
      success = retained_cycles();
      success = vm->DetachCurrentThread() == JNI_OK && success;
    }
  });
  reader.join();
  return success ? JNI_TRUE : JNI_FALSE;
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
  auto cycle_name = std::to_array("cycleProbe");
  auto cycle_signature = std::to_array("(Z)Z");
  const std::array methods{
      JNINativeMethod{
          .name = cycle_name.data(),
          .signature = cycle_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&cycle_probe),
      },
      JNINativeMethod{
          .name = read_name.data(),
          .signature = read_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires a void* ABI entry.
          .fnPtr = reinterpret_cast<void*>(&read_window),
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

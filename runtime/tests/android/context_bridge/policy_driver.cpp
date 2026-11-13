/// Test-only collector/clock boundaries feeding actual CycleMonitor and shipping C/JNI gate.
#include "android/context_bridge/policy_driver.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <jni.h>
#ifndef __ANDROID__
#include <jni_md.h>
#endif
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"

namespace {
/// An external clock boundary only, never a gate/action stub.
std::atomic<std::int64_t>& ticks() {
  static constinit std::atomic<std::int64_t> value{1000000000};
  return value;
}
/// Return checked fixture clock data.
std::optional<std::int64_t> clock_tick() {
  const auto value = ticks().load();
  return value < 0 ? std::nullopt : std::optional(value);
}
/// Immutable fixture policy version is selected before the one process-lifetime installation.
std::atomic<std::uint32_t>& fixture_version() {
  static constinit std::atomic<std::uint32_t> value{1};
  return value;
}
/// Select the fixture mode once before installing the process-lifetime policy.
std::atomic<bool>& fixture_report_only() {
  static constinit std::atomic<bool> value{false};
  return value;
}
/// Exact configured policy for the harmless receipt operation.
rasp::Config configuration() {
  return rasp::parse_config(
      std::string(
          R"({"build_id":"test","checks":["debugger"],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"demo","policy_version":)") +
      std::to_string(fixture_version().load()) + R"(,"mode":")" +
      (fixture_report_only().load() ? "report_only" : "gate") +
      R"(","scope":"host_calls_only","platform":"android","catalogue_id":"fce392826ee1d9e5bab8046ca1584e2755af0eb3fd26922769eb20c64e32f736","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[{"name":"append_demo_receipt","max_evidence_age_ms":75000,"max_cycle_duration_ms":5000,"rules":[{"rule_id":"native.android.dbg.tracer_pid.proc_status","rule_version":1}]}]}})");
}
/// Test-only uint32/mode initialization before installation, never a runtime policy replacement.
jboolean initialize_version(JNIEnv* env, jclass /*unused*/, jlongArray input) {
  if (input == nullptr || env->GetArrayLength(input) != 2) {
    return JNI_FALSE;
  }
  std::array<jlong, 2> values{};
  env->GetLongArrayRegion(input, 0, 2, values.data());
  if (env->ExceptionCheck() == JNI_TRUE || rasp::process_local_policy() != nullptr || values[0] <= 0 ||
      values[0] > 4294967295LL || (values[1] != 0 && values[1] != 1)) {
    return JNI_FALSE;
  }
  fixture_version().store(static_cast<std::uint32_t>(values[0]));
  fixture_report_only().store(values[1] == 1);
  return rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(configuration(), "android", clock_tick)) !=
                 nullptr
             ? JNI_TRUE
             : JNI_FALSE;
}
/// Publish real typed fixture cycles at the collector boundary.
void publish(JNIEnv* env, jclass /*unused*/, jlongArray input_values) {
  if (input_values == nullptr || env->GetArrayLength(input_values) != 3) {
    return;
  }
  std::array<jlong, 3> values{};
  env->GetLongArrayRegion(input_values, 0, 3, values.data());
  if (env->ExceptionCheck() == JNI_TRUE || values[1] < 0 || values[1] > 6) {
    return;
  }
  const auto [tracer, status, tick] = values;
  ticks().store(tick);
  auto* state = rasp::process_local_policy();
  const auto config = configuration();
  if (state == nullptr) {
    state = rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(config, "android", clock_tick));
  }
  if (state == nullptr) {
    return;
  }
  const std::vector<rasp::Observation> input{
      {
          .signal = "dbg.tracer_pid",
          .source = "proc_status",
          .status = static_cast<rasp::Status>(status),
          .value = static_cast<std::int64_t>(tracer),
      },
      rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{0}),
      rasp::observed("dbg.java_debugger", "debug_api", false),
      rasp::observed("dbg.java_debugger", "jdwp_threads", std::vector<std::string>{}),
  };
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  static_cast<void>(monitor.run(
      config, rasp::cycle_catalogue("android"), {}, context,
      [](const rasp::Config&, const void* argument) {
        return *static_cast<const std::vector<rasp::Observation>*>(argument);
      },
      &input, state));
}
/// Change only the external clock; reading must never refresh the stored cycle.
void advance(JNIEnv* /*unused*/, jclass /*unused*/, jlong tick) { ticks().store(tick); }
}  // namespace

bool register_policy_test(JNIEnv* env) {
  jclass test = env->FindClass("co/ostorlab/rasp/PolicyTest");
  if (test == nullptr) {
    return false;
  }
  auto publish_name = std::to_array("publishValuesNative");
  auto publish_signature = std::to_array("([J)V");
  auto advance_name = std::to_array("advanceNative");
  auto advance_signature = std::to_array("(J)V");
  auto initialize_name = std::to_array("initializeNative");
  auto initialize_signature = std::to_array("([J)Z");
  const std::array methods{
      JNINativeMethod{
          .name = initialize_name.data(),
          .signature = initialize_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): test-only JNI registration.
          .fnPtr = reinterpret_cast<void*>(&initialize_version),
      },
      JNINativeMethod{
          .name = publish_name.data(),
          .signature = publish_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): test-only JNI registration.
          .fnPtr = reinterpret_cast<void*>(&publish),
      },
      JNINativeMethod{
          .name = advance_name.data(),
          .signature = advance_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): test-only JNI registration.
          .fnPtr = reinterpret_cast<void*>(&advance),
      },
  };
  const auto result = env->RegisterNatives(test, methods.data(), static_cast<jint>(methods.size()));
  env->DeleteLocalRef(test);
  return result == JNI_OK;
}

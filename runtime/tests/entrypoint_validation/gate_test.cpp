/// Actual CycleMonitor -> host C consumer -> primitive gate -> receipt effect.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "c_host.h"
#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/entrypoint_validation.h"
#include "rasp/local_policy_host.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"

namespace {
/// Controlled native clock, never a gate stub.
std::int64_t& ticks() {
  static std::int64_t value = 1000000000;
  return value;
}
/// Native suspend-inclusive clock seam.
std::optional<std::int64_t> clock_tick() { return ticks() < 0 ? std::nullopt : std::optional(ticks()); }
/// App-compiled binding; no expectation learned from runtime info.
RaspEntryRuleV1 rule(bool report_only) {
  RaspEntryRuleV1 value{};
  value.version = 1;
  value.struct_size = sizeof(value);
  value.route_id = 1;
  value.delivery = 1;
  value.method = 1;
  value.dispatch_class = 1;
  std::ranges::copy(std::string_view("https"), std::span(value.scheme).begin());
  std::ranges::copy(std::string_view("links.example.invalid"), std::span(value.authority).begin());
  std::ranges::copy(std::string_view("/open/help"), std::span(value.path).begin());
  std::ranges::copy(std::string_view("append_demo_receipt"), std::span(value.operation).begin());
  const std::string_view hash = report_only ? "cd463047b2990133678d5afdd887eca134a46a1063c6d3c39b637472a4341fee"
                                            : "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81";
  std::ranges::copy(hash, std::span(value.expected_policy_sha256).begin());
  return value;
}
/// Same reviewed policy as the Android installed consumer.
rasp::Config config(bool report_only) {
  return rasp::parse_config(
      std::string(
          R"({"build_id":"test","checks":["debugger"],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"demo","policy_version":1,"mode":")") +
      (report_only ? "report_only" : "gate") +
      R"(","scope":"host_calls_only","platform":"android","catalogue_id":"2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[{"name":"append_demo_receipt","max_evidence_age_ms":75000,"max_cycle_duration_ms":5000,"rules":[{"rule_id":"native.android.dbg.tracer_pid.proc_status","rule_version":1}]}]}})");
}
/// Confirm the actual report-only candidate is ALLOW while final action stays REPORT.
bool actual_action(const RaspEntryRuleV1& binding, bool report_only) {
  RaspLocalGateRequestV1 request{};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  std::ranges::copy(std::span(binding.operation), std::span(request.operation).begin());
  std::ranges::copy(std::span(binding.expected_policy_sha256), std::span(request.expected_policy_sha256).begin());
  RaspLocalGateResultV1 native{};
  return rasp_local_policy_gate_v1(&request, sizeof(request), &native, sizeof(native)) == 0 && native.status == 0 &&
         native.candidate_action == 2 && native.action == (report_only ? 1U : 2U);
}
/// Replace only collection, letting actual code create and publish the owned typed report.
void publish(const rasp::Config& configuration, rasp::LocalPolicyState* state, std::int64_t tracer,
             rasp::Status status) {
  const std::vector<rasp::Observation> observations{
      {.signal = "dbg.tracer_pid", .source = "proc_status", .status = status, .value = tracer},
      rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{0}),
      rasp::observed("dbg.java_debugger", "debug_api", false),
      rasp::observed("dbg.java_debugger", "jdwp_threads", std::vector<std::string>{}),
  };
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  static_cast<void>(monitor.run(
      configuration, rasp::cycle_catalogue("android"), {}, context,
      [](const rasp::Config&, const void* input) { return *static_cast<const std::vector<rasp::Observation>*>(input); },
      &observations, state));
}
}  // namespace
/// Each process owns one immutable policy, gate or report-only.
int main(int argc, char** /*argv*/) {
  const bool report_only = argc > 1;
  const auto configuration = config(report_only);
  auto binding = rule(report_only);
  constexpr std::string_view kUrl = "https://links.example.invalid/open/help";
  std::array<std::uint8_t, kUrl.size()> url{};
  std::ranges::transform(kUrl, url.begin(), [](char byte) { return static_cast<std::uint8_t>(byte); });
  std::uint32_t receipts = 0;
  const auto dispatch = [&] {
    return entry_demo_open(&binding, url.data(), static_cast<std::uint32_t>(url.size()), &receipts);
  };
  if (dispatch() != 0) {
    return 1;
  }
  auto* state =
      rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(configuration, "android", clock_tick));
  if (state == nullptr || dispatch() != 0) {
    return 2;
  }
  publish(configuration, state, 0, rasp::Status::kOk);
  if (!actual_action(binding, report_only)) {
    return 10;
  }
  if (dispatch() != (report_only ? 0 : 1) || receipts != (report_only ? 0U : 1U)) {
    return 3;
  }
  const std::uint32_t expected = receipts;
  binding.dispatch_class = 4;
  if (dispatch() != 0 || receipts != expected) {
    return 4;
  }
  binding.dispatch_class = 1;
  binding.expected_policy_sha256[0] = '0';
  if (dispatch() != 0 || receipts != expected) {
    return 5;
  }
  binding = rule(report_only);
  publish(configuration, state, 42, rasp::Status::kOk);
  if (dispatch() != 0 || receipts != expected) {
    return 6;
  }
  for (const auto status : {rasp::Status::kUnsupported, rasp::Status::kError, rasp::Status::kTimeout}) {
    publish(configuration, state, 0, status);
    if (dispatch() != 0 || receipts != expected) {
      return 7;
    }
  }
  publish(configuration, state, 0, rasp::Status::kOk);
  ticks() += 75000000001LL;
  if (dispatch() != 0 || receipts != expected) {
    return 8;
  }
  publish(configuration, state, 0, rasp::Status::kOk);
  ticks() = -1;
  if (dispatch() != 0 || receipts != expected) {
    return 9;
  }
  std::puts(report_only ? "PASS actual C consumer/cycle/gate/effect: report-only receipts=0"
                        : "PASS actual C consumer/cycle/gate/effect: gate receipts=1");
  return 0;
}

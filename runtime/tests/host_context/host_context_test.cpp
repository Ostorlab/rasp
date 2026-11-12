/// Host-source context tests use the actual cycle publication, C gate and host mutation.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "clock_math.h"
#include "local_policy_host.h"
#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/host_events.h"
#include "rasp/local_policy.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"

namespace {
/// Controlled platform boundaries, never a replacement gate/evaluator.
std::int64_t& context_tick() {
  static std::int64_t value = 1000000000;
  return value;
}
std::int64_t& native_tick() {
  static std::int64_t value = 1000000000;
  return value;
}
bool& owner_thread() {
  static bool value = true;
  return value;
}
/// Native evidence clock is separate from host-context time.
std::optional<std::int64_t> native_clock() { return native_tick(); }
/// Exact fixture configuration, using an existing supported predicate.
rasp::Config configuration() {
  return rasp::parse_config(
      R"({"build_id":"context","checks":["debugger"],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"demo","policy_version":1,"mode":"gate","scope":"host_calls_only","platform":"android","catalogue_id":"2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[{"name":"append_demo_receipt","max_evidence_age_ms":75000,"max_cycle_duration_ms":5000,"rules":[{"rule_id":"native.android.dbg.tracer_pid.proc_status","rule_version":1}]}]}})");
}
/// Produce actual typed evidence at the collector boundary.
void publish(std::int64_t tracer = 0, rasp::Status status = rasp::Status::kOk) {
  const auto config = configuration();
  auto* state = rasp::process_local_policy();
  if (state == nullptr) {
    state = rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(config, "android", native_clock));
  }
  native_tick() += 1000000000;
  const std::vector<rasp::Observation> rows{
      {.signal = "dbg.tracer_pid", .source = "proc_status", .status = status, .value = tracer},
      rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{0}),
      rasp::observed("dbg.java_debugger", "debug_api", false),
      rasp::observed("dbg.java_debugger", "jdwp_threads", std::vector<std::string>{}),
  };
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  static_cast<void>(monitor.run(
      config, rasp::cycle_catalogue("android"), {}, context,
      [](const rasp::Config&, const void* data) { return *static_cast<const std::vector<rasp::Observation>*>(data); },
      &rows, state));
}
/// Each test owns one finite main-thread flow.
/// Passive fixture-owned values, separate from GoogleTest's protected lifecycle.
struct HostData {
  RaspHostContextV1 owner{};
  RaspHostContextViewV1 view{};
  RaspLocalGateResultV1 decision{};
  RaspHostEventV1 event{};
  int receipts = 0;
};
/// Named event-construction arguments prevent kind/sequence/attempt swaps.
struct EventRequest {
  std::uint32_t kind{};
  std::uint64_t sequence{};
  std::uint32_t attempt = 1;
};
/// Byte snapshot verifies no mutation, including private clocks and counter state.
std::array<std::byte, sizeof(RaspHostContextV1)> owner_image(const RaspHostContextV1& owner) {
  std::array<std::byte, sizeof(RaspHostContextV1)> bytes{};
  std::ranges::copy(std::as_bytes(std::span(&owner, 1)), bytes.begin());
  return bytes;
}
/// Main-thread host fixture; all mutable state belongs to this test instance.
class HostContext : public testing::Test {
 private:
  HostData data_;

 protected:
  /// Return only this fixture's owned values.
  HostData& data() { return data_; }
  /// Initialize an explicit compiled binding and real benign cycle.
  void SetUp() override {
    context_tick() = 1000000000;
    owner_thread() = true;
    publish();
    RaspHostBindingV1 binding{};
    binding.version = 1;
    binding.struct_size = sizeof(binding);
    binding.require_secure_input = 1;
    std::ranges::copy(std::string_view("append_demo_receipt"), std::span(binding.operation).begin());
    const auto hash = rasp::local_policy_hash(configuration().local_policy.canonical_json);
    std::ranges::copy(hash, std::span(binding.expected_policy_sha256).begin());
    ASSERT_EQ(rasp_host_context_init_v1(&data().owner, &binding, sizeof(binding)), 0);
  }
  /// Construct canonical events; tests deliberately alter individual boundary fields.
  static RaspHostEventV1 make(EventRequest request) {
    const auto kind = request.kind;
    const auto sequence = request.sequence;
    const auto attempt = request.attempt;
    RaspHostEventV1 value{};
    value.version = 1;
    value.struct_size = sizeof(value);
    value.kind = kind;
    value.generation = 1;
    value.event_sequence = sequence;
    value.session_ref[0] = 1;
    if (kind == 1) {
      {
        value.lifecycle = 1;
      }
    } else if (kind == 8) {
      {
        value.session_ref[0] = 0;
      }
    } else {
      value.action_ref[0] = 2;
      value.attempt = attempt;
    }
    if (kind == 2 || kind == 3 || kind == 7) {
      value.purpose = 1;
      value.secure_entry = 1;
    }
    if (kind == 5) {
      value.completion = 2;
    }
    return value;
  }
  /// Translate fixed test commands into canonical data independently of reducer internals.
  static RaspHostEventV1 vector_event(const std::string& command, std::uint64_t generation, EventRequest request,
                                      std::uint32_t secure) {
    const auto sequence = request.sequence;
    const auto attempt = request.attempt;

    std::uint32_t kind = 99;
    const std::vector<std::pair<std::string, std::uint32_t>> kinds{
        {"start", 1},  {"begin", 2},  {"input", 3}, {"background", 4}, {"foreground", 4},
        {"cancel", 6}, {"finish", 5}, {"fail", 5},  {"retry", 7},      {"stop", 8},
    };
    for (const auto& [name, number] : kinds) {
      if (command == name) {
        kind = number;
        break;
      }
    }
    auto value = make({.kind = kind, .sequence = sequence, .attempt = attempt});
    value.generation = generation;
    if (kind != 8) {
      value.session_ref[0] = generation == 1 ? 1 : 3;
    }
    if (kind == 2 || kind == 3 || kind == 7) {
      value.secure_entry = secure;
    }
    if (kind == 4) {
      value.lifecycle = command == "foreground" ? 1U : 3U;
      if (attempt == 0) {
        std::ranges::fill(value.action_ref, 0);
      }
    }
    if (command == "finish") {
      value.completion = 1;
    }
    return value;
  }
  /// Apply the actual reducer and retain only an owned readout.
  std::int32_t apply(RaspHostEventV1 value) {
    data().event = value;
    return rasp_host_context_apply_v1(&data().owner, &value, sizeof(value), &data().view, sizeof(data().view));
  }
  /// Begin a canonical flow.
  void begin() {
    ASSERT_EQ(apply(make({.kind = 1, .sequence = 1})), 0);
    ASSERT_EQ(apply(make({.kind = 2, .sequence = 2})), 0);
  }
  /// Actual host effect; no cached or caller-supplied data().decision can append.
  std::int32_t gate(std::uint64_t generation = 1, std::uint64_t sequence = 2, std::uint32_t attempt = 1) {
    const auto status = rasp_host_context_gate_v1(&data().owner, generation, sequence, attempt, &data().view,
                                                  sizeof(data().view), &data().decision, sizeof(data().decision));
    if (status == 0 && data().decision.status == RASP_LOCAL_OK && data().decision.action == RASP_LOCAL_ALLOW) {
      ++data().receipts;
    }
    return status;
  }
};
TEST_F(HostContext, gate_whenNativeAllows_consumesExactlyOnceBeforeReceipt) {
  begin();
  ASSERT_EQ(gate(), 0);
  EXPECT_EQ(data().receipts, 1);
  EXPECT_EQ(data().view.state, 9U);
  EXPECT_NE(gate(), 0);
  EXPECT_EQ(data().decision.abi_version, 0U);
  EXPECT_EQ(data().receipts, 1);
}
TEST_F(HostContext, gate_whenOldTupleOrSecureUnknown_doesNotConsumeCurrentAttempt) {
  begin();
  const auto before = owner_image(data().owner);
  EXPECT_NE(gate(9), 0);
  EXPECT_EQ(before, owner_image(data().owner));
  auto input = make({.kind = 3, .sequence = 3});
  input.secure_entry = 0;
  ASSERT_EQ(apply(input), 0);
  EXPECT_NE(gate(1, 3), 0);
  EXPECT_EQ(data().view.state, 2U);
  EXPECT_EQ(data().receipts, 0);
  ASSERT_EQ(apply(make({.kind = 3, .sequence = 4})), 0);
  EXPECT_EQ(gate(1, 4), 0);
  EXPECT_EQ(data().receipts, 1);
}
TEST_F(HostContext, apply_whenOldOrMalformedForeign_leavesNewFlowUntouched) {
  begin();
  auto replacement = make({.kind = 1, .sequence = 1});
  replacement.generation = 2;
  replacement.session_ref[0] = 3;
  ASSERT_EQ(apply(replacement), 0);
  const auto before = owner_image(data().owner);
  auto old = make({.kind = 3, .sequence = 3});
  EXPECT_NE(apply(old), 0);
  EXPECT_EQ(before, owner_image(data().owner));
  old.kind = 99;
  EXPECT_NE(apply(old), 0);
  EXPECT_EQ(before, owner_image(data().owner));
  auto bad = replacement;
  bad.kind = 99;
  EXPECT_NE(apply(bad), 0);
  EXPECT_EQ(data().view.state, 8U);
}
TEST_F(HostContext, apply_whenGapOrCurrentConflict_faultsWithoutOldBenignFallback) {
  begin();
  EXPECT_NE(apply(make({.kind = 3, .sequence = 4})), 0);
  EXPECT_EQ(data().view.state, 8U);
  EXPECT_NE(gate(), 0);
  EXPECT_EQ(data().receipts, 0);
}
TEST_F(HostContext, gate_whenNativeDeniesOrUnavailable_consumesAndRetryRunsFreshGate) {
  begin();
  publish(42);
  ASSERT_EQ(gate(), 0);
  EXPECT_EQ(data().decision.action, 0U);
  EXPECT_EQ(data().view.state, 9U);
  publish();
  EXPECT_NE(gate(), 0);
  EXPECT_EQ(data().receipts, 0);
  auto const retry = make({.kind = 7, .sequence = 3, .attempt = 2});
  ASSERT_EQ(apply(retry), 0);
  ASSERT_EQ(apply(retry), 1);
  ASSERT_EQ(gate(1, 3, 2), 0);
  EXPECT_EQ(data().receipts, 1);
}
TEST_F(HostContext, gate_whenClockFailsOrExpiry_closesWithoutNativeInvocation) {
  begin();
  context_tick() = -1;
  EXPECT_NE(gate(), 0);
  EXPECT_EQ(data().view.state, 8U);
  EXPECT_EQ(data().decision.abi_version, 0U);
  context_tick() = 2000000000;
  EXPECT_NE(gate(), 0);
  EXPECT_EQ(data().receipts, 0);
}
TEST_F(HostContext, gate_whenEventAgeAtBoundAndOneNanosecondOver_observesExactBoundary) {
  begin();
  context_tick() = 31000000000;
  EXPECT_EQ(gate(), 0);
  EXPECT_EQ(data().receipts, 1);
  ASSERT_EQ(apply(make({.kind = 7, .sequence = 3, .attempt = 2})), 0);
  context_tick() = 61000000001;
  EXPECT_NE(gate(1, 3, 2), 0);
  EXPECT_EQ(data().view.state, 7U);
}
TEST_F(HostContext, apply_whenFinishedCanceledOrBackground_erasesRefsAndCannotReplay) {
  begin();
  auto end = make({.kind = 5, .sequence = 3});
  end.completion = 1;
  ASSERT_EQ(apply(end), 0);
  EXPECT_EQ(data().owner.view.action_ref[0], 0);
  EXPECT_EQ(data().owner.last_event.action_ref[0], 0);
  end.action_ref[0] = 88;
  end.session_ref[0] = 89;
  EXPECT_EQ(apply(end), 1);
  EXPECT_NE(gate(1, 3), 0);
}
TEST_F(HostContext, apply_whenFailedRetried_preservesOnlyBoundedActionAndOriginalAge) {
  begin();
  ASSERT_EQ(apply(make({.kind = 5, .sequence = 3})), 0);
  EXPECT_EQ(data().owner.view.action_ref[0], 2);
  ASSERT_EQ(apply(make({.kind = 7, .sequence = 4, .attempt = 2})), 0);
  ASSERT_EQ(gate(1, 4, 2), 0);
  ASSERT_EQ(apply(make({.kind = 7, .sequence = 5, .attempt = 3})), 0);
  ASSERT_EQ(gate(1, 5, 3), 0);
  EXPECT_NE(apply(make({.kind = 7, .sequence = 6, .attempt = 4})), 0);
  EXPECT_EQ(data().receipts, 2);
}
TEST_F(HostContext, apply_whenWrongThreadOrShortInput_doesNotMutateOwner) {
  begin();
  const auto before = owner_image(data().owner);
  owner_thread() = false;
  EXPECT_NE(gate(), 0);
  owner_thread() = true;
  EXPECT_EQ(before, owner_image(data().owner));
  EXPECT_NE(rasp_host_context_apply_v1(&data().owner, &data().event, 79, &data().view, sizeof(data().view)), 0);
  EXPECT_EQ(before, owner_image(data().owner));
  ASSERT_EQ(rasp_host_context_dispose_v1(&data().owner), 0);
  EXPECT_NE(gate(), 0);
}
TEST_F(HostContext, reduce_whenSharedIndependentVectors_matchFiniteContract) {
  std::ifstream input(RASP_HOST_VECTORS);
  ASSERT_TRUE(input.good());
  std::string line;
  std::string previous;
  while (std::getline(input, line)) {
    if (line.empty() || line.front() == '#') {
      continue;
    }
    std::istringstream fields(line);
    std::string scenario;
    std::string command;
    std::uint64_t generation = 0;
    std::uint64_t sequence = 0;
    std::uint32_t attempt = 0;
    std::uint32_t secure = 0;
    std::uint32_t status = 0;
    std::uint32_t state = 0;
    std::uint32_t called = 0;
    std::uint32_t action = 0;
    std::int64_t tick = 0;
    ASSERT_TRUE(static_cast<bool>(fields >> scenario >> command >> generation >> sequence >> attempt >> secure >>
                                  tick >> status >> state >> called >> action));
    SCOPED_TRACE(line);
    if (scenario != previous) {
      data().owner = {};
      SetUp();
      previous = scenario;
    }
    context_tick() = tick;
    std::int32_t actual = 0;
    data().decision = {};
    if (command == "gate") {
      {
        actual = gate(generation, sequence, attempt);
      }
    } else {
      const auto value =
          vector_event(command, generation, {.kind = 0, .sequence = sequence, .attempt = attempt}, secure);
      actual = apply(value);
    }
    EXPECT_EQ(actual, status);
    EXPECT_EQ(data().view.state, state);
    EXPECT_EQ(data().decision.abi_version != 0, called != 0);
    EXPECT_EQ(data().decision.action, action);
  }
}
TEST_F(HostContext, gate_whenNativeClockUnavailable_consumesEvenWithoutPermit) {
  begin();
  const auto previous = native_tick();
  native_tick() = -1;
  EXPECT_EQ(gate(), 0);
  EXPECT_EQ(data().decision.action, 0U);
  EXPECT_EQ(data().decision.reason, static_cast<std::uint32_t>(RASP_LOCAL_CLOCK_UNAVAILABLE));
  EXPECT_EQ(data().view.state, 9U);
  EXPECT_EQ(data().receipts, 0);
  native_tick() = previous + 1;
  publish();
  EXPECT_EQ(gate(), 10);
  EXPECT_EQ(data().decision.abi_version, 0U);
  ASSERT_EQ(apply(make({.kind = 7, .sequence = 3, .attempt = 2})), 0);
  EXPECT_EQ(gate(1, 3, 2), 0);
  EXPECT_EQ(data().receipts, 1);
}
TEST_F(HostContext, lifecycle_whenAttemptAlreadyConsumed_stillClosesAndErasesFlow) {
  begin();
  ASSERT_EQ(gate(), 0);
  auto background = make({.kind = 4, .sequence = 3});
  background.lifecycle = 3;
  ASSERT_EQ(apply(background), 0);
  EXPECT_EQ(data().view.state, 6U);
  EXPECT_EQ(data().owner.view.session_ref[0], 0);
  EXPECT_EQ(data().owner.last_event.action_ref[0], 0);
}
TEST_F(HostContext, gate_whenActionOrSessionAgeExpires_cannotRefreshLifetimeWithInput) {
  begin();
  for (std::uint64_t seq = 3; seq <= 6; ++seq) {
    context_tick() += 30000000000;
    ASSERT_EQ(apply(make({.kind = 3, .sequence = seq})), 0);
  }
  EXPECT_EQ(gate(1, 6), 0);
  ASSERT_EQ(apply(make({.kind = 7, .sequence = 7, .attempt = 2})), 0);
  ++context_tick();
  EXPECT_EQ(gate(1, 7, 2), 8);
  EXPECT_EQ(data().view.reason, 7U);
}
TEST_F(HostContext, start_whenNewGenerationReusesLiveSessionRef_rejectsWithoutMutation) {
  begin();
  const auto before = owner_image(data().owner);
  auto repeated = make({.kind = 1, .sequence = 1});
  repeated.generation = 2;
  EXPECT_EQ(apply(repeated), 2);
  EXPECT_EQ(before, owner_image(data().owner));
}
TEST(HostContextClock, convert_whenZeroFractionOrMaximumBounds_preservesUnknownAndChecksOverflow) {
  std::int64_t out = -1;
  EXPECT_EQ(rasp_host_clock_convert(0, {.numerator = 1, .denominator = 1}, &out), 1);
  EXPECT_EQ(out, 0);
  EXPECT_EQ(rasp_host_clock_convert(5, {.numerator = 3, .denominator = 2}, &out), 1);
  EXPECT_EQ(out, 7);
  EXPECT_EQ(rasp_host_clock_convert(UINT64_MAX, {.numerator = 1, .denominator = 2}, &out), 1);
  EXPECT_EQ(out, INT64_MAX);
  EXPECT_EQ(rasp_host_clock_convert(UINT64_MAX, {.numerator = 1, .denominator = 1}, &out), 0);
  EXPECT_EQ(rasp_host_clock_convert(INT64_MAX, {.numerator = UINT32_MAX, .denominator = UINT32_MAX}, &out), 1);
  EXPECT_EQ(out, INT64_MAX);
  EXPECT_EQ(rasp_host_clock_convert(1, {.numerator = 0, .denominator = 1}, &out), 0);
  EXPECT_EQ(rasp_host_clock_convert(1, {.numerator = 1, .denominator = 0}, &out), 0);
  EXPECT_EQ(rasp_host_clock_convert(1, {.numerator = 1, .denominator = 1}, nullptr), 0);
}
}  // namespace
/// Test-only host clock boundary.
extern "C" std::int32_t rasp_host_clock_v1(std::int64_t* out) {
  if (context_tick() < 0) {
    return 0;
  }
  *out = context_tick();
  return 1;
}
/// Test-only data().owner-thread boundary.
extern "C" std::int32_t rasp_host_is_owner_thread_v1(void) { return owner_thread() ? 1 : 0; }

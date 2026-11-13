/// Real unchanged platform dispatcher and CycleMonitor must never reach inactive collector identities.
#include <array>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "builtin.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace {
/// Selects the actual platform dispatcher already linked by the capability test graph.
std::vector<rasp::Observation> builtins(const rasp::Config& config, const void* /*argument*/) {
#ifdef RASP_CAPABILITY_ANDROID
  return rasp::android::run_checks(config);
#else
  return rasp::ios::run_checks(config, "");
#endif
}
/// Checks names in both callback forms without introducing a privacy filter.
void assert_absent(std::span<const rasp::Observation> observations) {
  ASSERT_FALSE(observations.empty());
  for (const auto& item : observations) {
    EXPECT_NE(item.signal, "hook.exec_modules");
    EXPECT_NE(item.signal, "hook.exec_modules_meta");
    EXPECT_NE(item.signal, "hook.loader_chain");
    EXPECT_NE(item.signal, "hook.loader_chain_meta");
  }
}
TEST(ProvenanceDormancy, production_whenHooksEnabled_preservesLegacyAndOwningDispatchAbsence) {
  const rasp::Config config{.build_id = std::string(64, 'a'), .checks = std::vector<std::string>{"hooks"}};
  assert_absent(builtins(config, nullptr));
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  constexpr rasp::plugins::Plugin kConsumer{
      .init = nullptr,
      .checks = {},
      .on_observations = [](auto observations, auto&) { assert_absent(observations); },
      .on_cycle = [](const auto& snapshot, auto&) { assert_absent(snapshot->observations); },
  };
  const std::array plugins{&kConsumer};
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  const auto snapshot = monitor.run(config, catalogue, plugins, context, builtins);
  ASSERT_NE(snapshot, nullptr);
  assert_absent(snapshot->observations);
  EXPECT_TRUE(snapshot->metadata.complete);
  EXPECT_EQ(snapshot->metadata.extra, 0U);
}
}  // namespace

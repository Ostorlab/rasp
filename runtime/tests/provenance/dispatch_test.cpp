/// Production dispatch and both callback forms must carry exactly the allocated provenance identities.
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "builtin.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace {
/// Selects the same platform builtin function used by monitoring.
std::vector<rasp::Observation> builtins(const rasp::Config& config, const void* /*argument*/) {
#ifdef RASP_CAPABILITY_ANDROID
  return rasp::android::run_checks(config);
#else
  return rasp::ios::run_checks(config, "");
#endif
}
/// Checks fixed ordered new identities and diagnostic status independently of source availability.
void assert_pairs(std::span<const rasp::Observation> rows) {
#ifdef RASP_CAPABILITY_ANDROID
  constexpr std::array<std::string_view, 3> kSources{
      "proc_maps_v1",
      "dl_iterate_phdr_v1",
      "application_classloader_v1",
  };
  constexpr std::size_t kOld = 5;
#else
  constexpr std::array<std::string_view, 1> kSources{"dyld_v1"};
  constexpr std::size_t kOld = 4;
#endif
  ASSERT_EQ(rows.size(), kOld + (kSources.size() * 2));
  auto additions = rows.subspan(kOld);
  for (const auto source : kSources) {
    const auto* const signal = source == "application_classloader_v1" ? "hook.loader_chain" : "hook.exec_modules";
    EXPECT_EQ(additions[0].signal, signal);
    EXPECT_EQ(additions[0].source, source);
    EXPECT_EQ(additions[1].signal, std::string(signal) + "_meta");
    EXPECT_EQ(additions[1].source, source);
    EXPECT_EQ(additions[1].status, rasp::Status::kOk);
    ASSERT_TRUE(std::holds_alternative<std::string>(additions[1].value));
    EXPECT_LE(std::get<std::string>(additions[1].value).size(), 256U);
    if (additions[0].status != rasp::Status::kOk) {
      EXPECT_TRUE(std::holds_alternative<std::monostate>(additions[0].value));
    }
    additions = additions.subspan(2);
  }
}
TEST(ProvenanceDispatch, hooksSelected_whenProductionRuns_appendsExactPairsAndOwningCallbacks) {
  const rasp::Config config{.build_id = std::string(64, 'a'), .checks = std::vector<std::string>{"hooks"}};
  assert_pairs(builtins(config, nullptr));
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
  constexpr rasp::plugins::Plugin kConsumer{
      .init = nullptr,
      .checks = {},
      .on_observations = [](auto rows, auto&) { assert_pairs(rows); },
      .on_cycle = [](const auto& snapshot, auto&) { assert_pairs(snapshot->observations); },
  };
  const std::array plugins{&kConsumer};
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  const auto snapshot = monitor.run(config, catalogue, plugins, context, builtins);
  ASSERT_NE(snapshot, nullptr);
  assert_pairs(snapshot->observations);
  EXPECT_TRUE(snapshot->metadata.complete);
  EXPECT_EQ(snapshot->metadata.extra, 0U);
}
TEST(ProvenanceDispatch, hooksNotSelected_whenMissingEmptyUnknownOrIdentityOnly_emitsNoNewPairs) {
  for (const auto& selected :
       {std::vector<std::string>{}, std::vector<std::string>{"unknown"}, std::vector<std::string>{"identity"}}) {
    const rasp::Config config{.build_id = "fixture", .checks = selected};
    for (const auto& row : builtins(config, nullptr)) {
      EXPECT_FALSE(row.signal.starts_with("hook.exec_modules"));
      EXPECT_FALSE(row.signal.starts_with("hook.loader_chain"));
    }
  }
  EXPECT_TRUE(builtins({}, nullptr).empty());
}
}  // namespace

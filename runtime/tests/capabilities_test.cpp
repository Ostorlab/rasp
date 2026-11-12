/// Tests production dispatch output identities and kinds against the release catalogue.

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "builtin.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"

namespace {

/// An output identity and its typed value/status contract, generated from the catalogue.
struct Expected {
  /// Group enabling this output.
  std::string_view group;
  /// Observed signal name.
  std::string_view signal;
  /// Observed source name.
  std::string_view source;
  /// Index in the production Value variant.
  std::size_t kind;
  /// Bit mask indexed by the production Status enum.
  unsigned int statuses;
};

#include "capability_expectations.h"

/// Calls the production dispatcher selected by this test target.
[[nodiscard]] std::vector<rasp::Observation> dispatch(const rasp::Config& config) {
#ifdef RASP_CAPABILITY_ANDROID
  return rasp::android::run_checks(config);
#else
  return rasp::ios::run_checks(config, "");
#endif
}

/// Checks an observed identity and its status-dependent value against the catalogue.
void check_observation(std::string_view group, const rasp::Observation& observation) {
  const auto* const expected = std::ranges::find_if(kExpected, [&](const Expected& candidate) {
    return candidate.group == group && candidate.signal == observation.signal && candidate.source == observation.source;
  });
  ASSERT_NE(expected, kExpected.end()) << group << "/" << observation.signal << "/" << observation.source;
  EXPECT_NE(expected->statuses & (1U << static_cast<unsigned int>(observation.status)), 0U);
  EXPECT_EQ(observation.value.index(), observation.status == rasp::Status::kOk ? expected->kind : 0U);
#ifndef __APPLE__
  EXPECT_EQ(observation.status, rasp::Status::kUnsupported);
#endif
}

/// Checks a selected production group has each catalogue observation exactly once.
void check_group(const std::string& group) {
  const rasp::Config config{.build_id = "catalogue-test", .checks = std::vector<std::string>{group}};
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  const auto snapshot = monitor.run(config, catalogue, {}, context,
                                    [](const rasp::Config& selection, const void*) { return dispatch(selection); });
  ASSERT_TRUE(snapshot->metadata.complete);
  ASSERT_TRUE(snapshot->metadata.missing.empty());
  EXPECT_EQ(snapshot->metadata.catalogue_id.size(), 64U);
  const auto& observations = snapshot->observations;
  const auto expected_count = std::ranges::count(kExpected, group, &Expected::group);
  ASSERT_EQ(observations.size(), static_cast<std::size_t>(expected_count)) << group;
  std::set<std::pair<std::string, std::string>> identities;
  for (const rasp::Observation& observation : observations) {
    ASSERT_TRUE(identities.emplace(observation.signal, observation.source).second);
    check_observation(group, observation);
  }
}

TEST(Capabilities, generatedCycleCatalogue_whenCanonical_matchesExactIdentityAndOutputCount) {
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  EXPECT_EQ(catalogue.catalogue_id, kExpectedCatalogueId);
  EXPECT_EQ(catalogue.outputs.size(), kExpected.size());
}

TEST(Capabilities, statusVocabulary_whenGenerated_matchesNativeEnumsIncludingTimeout) {
  ASSERT_EQ(kStatusMasks.size(), 4U);
  EXPECT_EQ(kStatusMasks[0], 1U << static_cast<unsigned>(rasp::Status::kOk));
  EXPECT_EQ(kStatusMasks[1], 1U << static_cast<unsigned>(rasp::Status::kUnsupported));
  EXPECT_EQ(kStatusMasks[2], 1U << static_cast<unsigned>(rasp::Status::kError));
  EXPECT_EQ(kStatusMasks[3], 1U << static_cast<unsigned>(rasp::Status::kTimeout));
}

TEST(Capabilities, statusVocabulary_whenCurrentBuiltinsHaveNoTimeout_doesNotInventDeclarations) {
  for (const Expected& expected : kExpected) {
    EXPECT_EQ(expected.statuses & kStatusMasks[static_cast<std::size_t>(rasp::Status::kTimeout)], 0U);
  }
}

TEST(Capabilities, dispatch_whenGroupEnabled_matchesCatalogueIdentitiesKindsAndStatuses) {
  std::set<std::string> groups;
  for (const Expected& expected : kExpected) {
    groups.emplace(expected.group);
  }
  for (const std::string& group : groups) {
    check_group(group);
  }
}

TEST(Capabilities, dispatch_whenMissingEmptyOrUnknownConfig_returnsNoObservations) {
  EXPECT_TRUE(dispatch({}).empty());
  EXPECT_TRUE(dispatch({.build_id = "test", .checks = std::vector<std::string>{}}).empty());
  EXPECT_TRUE(dispatch({.build_id = "test", .checks = std::vector<std::string>{"unknown"}}).empty());
}

}  // namespace

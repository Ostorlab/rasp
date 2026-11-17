/// Tests for is_check_enabled, which says whether the protected app runs a check group.

#include "rasp/config.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rasp {
namespace {

TEST(Config, isCheckEnabled_whenTheConfigListsNoChecks_returnsFalse) {
  EXPECT_FALSE(is_check_enabled(Config{}, "debugger"));
}

TEST(Config, isCheckEnabled_whenOnlyTheBuildIdIsSet_returnsFalse) {
  const Config config{.build_id = "build-1"};

  EXPECT_FALSE(is_check_enabled(config, "debugger"));
}

TEST(Config, isCheckEnabled_whenTheChecksListTheGroup_returnsTrue) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{"debugger", "root"}};

  EXPECT_TRUE(is_check_enabled(config, "root"));
}

TEST(Config, isCheckEnabled_whenTheChecksDoNotListTheGroup_returnsFalse) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{"debugger", "root"}};

  EXPECT_FALSE(is_check_enabled(config, "hooks"));
}

TEST(Config, isCheckEnabled_whenTheChecksAreEmpty_returnsFalse) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{}};

  EXPECT_FALSE(is_check_enabled(config, "debugger"));
}

TEST(Config, isCheckEnabledByBit_whenTheMaskSetsTheBit_returnsTrue) {
  const Config config{.checks_mask = std::uint64_t{1} << 1};

  EXPECT_TRUE(is_check_enabled(config, 1, "debugger"));
}

TEST(Config, isCheckEnabledByBit_whenTheMaskClearsTheBit_returnsFalse) {
  const Config config{.checks_mask = std::uint64_t{1} << 1};

  EXPECT_FALSE(is_check_enabled(config, 0, "root"));
}

TEST(Config, isCheckEnabledByBit_whenBothMaskAndListAreSet_theMaskWins) {
  const Config config{.checks = std::vector<std::string>{"root"}, .checks_mask = std::uint64_t{0}};

  EXPECT_FALSE(is_check_enabled(config, 0, "root"));
}

TEST(Config, isCheckEnabledByBit_whenOnlyTheListIsSet_readsTheList) {
  const Config config{.checks = std::vector<std::string>{"root", "debugger"}};

  EXPECT_TRUE(is_check_enabled(config, 0, "root"));
  EXPECT_FALSE(is_check_enabled(config, 2, "hooks"));
}

TEST(Config, isCheckEnabledByBit_whenNeitherMaskNorListIsSet_returnsFalse) {
  EXPECT_FALSE(is_check_enabled(Config{}, 1, "debugger"));
}

TEST(Config, isCheckEnabledByBit_whenTheBitDoesNotFitTheMask_returnsFalse) {
  const Config config{.checks = std::vector<std::string>{"debugger"}, .checks_mask = std::uint64_t{1} << 1};

  EXPECT_FALSE(is_check_enabled(config, 64, "debugger"));
}

}  // namespace
}  // namespace rasp

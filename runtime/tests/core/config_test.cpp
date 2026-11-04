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

}  // namespace
}  // namespace rasp

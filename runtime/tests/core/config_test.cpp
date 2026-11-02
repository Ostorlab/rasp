/// Tests for is_check_enabled, which says whether the protected app runs a check group.

#include "rasp/config.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rasp {
namespace {

TEST(Config, isCheckEnabled_whenTheConfigListsNoChecks_returnsTrue) {
  EXPECT_TRUE(is_check_enabled(Config{}, "debugger"));
}

TEST(Config, isCheckEnabled_whenTheChecksListTheGroup_returnsTrue) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{"debugger", "identity"}};

  EXPECT_TRUE(is_check_enabled(config, "identity"));
}

TEST(Config, isCheckEnabled_whenTheChecksDoNotListTheGroup_returnsFalse) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{"debugger", "identity"}};

  EXPECT_FALSE(is_check_enabled(config, "hooks"));
}

TEST(Config, isCheckEnabled_whenTheChecksAreEmpty_returnsFalse) {
  const Config config{.build_id = {}, .checks = std::vector<std::string>{}};

  EXPECT_FALSE(is_check_enabled(config, "identity"));
}

}  // namespace
}  // namespace rasp

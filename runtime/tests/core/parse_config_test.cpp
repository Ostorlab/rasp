/// Tests for parse_config, against the JSON the packer writes and against JSON it never writes.

#include "rasp/parse_config.h"

#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

#include "rasp/config.h"

namespace rasp {
namespace {

TEST(ParseConfig, parseConfig_whenGivenThePackersJson_readsTheBuildId) {
  EXPECT_EQ(parse_config(R"({"build_id":"build-7"})").build_id, "build-7");
}

TEST(ParseConfig, parseConfig_whenTheBuildIdIsEscaped_readsItInUtf8) {
  EXPECT_EQ(parse_config(R"({"build_id":"bühl \"7\""})").build_id, "b\xc3\xbchl \"7\"");
}

TEST(ParseConfig, parseConfig_whenTheObjectHasMembersItDoesNotKnow_ignoresThem) {
  EXPECT_EQ(parse_config(R"({"later":{"a":[1,2]},"build_id":"build-7"})").build_id, "build-7");
}

TEST(ParseConfig, parseConfig_whenTheBuildIdIsMissing_leavesItEmpty) { EXPECT_EQ(parse_config("{}").build_id, ""); }

TEST(ParseConfig, parseConfig_whenTheBuildIdIsNotAString_leavesItEmpty) {
  EXPECT_EQ(parse_config(R"({"build_id":7})").build_id, "");
}

TEST(ParseConfig, parseConfig_whenTheJsonIsNotAnObject_leavesTheBuildIdEmpty) {
  EXPECT_EQ(parse_config(R"(["build_id","build-7"])").build_id, "");
}

TEST(ParseConfig, parseConfig_whenTheJsonIsMalformed_leavesTheBuildIdEmpty) {
  EXPECT_EQ(parse_config(R"({"build_id":"build-7")").build_id, "");
}

TEST(ParseConfig, parseConfig_whenTheJsonIsNotStandard_leavesTheBuildIdEmpty) {
  EXPECT_EQ(parse_config("{/* comment */\"build_id\":\"build-7\"}").build_id, "");
}

TEST(ParseConfig, parseConfig_whenTheTextIsEmpty_leavesTheBuildIdEmpty) { EXPECT_EQ(parse_config("").build_id, ""); }

TEST(ParseConfig, parseConfig_whenGivenThePackersJsonWithChecks_readsTheChecksInOrder) {
  const std::optional<std::vector<std::string>> checks =
      parse_config(R"({"build_id":"build-7","checks":["root","debugger"]})").checks;

  ASSERT_TRUE(checks.has_value());
  EXPECT_EQ(*checks, (std::vector<std::string>{"root", "debugger"}));
}

TEST(ParseConfig, parseConfig_whenTheChecksAreAnEmptyArray_readsNoCheck) {
  const std::optional<std::vector<std::string>> checks = parse_config(R"({"checks":[]})").checks;

  ASSERT_TRUE(checks.has_value());
  EXPECT_TRUE(checks->empty());
}

TEST(ParseConfig, parseConfig_whenAChecksItemIsNotAString_ignoresIt) {
  const std::optional<std::vector<std::string>> checks =
      parse_config(R"({"checks":["debugger",7,null,["hooks"],{"id":"root"},"hooks"]})").checks;

  ASSERT_TRUE(checks.has_value());
  EXPECT_EQ(*checks, (std::vector<std::string>{"debugger", "hooks"}));
}

TEST(ParseConfig, parseConfig_whenTheChecksAreMissing_leavesThemEmpty) {
  EXPECT_FALSE(parse_config(R"({"build_id":"build-7"})").checks.has_value());
}

TEST(ParseConfig, parseConfig_whenTheChecksAreNotAnArray_leavesThemEmpty) {
  EXPECT_FALSE(parse_config(R"({"checks":"debugger"})").checks.has_value());
}

TEST(ParseConfig, parseConfig_whenTheJsonIsMalformed_leavesTheChecksEmpty) {
  EXPECT_FALSE(parse_config(R"({"checks":["debugger"])").checks.has_value());
}

TEST(ParseConfig, parseConfig_whenInputExceedsEmbeddedLimit_refusesSelection) {
  const std::string oversized = std::string(4096, ' ') + R"({"checks":["debugger"]})";
  EXPECT_FALSE(parse_config(oversized).checks.has_value());
}

}  // namespace
}  // namespace rasp

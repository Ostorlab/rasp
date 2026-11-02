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
  EXPECT_EQ(parse_config(R"({"build_id":"build-7","checks":["identity","debugger"]})").checks,
            (std::vector<std::string>{"identity", "debugger"}));
}

TEST(ParseConfig, parseConfig_whenTheChecksAreAnEmptyArray_readsNoCheck) {
  EXPECT_EQ(parse_config(R"({"checks":[]})").checks, std::vector<std::string>{});
}

TEST(ParseConfig, parseConfig_whenAChecksItemIsNotAString_ignoresIt) {
  EXPECT_EQ(parse_config(R"({"checks":["debugger",7,null,["hooks"],{"id":"root"},"identity"]})").checks,
            (std::vector<std::string>{"debugger", "identity"}));
}

TEST(ParseConfig, parseConfig_whenTheChecksAreMissing_leavesThemEmpty) {
  EXPECT_EQ(parse_config(R"({"build_id":"build-7"})").checks, std::nullopt);
}

TEST(ParseConfig, parseConfig_whenTheChecksAreNotAnArray_leavesThemEmpty) {
  EXPECT_EQ(parse_config(R"({"checks":"debugger"})").checks, std::nullopt);
}

TEST(ParseConfig, parseConfig_whenTheJsonIsMalformed_leavesTheChecksEmpty) {
  EXPECT_EQ(parse_config(R"({"checks":["debugger"])").checks, std::nullopt);
}

}  // namespace
}  // namespace rasp

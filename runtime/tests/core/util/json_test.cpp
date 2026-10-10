/// Tests for the JSON string writer.

#include "rasp/util/json.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rasp::json {
namespace {

/// `value` written as a JSON string.
[[nodiscard]] std::string quoted(std::string_view value) {
  std::string out;
  append_string(out, value);
  return out;
}

TEST(Json, appendString_whenTheTextHasQuotesBackslashesAndControlCharacters_escapesThem) {
  EXPECT_EQ(quoted("a\"b\\c\nd\x01"), R"("a\"b\\c\nd\u0001")");
}

TEST(Json, appendString_whenTheTextHasACarriageReturnOrATab_escapesThemWithALetter) {
  EXPECT_EQ(quoted("a\rb\tc"), R"("a\rb\tc")");
}

TEST(Json, appendString_whenTheTextHasControlCharactersFrom0x10To0x1F_writesBothHexDigits) {
  EXPECT_EQ(quoted("\x10"), R"("\u0010")");
  EXPECT_EQ(quoted("\x1a"), R"("\u001a")");
  EXPECT_EQ(quoted("\x1f"), R"("\u001f")");
}

TEST(Json, appendString_whenTheTextIsUtf8_keepsItAsItIs) { EXPECT_EQ(quoted("caf\xc3\xa9"), "\"caf\xc3\xa9\""); }

TEST(Json, appendString_whenTheTextHasTwoThreeAndFourByteCharacters_keepsThemAsTheyAre) {
  EXPECT_EQ(quoted("\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80"), "\"\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"");
}

TEST(Json, appendString_whenCharactersAreAtTheEdgesOfValidUtf8_keepsThemAsTheyAre) {
  EXPECT_EQ(quoted("\xc2\x80"), "\"\xc2\x80\"");
  EXPECT_EQ(quoted("\xe0\xa0\x80"), "\"\xe0\xa0\x80\"");
  EXPECT_EQ(quoted("\xed\x9f\xbf"), "\"\xed\x9f\xbf\"");
  EXPECT_EQ(quoted("\xf0\x90\x80\x80"), "\"\xf0\x90\x80\x80\"");
  EXPECT_EQ(quoted("\xf4\x8f\xbf\xbf"), "\"\xf4\x8f\xbf\xbf\"");
}

TEST(Json, appendString_whenAByteCanNeverBeUtf8_replacesIt) {
  EXPECT_EQ(quoted("a\xff"
                   "b"),
            "\"a\xef\xbf\xbd"
            "b\"");
}

TEST(Json, appendString_whenACharacterIsInAnOverlongForm_replacesEachOfItsBytes) {
  EXPECT_EQ(quoted("\xc0\x80"), "\"\xef\xbf\xbd\xef\xbf\xbd\"");
  EXPECT_EQ(quoted("\xe0\x80\xaf"), "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"");
}

TEST(Json, appendString_whenTheTextHasASurrogate_replacesEachOfItsBytes) {
  EXPECT_EQ(quoted("\xed\xa0\x80"), "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"");
}

TEST(Json, appendString_whenACodePointIsAboveU10FFFF_replacesEachOfItsBytes) {
  EXPECT_EQ(quoted("\xf4\x90\x80\x80"), "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"");
}

TEST(Json, appendString_whenTheTextEndsInTheMiddleOfACharacter_replacesTheBytesLeft) {
  EXPECT_EQ(quoted("a\xe2\x82"), "\"a\xef\xbf\xbd\xef\xbf\xbd\"");
}

TEST(Json, appendString_whenACharacterIsCutShortByAnAsciiByte_replacesTheLeadAndKeepsTheAsciiByte) {
  EXPECT_EQ(quoted("\xe2\x82"
                   "a"),
            "\"\xef\xbf\xbd\xef\xbf\xbd"
            "a\"");
}

TEST(Json, appendString_whenAContinuationByteFollowsNoLeadByte_replacesIt) {
  EXPECT_EQ(quoted("a\x80"
                   "b"),
            "\"a\xef\xbf\xbd"
            "b\"");
}

TEST(Json, appendString_whenTheStringAlreadyHasText_appendsAfterIt) {
  std::string out = "[";
  append_string(out, "a");

  EXPECT_EQ(out, "[\"a\"");
}

}  // namespace
}  // namespace rasp::json

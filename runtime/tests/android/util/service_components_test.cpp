/// Production parser regression controls, also run under native sanitizers without a Java VM.

#include "util/service_components.h"

#include <cstddef>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::util {
namespace {
TEST(ServiceComponents, normalize_whenRelativeOrFull_keepsOneCanonicalService) {
  EXPECT_EQ(normalize_component("org.assist/.Keyboard"), normalize_component("org.assist/org.assist.Keyboard"));
  EXPECT_EQ(normalize_component("org.assist/.Outer$Inner"), "org.assist/org.assist.Outer$Inner");
  EXPECT_NE(normalize_component("org.assist/.A"), normalize_component("org.assist/.B"));
}
TEST(ServiceComponents, normalize_whenMalformedOrUnrepresentable_rejectsRecord) {
  for (const std::string_view raw : {
           "",
           "missing",
           "pkg/",
           "/Class",
           "pkg/.",
           "pkg/.A/B",
           "pkg/.A:",
           "pkg/1A",
           "pkg/..A",
           "pkg/.A\n",
           "pkg/.A capabilities=1",
           "pkg/.É",
           "pkg./Class",
       }) {
    EXPECT_FALSE(normalize_component(raw).has_value()) << raw;
  }
  EXPECT_FALSE(normalize_component(std::string_view("pkg/.A\0Z", 8)).has_value());
}
TEST(ServiceComponents, normalize_whenAtByteBoundary_acceptsExactAndRejectsOverflow) {
  const std::string exact = "p/" + std::string(kMaxComponentBytes - 2, 'A');
  EXPECT_EQ(normalize_component(exact), exact);
  EXPECT_FALSE(normalize_component(exact + "A").has_value());
  EXPECT_FALSE(normalize_component("pkg/." + std::string(kMaxComponentBytes - 5, 'A')).has_value());
}
TEST(ServiceComponents, parse_whenExplicitlyEmptyOrRepeated_sortsFullComponents) {
  EXPECT_EQ(parse_notification_components(""), std::optional(std::vector<std::string>{}));
  EXPECT_EQ(parse_notification_components("z/.B:a/.A:z/z.B:z/.C"),
            std::optional(std::vector<std::string>{"a/a.A", "z/z.B", "z/z.C"}));
}
TEST(ServiceComponents, parse_whenAnyEntryMalformed_discardsPartialResults) {
  for (const std::string_view raw : {":", "p/.A:", ":p/.A", "p/.A::p/.B", "p/.A:bad", "p/.A:p/.B\n"}) {
    EXPECT_FALSE(parse_notification_components(raw).has_value()) << raw;
  }
}
TEST(ServiceComponents, parse_whenDuplicateCountExceedsLimit_rejectsBeforeDeduplication) {
  std::string raw;
  for (std::size_t index = 0; index < kMaxComponents; ++index) {
    if (index > 0) {
      raw += ':';
    }
    raw += "p/.A";
  }
  EXPECT_EQ(parse_notification_components(raw), std::optional(std::vector<std::string>{"p/p.A"}));
  EXPECT_FALSE(parse_notification_components(raw + ":p/.A").has_value());
}
TEST(ServiceComponents, parse_whenRawBytesExceedLimit_doesNotTruncate) {
  EXPECT_FALSE(parse_notification_components(std::string(kMaxObservationBytes + 1, 'a')).has_value());
}
}  // namespace
}  // namespace rasp::android::util

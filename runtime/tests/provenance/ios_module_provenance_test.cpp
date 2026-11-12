/// Dyld parser/race regressions use copied native metadata, never a separate parser implementation.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <variant>
#include <vector>

#include "checks/module_provenance.h"
#include "rasp/observation.h"
#include "rasp/posix/provenance.h"

namespace {
/// Places a little-endian native field in the fixture's known bounded command area.
template <std::integral T>
void field(std::vector<std::uint8_t>& bytes, std::size_t offset, T value, std::size_t size = 4) {
  for (std::size_t index = 0; index < size; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(value) >> (index * 8U));
  }
}
/// Builds an ordinary64-bit image with one executable declared segment.
rasp::ios::checks::ProvenanceImage image() {
  std::vector<std::uint8_t> bytes(104);
  field(bytes, 0, 0xfeedfacf);
  field(bytes, 16, 1);
  field(bytes, 20, 72);
  field(bytes, 32, 0x19);
  field(bytes, 36, 72);
  field(bytes, 56, 0x1000, 8);
  field(bytes, 64, 0x1000, 8);
  field(bytes, 80, 0x800, 8);
  field(bytes, 92, 5);
  return {.name = "/private/app/Test.app/Frameworks/Secret.framework/Secret", .header_address = 0x1000, .bytes = bytes};
}
/// A dyld snapshot whose second pass can change without count changes.
struct Images {
  std::vector<rasp::ios::checks::ProvenanceImage> images{image()};
  unsigned passes = 0;
  bool race = false;
  bool count_limit = false;
  rasp::provenance::Error failure = rasp::provenance::Error::kNone;
};
/// Mirrors the count accessor with explicit source-boundary failures left to individual cases.
rasp::provenance::Result<std::uint32_t> count(void* context, rasp::provenance::Budget& /*budget*/) {
  auto& state = *static_cast<Images*>(context);
  ++state.passes;
  if (state.count_limit) {
    return 4097;
  }
  return static_cast<std::uint32_t>(state.images.size());
}
/// Transfers only owned copied image data at the native boundary.
rasp::provenance::Result<rasp::ios::checks::ProvenanceImage> read_image(void* context, std::uint32_t index,
                                                                        rasp::provenance::Budget& /*budget*/) {
  auto& state = *static_cast<Images*>(context);
  if (state.failure != rasp::provenance::Error::kNone) {
    return std::unexpected(state.failure);
  }
  auto result = state.images[index];
  if (state.race && state.passes > 1) {
    ++result.header_address;
  }
  return result;
}
/// Freezes time so fixtures test structure rather than scheduler latency.
std::int64_t clock() { return 1; }
/// Uses the intended production reducer with controlled native accessor results.
rasp::provenance::Pair collect(Images& images) {
  return rasp::ios::checks::collect_module_provenance(
      {.apk_paths = {}, .native_directory = {}, .bundle_directory = "/private/app/Test.app", .available = true},
      {.context = &images, .count = count, .image = read_image}, clock);
}
TEST(IosModuleProvenance, collect_whenLegitimateFrameworkIsExecutable_reportsDeclaredFlagsWithoutIdentity) {
  Images images;
  const auto result = collect(images);
  ASSERT_EQ(result[0].status, rasp::Status::kOk);
  EXPECT_NE(rasp::describe(result[0]).find("scope=app_location;exec_segments=1;declared_flags=5"), std::string::npos);
  EXPECT_EQ(rasp::describe(result[0]).find("Secret"), std::string::npos);
}
TEST(IosModuleProvenance, collect_whenSameCountImageChanges_reportsRaceWithoutPartialInventory) {
  Images images;
  images.race = true;
  const auto result = collect(images);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(result[1]).find("reason=race"), std::string::npos);
}
TEST(IosModuleProvenance, collect_whenSectionTableEscapesCommand_reportsMalformed) {
  Images images;
  field(images.images[0].bytes, 96, 1);
  EXPECT_EQ(collect(images)[0].status, rasp::Status::kError);
}
TEST(IosModuleProvenance, collect_whenSignedSlideUnderflows_reportsMalformed) {
  Images images;
  images.images[0].slide = -0x2000;
  EXPECT_EQ(collect(images)[0].status, rasp::Status::kError);
}
TEST(IosModuleProvenance, collect_whenImageCountExceedsSourceBudget_returnsInputLimit) {
  Images images;
  images.count_limit = true;
  const auto result = collect(images);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(result[1]).find("reason=input_limit"), std::string::npos);
}
TEST(IosModuleProvenance, collect_whenSampleSaturates_validatesRemainingCommands) {
  Images images;
  images.images.resize(33, image());
  auto result = collect(images);
  ASSERT_EQ(result[0].status, rasp::Status::kOk);
  EXPECT_EQ(std::get<std::vector<std::string>>(result[0].value).size(), 32U);
  EXPECT_NE(rasp::describe(result[1]).find("sample_truncated=1"), std::string::npos);
  field(images.images[32].bytes, 96, 1);
  result = collect(images);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(result[0].value));
}
TEST(IosModuleProvenance, collect_whenSourceFails_preservesUnknownAndTimeoutStatuses) {
  Images images;
  for (const auto failure : {
           rasp::provenance::Error::kDenied,
           rasp::provenance::Error::kCleanup,
           rasp::provenance::Error::kIo,
           rasp::provenance::Error::kUnrecognized,
       }) {
    images.failure = failure;
    const auto result = collect(images);
    EXPECT_EQ(result[0].status, rasp::Status::kError);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result[0].value));
  }
  images.failure = rasp::provenance::Error::kDeadline;
  EXPECT_EQ(collect(images)[0].status, rasp::Status::kTimeout);
  EXPECT_EQ(rasp::ios::checks::collect_module_provenance({}, {})[0].status, rasp::Status::kUnsupported);
}
TEST(IosModuleProvenance, collect_whenCommandHeaderOrNameBoundsFail_returnsNoPartialRows) {
  for (const auto mode : {0, 1, 2, 3, 4}) {
    Images images;
    auto& first = images.images[0];
    if (mode == 0) {
      field(first.bytes, 16, 4097);
    }
    if (mode == 1) {
      field(first.bytes, 20, 65537);
    }
    if (mode == 2) {
      first.name.assign(4096, 'a');
    }
    if (mode == 3) {
      first.bytes.pop_back();
    }
    if (mode == 4) {
      field(first.bytes, 36, 71);
    }
    const auto result = collect(images);
    EXPECT_EQ(result[0].status, rasp::Status::kError) << mode;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result[0].value));
  }
}
TEST(IosModuleProvenance, collect_whenAggregateHeaderBudgetExceeded_rejectsCompleteInventory) {
  auto large = image();
  large.bytes.resize(65568);
  field(large.bytes, 20, 65536);
  field(large.bytes, 32, 2);
  field(large.bytes, 36, 65536);
  Images images;
  images.images.assign(129, large);
  const auto result = collect(images);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(result[1]).find("reason=input_limit"), std::string::npos);
}
}  // namespace

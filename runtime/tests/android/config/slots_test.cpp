#include "config/slots.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

#include "rasp/config.h"

namespace rasp::android::config {
namespace {

TEST(Slots, readers_whenTheLibraryWasNeverPacked_readNothing) {
  const Config config = read_config();

  EXPECT_TRUE(config.build_id.empty());
  EXPECT_FALSE(config.checks_mask.has_value());
  EXPECT_FALSE(fold_program().has_value());
  EXPECT_FALSE(text_digest().has_value());
  EXPECT_FALSE(keystore_share().has_value());
  EXPECT_FALSE(region().has_value());
}

TEST(Slots, decodeConfig_whenTheIdEndsBeforeTheSlot_readsUpToItsZeroByte) {
  std::array<std::uint8_t, kBuildIdSlotSize> build{};
  build.fill(0xA5);
  const std::string id = "release-7";
  std::ranges::copy(id, build.begin());
  build.at(id.size()) = 0;
  const std::array<std::uint8_t, kChecksSlotSize> checks = {0x7F, 0x01, 0, 0, 0, 0, 0, 0x80, 0xEE, 0xEE};

  const Config config = decode_config(build, checks);

  EXPECT_EQ(config.build_id, id);
  EXPECT_EQ(config.checks_mask, std::optional<std::uint64_t>(0x800000000000017FULL));
}

TEST(Slots, unmaskShare_whenGivenTheMaskedShareAndItsPad_returnsTheShare) {
  SlotKey share{};
  SlotKey pad{};
  SlotKey masked{};
  for (std::size_t index = 0; index < share.size(); ++index) {
    share.at(index) = static_cast<std::uint8_t>(index);
    pad.at(index) = static_cast<std::uint8_t>(0xC3U ^ (index * 7U));
    masked.at(index) = static_cast<std::uint8_t>(share.at(index) ^ pad.at(index));
  }

  EXPECT_EQ(unmask_share(masked, pad), share);
}

}  // namespace
}  // namespace rasp::android::config

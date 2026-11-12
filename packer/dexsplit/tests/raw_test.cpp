#include <gtest/gtest.h>

#include <array>

#include "analysis/instruction.hpp"
#include "common/budget.hpp"
#include "raw/byte_writer.hpp"
#include "raw/mutf8.hpp"
#include "raw/opcodes.hpp"
#include "raw/parser.hpp"
#include "raw/parsing_utils.hpp"

namespace dexsplit::test {
TEST(Raw, readUleb_whenFifthByteOverflows_rejectsBeforeTruncation) {
  budget::Scope scope;
  std::array<uint8_t, 5> data{0xff, 0xff, 0xff, 0xff, 0x1f};
  uint32_t offset = 0;
  EXPECT_FALSE(raw::parse_utils::read_uleb128(data, offset).has_value());
}
TEST(Raw, readSleb_whenFifthByteOverflows_rejectsBeforeTruncation) {
  budget::Scope scope;
  std::array<uint8_t, 5> data{0xff, 0xff, 0xff, 0xff, 0x40};
  uint32_t offset = 0;
  EXPECT_FALSE(raw::parse_utils::read_sleb128(data, offset).has_value());
}
TEST(Raw, mutf8_whenStringContainsLoneSurrogate_preservesUtf16Units) {
  budget::Scope scope;
  std::array<uint8_t, 5> data{1, 0xed, 0xa0, 0x80, 0};
  auto result = raw::mutf8::decode_string_data(data, 0);
  ASSERT_TRUE(result.has_value());
  budget::Vector<uint8_t> encoded;
  raw::mutf8::append_mutf8(*result, encoded);
  EXPECT_EQ(encoded, (budget::Vector<uint8_t>{0xed, 0xa0, 0x80}));
}
TEST(Raw, decode_whenUnusedOpcode_refuses) {
  budget::Scope scope;
  std::array<uint16_t, 1> code{0x73};
  EXPECT_FALSE(raw::decode_insn(code, 0).has_value());
  EXPECT_THROW(static_cast<void>(decode_instructions(code)), std::invalid_argument);
}
TEST(Raw, allocate_whenBudgetIsTooSmall_failsBeforeBackingGrowth) {
  auto state = std::make_shared<budget::State>();
  state->max_storage = 64;
  budget::Scope scope(state);
  EXPECT_THROW((budget::Vector<uint8_t>(1024)), budget::Exhausted);
}
TEST(Raw, charge_whenAtApprovedDefaults_rejectsOneMoreWithoutRefund) {
  budget::State state;
  EXPECT_EQ(state.max_work, 64000000U);
  EXPECT_EQ(state.max_storage, 1610612736U);
  EXPECT_EQ(state.max_backing, 536870912U);
  EXPECT_EQ(budget::kDexBytes, 67108864U);
  EXPECT_EQ(budget::kTotalBytes, 268435456U);
  state.charge(64000000U, 1610612736U);
  EXPECT_THROW(state.charge(1, 0), budget::Exhausted);
  EXPECT_THROW(state.charge(0, 1), budget::Exhausted);
  EXPECT_EQ(state.work, 64000000U);
  EXPECT_EQ(state.storage, 1610612736U);
}
TEST(Raw, allocate_whenBackingReachesApprovedDefault_checksAlignmentBeforeGrowth) {
  budget::State state;
  constexpr auto alignment = alignof(std::max_align_t);
  state.backing = 536870912U - alignment;
  void* pointer = nullptr;
  ASSERT_NO_THROW(pointer = state.upstream.allocate(1, alignment));
  EXPECT_EQ(state.backing, 536870912U);
  state.upstream.deallocate(pointer, 1, alignment);
  EXPECT_EQ(state.backing, 536870912U);
  void* refused = nullptr;
  EXPECT_THROW(refused = state.upstream.allocate(1, alignment), budget::Exhausted);
  if (refused != nullptr) {
    state.upstream.deallocate(refused, 1, alignment);
  }
}
TEST(Raw, allocate_whenRetainedPoolOutlivesScopes_remainsBoundedAndReleasesOwner) {
  auto state = std::make_shared<budget::State>();
  std::weak_ptr<budget::State> owner = state;
  state->max_backing = 65536;
  std::size_t previous = state->backing;
  for (int i = 0; i < 64; ++i) {
    budget::Scope scope(state);
    budget::Vector<uint8_t> temporary(1024);
    EXPECT_GE(state->backing, previous);
    EXPECT_LE(state->backing, state->max_backing);
    previous = state->backing;
  }
  {
    budget::Scope scope(state);
    EXPECT_THROW((budget::Vector<uint8_t>(65536)), budget::Exhausted);
  }
  EXPECT_LE(state->backing, state->max_backing);
  EXPECT_GT(state->storage, 64U * 1024U);
  state.reset();
  EXPECT_TRUE(owner.expired());
}
TEST(Raw, put_whenPatchIsOutsideWriter_refusesWithoutWriting) {
  budget::Scope scope;
  raw::ByteWriter writer;
  EXPECT_THROW(writer.put_u32(0, 1), std::out_of_range);
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Raw, encodedArray_whenNestingBoundaryIsExceeded_refusesEvenAnEmptyInnerArray) {
  for (int depth : {64, 65}) {
    budget::Scope scope;
    budget::Vector<uint8_t> bytes{1};
    for (int i = 0; i < depth; ++i) {
      bytes.push_back(0x1c);
      bytes.push_back(i + 1 == depth ? 0 : 1);
    }
    uint32_t offset = 0;
    auto result = raw::parser::parse_encoded_array(bytes, offset);
    EXPECT_EQ(result.has_value(), depth == 64);
  }
}
}  // namespace dexsplit::test

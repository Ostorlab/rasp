#include <gtest/gtest.h>

#include <atomic>
#include <thread>

#include "feature_fixture.hpp"
#include "model/io.hpp"

namespace dexsplit::test {
TEST(Model, roundTrip_whenVersionUsesRealFeature_preservesSemanticsAndStableBytes) {
  for (uint32_t version : {35U, 37U, 38U, 39U, 40U}) {
    budget::Scope scope;
    auto dex = feature_fixture(version);
    if (version == 35) {
      auto& items = dex.classes[0].methods[0].code->items;
      items.insert(items.end() - 1, model::Insn{model::ConstString{0, budget::String("\xED\xA0\x80")}});
    }
    ASSERT_TRUE(model::validate(dex).empty());
    if (version == 37 || version == 38 || version == 39) {
      EXPECT_EQ(model::required_version(dex), version);
    }
    auto bytes = model::write(dex);
    ASSERT_TRUE(bytes.has_value()) << bytes.error().message;
    auto reread = model::read(*bytes);
    ASSERT_TRUE(reread.has_value()) << reread.error().message;
    EXPECT_EQ(reread->version, version);
    EXPECT_EQ(reread->classes.front().methods.front().name, dex.classes.front().methods.front().name);
    EXPECT_EQ(reread->classes.front().annotations, dex.classes.front().annotations);
    EXPECT_EQ(reread->classes.front().fields, dex.classes.front().fields);
    EXPECT_EQ(reread->classes.front().methods.front().code, dex.classes.front().methods.front().code);
    auto second = model::write(*reread);
    ASSERT_TRUE(second.has_value()) << second.error().message;
    EXPECT_EQ(*second, *bytes);
    auto again = model::read(*second);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(*reread, *again);
  }
}
TEST(Model, write_whenFeatureRequiresLaterVersion_refusesRatherThanUpgrading) {
  for (uint32_t version : {37U, 38U, 39U}) {
    budget::Scope scope;
    auto dex = feature_fixture(version);
    dex.version = 35;
    auto result = model::write(dex);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, model::Error::Kind::VersionTooLow);
  }
}
TEST(Model, validate_whenHierarchyCycles_reportsFailureWithoutRecursion) {
  budget::Scope scope;
  auto dex = feature_fixture(35);
  dex.classes[0].superclass = dex.classes[0].type;
  EXPECT_FALSE(model::validate(dex).empty());
}
TEST(Model, validate_whenRegisterIsOutsideFrame_refusesWrite) {
  budget::Scope scope;
  auto dex = feature_fixture(35);
  dex.classes[0].methods[0].code->registers = 0;
  EXPECT_FALSE(model::write(dex).has_value());
}
TEST(Model, write_whenRetriedWithSameRequest_cannotResetWorkAllowance) {
  auto state = std::make_shared<budget::State>();
  budget::Scope scope(state);
  auto dex = feature_fixture(35);
  state->max_work = state->work + 10;
  EXPECT_THROW(static_cast<void>(model::write(dex)), budget::Exhausted);
  EXPECT_THROW(static_cast<void>(model::write(dex)), budget::Exhausted);
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, copy_whenOneMethodIsEdited_preservesOriginalBody) {
  budget::Scope scope;
  auto original = feature_fixture(35);
  auto copy = original;
  copy.classes[0].methods[0].code->registers = 3;
  EXPECT_EQ(original.classes[0].methods[0].code->registers, 2);
  EXPECT_EQ(copy.classes[0].methods[0].code->registers, 3);
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, annotationValues_whenDepthIs64_roundTripAndReject65) {
  for (int depth : {64, 65}) {
    budget::Scope scope;
    auto dex = feature_fixture(35);
    model::Value value{model::Value::Null{}};
    for (int i = 0; i < depth; ++i) {
      model::Value::Array array;
      array.values.push_back(std::move(value));
      value = model::Value{std::move(array)};
    }
    dex.classes[0].annotations[0].annotation.elements[0].value = std::move(value);
    auto output = model::write(dex);
    if (depth == 64) {
      ASSERT_TRUE(output.has_value()) << output.error().message;
      auto parsed = model::read(*output);
      ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
      EXPECT_EQ(parsed->classes[0].annotations, dex.classes[0].annotations);
    } else {
      EXPECT_FALSE(output.has_value());
    }
  }
}
TEST(Model, write_whenScopeExited_retainsOriginalRequestCounters) {
  auto request = std::make_shared<budget::State>();
  model::Dex saved;
  ASSERT_NE(saved.request, nullptr);
  {
    budget::Scope scope(request);
    saved = feature_fixture(35);
    ASSERT_TRUE(model::write(saved).has_value());
  }
  request->max_work = request->work + 1;
  EXPECT_THROW(static_cast<void>(model::write(saved)), budget::Exhausted);
}
TEST(Model, write_whenDebugLocalStateIsInvalid_refusesWithoutEncoding) {
  budget::Scope scope;
  auto dex = feature_fixture(35);
  auto& code = *dex.classes[0].methods[0].code;
  code.items.insert(code.items.begin(), model::LocalEnd{0});
  EXPECT_TRUE(model::write(dex).has_value());
  code.items[0] = model::LocalRestart{0};
  EXPECT_FALSE(model::write(dex).has_value());
  code.items[0] = model::LocalStart{2, model::LocalVariable{}};
  EXPECT_FALSE(model::write(dex).has_value());
  code.items[0] = model::LocalStart{0, model::LocalVariable{}};
  code.items.insert(code.items.begin() + 1, model::LocalEnd{0});
  code.items.insert(code.items.begin() + 2, model::LocalEnd{0});
  code.items.insert(code.items.begin() + 3, model::LocalRestart{0});
  code.items.insert(code.items.begin() + 4, model::LocalRestart{0});
  auto bytes = model::write(dex);
  ASSERT_TRUE(bytes.has_value());
  EXPECT_TRUE(model::read(*bytes).has_value());
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, debugLocals_whenIncomingArgsAreWide_acceptsRedundancyWithoutInventingUpperWordMetadata) {
  for (bool is_static : {true, false}) {
    budget::Scope scope;
    auto dex = feature_fixture(35);
    auto& method = dex.classes[0].methods[0];
    method.access = is_static ? AccessFlags::Public | AccessFlags::Static : AccessFlags::Public;
    method.proto = "(JDI)V";
    auto& code = *method.code;
    code.registers = is_static ? 6 : 7;
    code.parameter_names = {budget::String("wide"), std::nullopt, budget::String("integer")};
    model::Reg first_wide = is_static ? 1 : 2;
    if (!is_static) {
      code.items.insert(code.items.begin(), model::LocalRestart{1});
    }
    code.items.insert(code.items.begin(), model::LocalRestart{first_wide});
    code.items.insert(code.items.begin(), model::LocalEnd{first_wide});
    code.items.insert(code.items.begin(), model::LocalEnd{first_wide});
    auto bytes = model::write(dex);
    ASSERT_TRUE(bytes.has_value()) << bytes.error().message;
    auto read = model::read(*bytes);
    ASSERT_TRUE(read.has_value()) << read.error().message;
    EXPECT_EQ(read->classes[0].methods[0].code->parameter_names, code.parameter_names);
    EXPECT_TRUE(model::write(*read).has_value());
    code.items.insert(code.items.begin(), model::LocalRestart{static_cast<model::Reg>(first_wide + 1)});
    EXPECT_FALSE(model::write(dex).has_value());
  }
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, write_whenThreadsShareRetainedRequest_countsEveryAllocationAndBoundsPool) {
  auto state = std::make_shared<budget::State>();
  budget::Scope scope(state);
  const auto dex = feature_fixture(35);
  auto before_work = state->work;
  auto before_storage = state->storage;
  ASSERT_TRUE(model::write(dex).has_value());
  auto one_work = state->work - before_work;
  auto one_storage = state->storage - before_storage;
  before_work = state->work;
  before_storage = state->storage;
  std::atomic<unsigned> completed = 0;
  auto write = [&] {
    if (model::write(dex).has_value()) {
      ++completed;
    }
  };
  {
    std::jthread first(write);
    std::jthread second(write);
  }
  EXPECT_EQ(completed.load(), 2U);
  EXPECT_EQ(state->work - before_work, 2 * one_work);
  EXPECT_EQ(state->storage - before_storage, 2 * one_storage);
  EXPECT_LE(state->backing, state->max_backing);
}
}  // namespace dexsplit::test

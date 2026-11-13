#include <gtest/gtest.h>

#include <atomic>
#include <fstream>
#include <iterator>
#include <thread>

#include "analysis/analysis_context.hpp"
#include "analysis/class.hpp"
#include "analysis/method.hpp"
#include "feature_fixture.hpp"
#include "model/io.hpp"
#include "raw/constants.hpp"
#include "raw/parser.hpp"

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

namespace dexsplit::test {
TEST(Analysis, typeUse_whenAllContextOwnersExit_ownsExactDescriptor) {
  std::optional<TypeUse> retained;
  std::string expected;
  {
    auto source = model::read_file(DEXSPLIT_FIXTURE);
    ASSERT_TRUE(source.has_value());
    budget::Scope scope(source->request);
    budget::Vector<const model::Dex*> models{&*source};
    auto context = AnalysisContext::from_models(models);
    ASSERT_TRUE(context.has_value());
    for (const auto& cls : context->classes()) {
      for (const auto& method : cls.methods()) {
        auto uses = method.type_uses();
        if (!uses.empty()) {
          retained = uses.front();
          expected = retained->descriptor;
          break;
        }
      }
      if (retained) {
        break;
      }
    }
    ASSERT_TRUE(retained.has_value());
  }
  if (retained.has_value()) {
    EXPECT_EQ(std::string(retained.value().descriptor), expected);
  } else {
    FAIL() << "fixture type use was not retained";
  }
}

TEST(Model, copy_whenOriginalScopeExited_chargesSourceAndRetainsNestedOwners) {
  auto source = model::read_file(DEXSPLIT_FIXTURE);
  ASSERT_TRUE(source.has_value());
  auto owner = source->request;
  auto before = owner->storage;
  auto copy = *source;
  EXPECT_GT(owner->storage, before);
  EXPECT_EQ(copy.request, owner);
  model::Dex assigned;
  assigned = copy;
  EXPECT_EQ(assigned.request, owner);
  source = std::unexpected(model::Error{});
  copy.classes.clear();
  before = owner->storage;
  auto& cls = assigned.classes.front();
  cls.annotations.reserve(cls.annotations.capacity() + 1);
  cls.methods.front().name.append(128, 'x');
  cls.interfaces.emplace_back(128, 'y');
  cls.methods.front().parameter_annotations.emplace_back();
  cls.methods.front().parameter_annotations.back().reserve(4);
  EXPECT_GT(owner->storage, before);
  auto moved = std::move(assigned);
  EXPECT_EQ(moved.request, owner);
  owner->charge(budget::kWork - owner->work, budget::kAllocationBytes - owner->storage);
  EXPECT_THROW((model::Dex(moved)), budget::Exhausted);
  EXPECT_THROW(cls.interfaces.back().append(1024, 'z'), budget::Exhausted);
  EXPECT_THROW(cls.methods.front().parameter_annotations.back().reserve(1024), budget::Exhausted);
}

TEST(Model, copyAndCow_whenRetainedOwnerExhaustedOutsideScope_refuseWithoutFreshAllowance) {
  for (bool unrelated : {false, true}) {
    auto source = model::read_file(DEXSPLIT_FIXTURE);
    ASSERT_TRUE(source.has_value());
    auto owner = source->request;
    auto copy = *source;
    auto assigned = *source;
    auto& code = copy.classes.front().methods.front().code;
    auto& unique_code = assigned.classes.front().methods.front().code;
    static_cast<void>(unique_code->items);
    owner->charge(budget::kWork - owner->work, budget::kAllocationBytes - owner->storage);
    auto other = std::make_shared<budget::State>();
    std::optional<budget::Scope> scope;
    if (unrelated) {
      scope.emplace(other);
    }
    EXPECT_THROW((model::Dex(*source)), budget::Exhausted);
    EXPECT_THROW(assigned = *source, budget::Exhausted);
    EXPECT_THROW(code->registers += 1, budget::Exhausted);
    EXPECT_THROW(unique_code->items.reserve(unique_code->items.capacity() + 1), budget::Exhausted);
    EXPECT_EQ(owner->work, budget::kWork);
    EXPECT_EQ(owner->storage, budget::kAllocationBytes);
    EXPECT_EQ(other->work, 0U);
    EXPECT_EQ(other->storage, 0U);
  }
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, nestedStorage_whenDetachedAndOriginalScopeExited_retainsOwnerForEveryGrowth) {
  auto source = model::read_file(DEXSPLIT_FIXTURE);
  ASSERT_TRUE(source.has_value());
  auto owner = source->request;
  auto copy = *source;
  auto& code = *copy.classes.front().methods.front().code;
  code.tries.emplace_back();
  code.tries.back().catches.emplace_back();
  auto replacement = code;
  model::RegList registers;
  {
    budget::Scope scope(owner);
    registers = model::RegList::range(0, 16);
  }
  auto* moved_from = &copy;
  auto moved = std::move(copy);
  EXPECT_EQ(moved_from->request, owner);
  auto before = owner->storage;
  moved_from->classes.reserve(1);
  EXPECT_GT(owner->storage, before);
  owner->charge(budget::kWork - owner->work, budget::kAllocationBytes - owner->storage);
  EXPECT_THROW(code.tries.back().catches.front().type.append(128, 'x'), budget::Exhausted);
  EXPECT_THROW((model::RegList(registers)), budget::Exhausted);
  EXPECT_THROW(registers.push_back(16), budget::Exhausted);
  EXPECT_THROW((model::CodeValue(std::move(replacement))), budget::Exhausted);
  EXPECT_THROW(moved_from->classes.reserve(2), budget::Exhausted);
  EXPECT_EQ(moved.request, owner);
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, emptySharedAndAnalysisSentinels_whenScopeExits_doNotRetainRequestForever) {
  auto state = std::make_shared<budget::State>();
  std::weak_ptr<budget::State> owner = state;
  {
    budget::Scope scope(state);
    EXPECT_TRUE(model::Shared<budget::String>{}.get().empty());
    EXPECT_TRUE(model::Shared<FieldId>{}.get().name.empty());
    EXPECT_TRUE(model::Shared<MethodId>{}.get().name.empty());
    EXPECT_TRUE(model::Shared<model::EncodedAnnotation>{}.get().elements.empty());
    EXPECT_TRUE(model::Shared<model::CallSite>{}.get().extra_args.empty());
    static_cast<void>(model::Shared<model::MethodHandle>{}.get());
    auto source = model::read_file(DEXSPLIT_FIXTURE);
    ASSERT_TRUE(source.has_value());
    budget::Vector<const model::Dex*> models{&*source};
    auto context = AnalysisContext::from_models(models);
    ASSERT_TRUE(context.has_value());
    bool calls = false;
    for (const auto& cls : context->classes()) {
      for (const auto& method : cls.methods()) {
        calls = !method.calls().empty() || calls;
      }
    }
    EXPECT_TRUE(calls);
  }
  state.reset();
  EXPECT_TRUE(owner.expired());
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, read_whenUnusedMappedCodeIsMalformed_allNativeBoundariesRefuse) {
  std::ifstream input(DEXSPLIT_FIXTURE, std::ios::binary);
  const std::vector<uint8_t> original{std::istreambuf_iterator<char>(input), {}};
  ASSERT_FALSE(original.empty());
  for (int damage = 0; damage < 5; ++damage) {
    budget::Scope scope;
    budget::Vector<uint8_t> bytes(original.begin(), original.end());
    const auto header = raw::parser::parse_header(bytes);
    ASSERT_TRUE(header.has_value());
    const auto map = raw::parser::parse_map_list(bytes, header->map_off);
    ASSERT_TRUE(map.has_value());
    uint32_t code = 0;
    uint32_t tries = 0;
    for (const auto& section : map->items) {
      if (section.type == raw::TYPE_CODE_ITEM) {
        code = section.offset;
        auto at = code;
        for (uint32_t i = 0; i < section.size; ++i) {
          const auto item = raw::parser::parse_code_item(bytes, at);
          ASSERT_TRUE(item.has_value());
          if (item->tries_size != 0) {
            tries = at + 16 + 2 * item->insns_size + 2 * (item->insns_size % 2);
            break;
          }
          at = (item->end_offset + 3) & ~3U;
        }
      }
    }
    ASSERT_NE(code, 0U);
    ASSERT_NE(tries, 0U);
    auto set16 = [&](std::size_t at, uint16_t value) {
      bytes[at] = static_cast<uint8_t>(value);
      bytes[at + 1] = static_cast<uint8_t>(value >> 8);
    };
    auto set32 = [&](std::size_t at, uint32_t value) {
      set16(at, static_cast<uint16_t>(value));
      set16(at + 2, static_cast<uint16_t>(value >> 16));
    };
    for (uint32_t i = 0; i < header->class_defs_size; ++i) {
      for (uint32_t field : {20U, 24U, 28U}) {
        set32(header->class_defs_off + i * 32 + field, 0);
      }
    }
    if (damage == 1) {
      set16(code + 16, 0x29);
      set16(code + 18, 0x7fff);
    } else if (damage == 2) {
      set16(code, 0);
    } else if (damage == 3) {
      set16(tries + 4, 0);
    } else if (damage == 4) {
      set16(tries + 6, 0xffff);
    }
    const auto signature = raw::parser::compute_signature(bytes);
    ASSERT_TRUE(signature.has_value());
    std::copy(signature->begin(), signature->end(), bytes.begin() + 12);
    const auto checksum = raw::parser::compute_checksum(bytes);
    ASSERT_TRUE(checksum.has_value());
    set32(8, *checksum);
    EXPECT_EQ(raw::parser::parse_buffer(bytes).has_value(), damage == 0);
    EXPECT_EQ(model::read(bytes).has_value(), damage == 0);
    budget::Vector<std::span<const uint8_t>> buffers{bytes};
    EXPECT_EQ(AnalysisContext::from_dex_buffers(buffers).has_value(), damage == 0);
  }
}
}  // namespace dexsplit::test

namespace dexsplit::test {
TEST(Model, generated_whenConstructedWithoutExplicitScope_retainsOneRequestForNestedValues) {
  auto source = feature_fixture(35);
  auto owner = source.request;
  auto bytes = model::write(source);
  ASSERT_TRUE(bytes.has_value()) << bytes.error().message;
  EXPECT_EQ(source.classes.get_allocator().owner(), owner);
  EXPECT_EQ(source.classes.front().type.get_allocator().owner(), owner);
  EXPECT_EQ(source.classes.front().methods.front().code->items.get_allocator().owner(), owner);
  {
    budget::Scope independent;
    auto separate = feature_fixture(35);
    EXPECT_NE(separate.request, owner);
    EXPECT_EQ(separate.classes.front().type.get_allocator().owner(), separate.request);
  }
  owner->charge(budget::kWork - owner->work, budget::kAllocationBytes - owner->storage);
  EXPECT_THROW(source.classes.front().type.append(128, 'x'), budget::Exhausted);
  EXPECT_THROW((model::Dex(source)), budget::Exhausted);
}
}  // namespace dexsplit::test

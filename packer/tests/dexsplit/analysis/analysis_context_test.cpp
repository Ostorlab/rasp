// Tests for AnalysisContext, run on the files under fixtures/ and on patched copies.

#include "analysis/analysis_context.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "analysis/class.hpp"
#include "analysis/instruction.hpp"
#include "analysis/method.hpp"
#include "common/ids.hpp"
#include "raw/parser.hpp"
#include "support/fixtures.hpp"

namespace dexsplit {
namespace {

using support::load_fixture;

using Files = std::vector<std::vector<uint8_t>>;

// Offsets in classes.dex, from dexdump -h and the bytes of its class_data_item.
constexpr std::size_t kClassesClassDef = 0x130;
constexpr std::size_t kClassesHelloDexCodeOffUleb = 0x32d;

constexpr std::size_t kSuperclassIdx = 8;
constexpr std::size_t kClassDataOff = 24;
constexpr uint32_t kOffsetPastTheFile = 0x00100000;

// Type index of Ljava/lang/String; in classes.dex.
constexpr uint32_t kClassesTypeString = 3;

void put_u32(std::vector<uint8_t> &b, std::size_t off, uint32_t v)
{
    b[off] = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
}

std::vector<std::span<const uint8_t>> spans_of(const Files &files)
{
    return {files.begin(), files.end()};
}

AnalysisContext context_of(const Files &files)
{
    auto context = AnalysisContext::from_dex_buffers(spans_of(files));
    if (!context.has_value())
        throw std::runtime_error(context.error());
    return std::move(*context);
}

std::string error_of(const Files &files)
{
    auto context = AnalysisContext::from_dex_buffers(spans_of(files));
    if (context.has_value())
        throw std::runtime_error("the buffers were accepted");
    return context.error();
}

std::vector<std::string> names_of(const AnalysisContext &context)
{
    std::vector<std::string> names;
    for (const auto &cls : context.classes())
        names.emplace_back(cls.name());
    return names;
}

std::vector<uint8_t> opcodes_of(const Method &method)
{
    std::vector<uint8_t> opcodes;
    for (const auto &insn : method.instructions())
        opcodes.push_back(base_of(insn).opcode);
    return opcodes;
}

std::vector<uint8_t> with_malformed_class_name(std::vector<uint8_t> bytes, std::string_view name)
{
    auto at = std::search(bytes.begin(), bytes.end(), name.begin(), name.end());
    if (at == bytes.end())
        throw std::runtime_error("the fixture has no such class name");
    at[1] = 0xc0;
    at[2] = 0x41;
    return bytes;
}

TEST(AnalysisContext, fromDexBuffers_whenGivenOneDex_returnsAContextOverIt)
{
    auto bytes = load_fixture("classes.dex");

    auto context = AnalysisContext::from_dex_buffers({bytes});

    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_EQ(names_of(*context), (std::vector<std::string>{"LTestDex;"}));
}

TEST(AnalysisContext, fromDexBuffers_whenGivenSeveralDexFiles_returnsOneContextOverAll)
{
    Files files = {load_fixture("classes.dex"), load_fixture("fibonacci.dex"),
                   load_fixture("polymorphic.dex")};

    auto context = AnalysisContext::from_dex_buffers(spans_of(files));

    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_EQ(context->classes().size(), 7u);
}

TEST(AnalysisContext, fromDexBuffers_whenGivenNoBuffer_returnsAContextWithoutClasses)
{
    auto context = AnalysisContext::from_dex_buffers({});

    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_TRUE(context->classes().empty());
}

TEST(AnalysisContext, fromDexBuffers_whenBufferIsEmpty_returnsAnErrorNamingDexZero)
{
    std::string error = error_of({{}});

    EXPECT_TRUE(error.starts_with("dex 0: ")) << error;
}

TEST(AnalysisContext, fromDexBuffers_whenSecondBufferIsInvalid_returnsAnErrorNamingDexOne)
{
    auto cut = load_fixture("fibonacci.dex");
    cut.resize(0x40);

    std::string error = error_of({load_fixture("classes.dex"), cut, load_fixture("shapes.dex")});

    EXPECT_TRUE(error.starts_with("dex 1: ")) << error;
}

TEST(AnalysisContext, fromDexBuffers_whenTwoBuffersAreInvalid_returnsAnErrorNamingTheFirst)
{
    std::vector<uint8_t> garbage(0x70, 0xAB);

    std::string error = error_of({load_fixture("classes.dex"), garbage, {}});

    EXPECT_TRUE(error.starts_with("dex 1: ")) << error;
}

TEST(AnalysisContext, fromDexBuffers_whenBufferIsInvalid_returnsTheParserMessageAfterTheDexIndex)
{
    auto bytes = load_fixture("classes.dex");
    bytes[0] = 'x';
    auto parsed = raw::parser::parse_buffer(bytes);
    ASSERT_FALSE(parsed.has_value());

    std::string error = error_of({bytes});

    EXPECT_EQ(error, "dex 0: " + parsed.error().message);
}

TEST(AnalysisContext, fromDexBuffers_whenMagicIsWrong_returnsAnError)
{
    auto bytes = load_fixture("classes.dex");
    bytes[0] = 'x';

    auto context = AnalysisContext::from_dex_buffers({bytes});

    EXPECT_FALSE(context.has_value());
}

TEST(AnalysisContext, fromDexBuffers_whenHeaderIsCutOff_returnsAnError)
{
    auto bytes = load_fixture("classes.dex");
    bytes.resize(0x40);

    auto context = AnalysisContext::from_dex_buffers({bytes});

    EXPECT_FALSE(context.has_value());
}

TEST(AnalysisContext, fromDexBuffers_whenFileIsCutInHalf_returnsAnError)
{
    auto bytes = load_fixture("classes.dex");
    bytes.resize(bytes.size() / 2);

    auto context = AnalysisContext::from_dex_buffers({bytes});

    EXPECT_FALSE(context.has_value());
}

TEST(AnalysisContext, fromDexBuffers_whenSourceBufferIsOverwrittenAfterwards_readsFromItsOwnCopy)
{
    auto bytes = load_fixture("classes.dex");
    auto context = AnalysisContext::from_dex_buffers({bytes});
    ASSERT_TRUE(context.has_value()) << context.error();

    std::fill(bytes.begin(), bytes.end(), 0xFF);
    bytes.clear();
    bytes.shrink_to_fit();

    auto classes = context->classes();
    ASSERT_EQ(classes.size(), 1u);
    EXPECT_EQ(classes[0].name(), "LTestDex;");
    auto methods = classes[0].methods();
    ASSERT_EQ(methods.size(), 3u);
    EXPECT_EQ(opcodes_of(methods[1]), (std::vector<uint8_t>{0x1a, 0x11}));
}

TEST(AnalysisContext, fromDexBuffers_whenAClassNameIsMalformed_stillReturnsAContext)
{
    auto bytes = with_malformed_class_name(load_fixture("classes.dex"), "LTestDex;");

    auto context = AnalysisContext::from_dex_buffers({bytes});

    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_EQ(context->classes().size(), 1u);
}

TEST(AnalysisContext, fromDexBuffers_whenClassDataOffsetIsOutOfFile_stillReturnsAContext)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kClassDataOff, kOffsetPastTheFile);

    auto context = AnalysisContext::from_dex_buffers({bytes});

    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_EQ(names_of(*context), (std::vector<std::string>{"LTestDex;"}));
}

TEST(AnalysisContext, fromDexBuffers_whenACodeOffsetIsOutOfFile_stillReturnsAContext)
{
    auto bytes = load_fixture("classes.dex");
    bytes[kClassesHelloDexCodeOffUleb] = 0xFF;
    bytes[kClassesHelloDexCodeOffUleb + 1] = 0x7F;

    auto context = AnalysisContext::from_dex_buffers({bytes});

    ASSERT_TRUE(context.has_value()) << context.error();
    auto methods = context->classes().at(0).methods();
    ASSERT_EQ(methods.size(), 3u);
    EXPECT_TRUE(methods[1].instructions().empty());
    EXPECT_EQ(opcodes_of(methods[0]), (std::vector<uint8_t>{0x70, 0x0e}));
}

TEST(AnalysisContext, classes_whenDexHasOneClass_returnsIt)
{
    auto context = context_of({load_fixture("classes.dex")});

    auto classes = context.classes();

    ASSERT_EQ(classes.size(), 1u);
    EXPECT_TRUE(classes[0].is_valid());
    EXPECT_EQ(classes[0].name(), "LTestDex;");
}

// The class_defs order of shapes.dex, which is not the order of its type ids, from dexdump.
TEST(AnalysisContext, classes_whenDexHasSeveralClasses_returnsThemInDefinitionOrder)
{
    auto context = context_of({load_fixture("shapes.dex")});

    EXPECT_EQ(names_of(context),
              (std::vector<std::string>{"LShape;", "LAbstractShape;", "LCircle;", "LRectangle;"}));
}

TEST(AnalysisContext, classes_whenContextHasSeveralDexFiles_returnsThemInFileOrder)
{
    auto context = context_of({load_fixture("polymorphic.dex"), load_fixture("classes.dex")});

    EXPECT_EQ(names_of(context), (std::vector<std::string>{"LAnimal;", "LKennel;", "LPet;", "LCat;",
                                                           "LDog;", "LTestDex;"}));
}

TEST(AnalysisContext, classes_whenTheSameFilesAreGivenInAnotherOrder_followsThatOrder)
{
    auto context = context_of({load_fixture("classes.dex"), load_fixture("polymorphic.dex")});

    EXPECT_EQ(names_of(context), (std::vector<std::string>{"LTestDex;", "LAnimal;", "LKennel;",
                                                           "LPet;", "LCat;", "LDog;"}));
}

TEST(AnalysisContext, classes_whenAProgramIsSplitOverTwoFiles_returnsTheClassesOfBoth)
{
    auto context = context_of({load_fixture("inherit_a.dex"), load_fixture("inherit_b.dex")});

    EXPECT_EQ(names_of(context),
              (std::vector<std::string>{"LBase2;", "LMid2;", "LLeaf2;", "LUseB;"}));
}

TEST(AnalysisContext, classes_whenASuperclassIsDefinedInAnotherFile_namesItByTheSameDescriptor)
{
    auto context = context_of({load_fixture("inherit_a.dex"), load_fixture("inherit_b.dex")});
    auto classes = context.classes();
    ASSERT_EQ(classes.size(), 4u);

    auto superclass = classes[2].superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), classes[1].name());
}

TEST(AnalysisContext, classes_whenAClassIsDefinedInTwoFiles_returnsBothDefinitions)
{
    auto context = context_of({load_fixture("inherit.dex"), load_fixture("inherit_a.dex")});

    auto names = names_of(context);

    ASSERT_EQ(names.size(), 27u);
    EXPECT_EQ(std::count(names.begin(), names.end(), "LBase2;"), 2);
    EXPECT_EQ(std::count(names.begin(), names.end(), "LMid2;"), 2);
    EXPECT_EQ(names[0], "LBase2;");
    EXPECT_EQ(names[25], "LBase2;");
    EXPECT_EQ(names[26], "LMid2;");
}

TEST(AnalysisContext, classes_whenAClassIsDefinedInTwoFiles_readsEachDefinitionFromItsOwnFile)
{
    auto changed = load_fixture("classes.dex");
    put_u32(changed, kClassesClassDef + kSuperclassIdx, kClassesTypeString);
    auto context = context_of({load_fixture("classes.dex"), changed});

    auto classes = context.classes();

    ASSERT_EQ(classes.size(), 2u);
    EXPECT_EQ(classes[0].name(), "LTestDex;");
    EXPECT_EQ(classes[1].name(), "LTestDex;");
    EXPECT_EQ(classes[0].superclass()->descriptor(), "Ljava/lang/Object;");
    EXPECT_EQ(classes[1].superclass()->descriptor(), "Ljava/lang/String;");
}

// proto_ids[2] is (Ljava/lang/String;)V in classes.dex and ()V in shapes.dex.
TEST(AnalysisContext, classes_whenFilesReuseTheSameIndexes_resolvesEachCallInItsOwnFile)
{
    auto context = context_of({load_fixture("classes.dex"), load_fixture("shapes.dex")});
    auto classes = context.classes();
    ASSERT_EQ(classes.size(), 5u);

    auto println = classes[0].methods().at(2).calls().at(1).target;
    auto object_init = classes[2].methods().at(0).calls().at(0).target;

    EXPECT_EQ(println, (MethodId{"Ljava/io/PrintStream;", "println", "(Ljava/lang/String;)V"}));
    EXPECT_EQ(object_init, (MethodId{"Ljava/lang/Object;", "<init>", "()V"}));
}

// Casts.makeArray and Fibonacci.classify both have their code item at 0x140.
TEST(AnalysisContext, classes_whenFilesHaveCodeAtTheSameOffset_decodesEachBodyFromItsOwnFile)
{
    auto context = context_of({load_fixture("casts.dex"), load_fixture("fibonacci.dex")});
    auto classes = context.classes();
    ASSERT_EQ(classes.size(), 2u);

    auto make_array = classes[0].methods().at(2).instructions();
    auto classify = classes[1].methods().at(1).instructions();

    ASSERT_EQ(make_array.size(), 9u);
    ASSERT_EQ(classify.size(), 21u);
    EXPECT_TRUE(std::holds_alternative<TypeInstruction>(make_array[1]));
    EXPECT_TRUE(std::holds_alternative<CompareInstruction>(classify[1]));
}

TEST(AnalysisContext, classes_whenCalledTwice_returnsHandlesToTheSameClasses)
{
    auto context = context_of({load_fixture("shapes.dex")});

    auto first = context.classes();
    auto second = context.classes();

    ASSERT_EQ(first.size(), second.size());
    for (std::size_t i = 0; i < first.size(); ++i)
        EXPECT_EQ(first[i].name(), second[i].name());
}

TEST(AnalysisContext, classes_whenANameIsReadThroughTwoHandles_returnsTheSameDecodedString)
{
    auto context = context_of({load_fixture("classes.dex")});

    std::string_view first = context.classes().at(0).name();
    std::string_view second = context.classes().at(0).name();

    EXPECT_EQ(first, "LTestDex;");
    EXPECT_EQ(first.data(), second.data());
}

TEST(AnalysisContext, classes_whenAMethodIsReadThroughTwoHandles_returnsTheSameDecodedBody)
{
    auto context = context_of({load_fixture("classes.dex")});

    auto first = context.classes().at(0).methods().at(2).instructions();
    auto second = context.classes().at(0).methods().at(2).instructions();

    ASSERT_EQ(first.size(), 5u);
    EXPECT_EQ(first.data(), second.data());
    EXPECT_EQ(first.size(), second.size());
}

TEST(AnalysisContext, classes_whenEveryContextIsDestroyed_keepsItsHandlesUsable)
{
    std::optional<Class> cls;
    {
        auto context = context_of({load_fixture("classes.dex")});
        cls = context.classes().at(0);
    }

    EXPECT_EQ(cls->name(), "LTestDex;");
    auto methods = cls->methods();
    ASSERT_EQ(methods.size(), 3u);
    EXPECT_EQ(opcodes_of(methods[1]), (std::vector<uint8_t>{0x1a, 0x11}));
}

TEST(AnalysisContext, copyConstructor_whenContextIsCopied_sharesTheParsedFilesWithTheCopy)
{
    auto context = context_of({load_fixture("classes.dex")});

    AnalysisContext copy = context;

    EXPECT_EQ(names_of(copy), names_of(context));
    EXPECT_EQ(copy.classes().at(0).name().data(), context.classes().at(0).name().data());
}

TEST(AnalysisContext, copyConstructor_whenTheOriginalIsDestroyed_keepsTheCopyUsable)
{
    std::optional<AnalysisContext> original = context_of({load_fixture("classes.dex")});
    AnalysisContext copy = *original;
    auto cls = copy.classes().at(0);

    original.reset();

    EXPECT_EQ(cls.name(), "LTestDex;");
    EXPECT_EQ(cls.methods().size(), 3u);
    EXPECT_EQ(names_of(copy), (std::vector<std::string>{"LTestDex;"}));
}

class AnalysisContextFixture : public ::testing::TestWithParam<std::string>
{
};

TEST_P(AnalysisContextFixture, fromDexBuffers_whenFileIsWellFormed_succeeds)
{
    auto bytes = load_fixture(GetParam());

    auto context = AnalysisContext::from_dex_buffers({bytes});

    EXPECT_TRUE(context.has_value()) << context.error();
}

TEST_P(AnalysisContextFixture, classes_whenFileIsWellFormed_returnsEveryClassDefInOrder)
{
    auto bytes = load_fixture(GetParam());
    auto dex = raw::parser::parse_buffer(bytes);
    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    std::vector<std::string> expected;
    for (const auto &class_def : dex->class_defs())
        expected.push_back(dex->strings()[dex->type_ids()[class_def.class_idx]]);

    auto context = context_of({bytes});

    EXPECT_EQ(names_of(context), expected);
}

TEST_P(AnalysisContextFixture, classes_whenFileIsWellFormed_decodesEveryMethodBodyToItsEnd)
{
    auto bytes = load_fixture(GetParam());
    auto dex = raw::parser::parse_buffer(bytes);
    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    std::vector<uint32_t> expected;
    for (const auto &class_def : dex->class_defs()) {
        if (class_def.class_data_off == 0)
            continue;
        auto class_data = raw::parser::parse_class_data(bytes, class_def.class_data_off);
        ASSERT_TRUE(class_data.has_value()) << class_data.error().message;
        for (const auto *methods : {&class_data->direct_methods, &class_data->virtual_methods}) {
            for (const auto &method : *methods) {
                if (method.code_off == 0) {
                    expected.push_back(0);
                    continue;
                }
                auto code = raw::parser::parse_code_item(bytes, method.code_off);
                ASSERT_TRUE(code.has_value()) << code.error().message;
                expected.push_back(code->insns_size);
            }
        }
    }

    auto context = context_of({bytes});

    std::vector<uint32_t> decoded;
    for (const auto &cls : context.classes()) {
        for (const auto &method : cls.methods()) {
            auto insns = method.instructions();
            decoded.push_back(
                insns.empty() ? 0 : base_of(insns.back()).offset + base_of(insns.back()).size);
        }
    }
    EXPECT_EQ(decoded, expected);
}

INSTANTIATE_TEST_SUITE_P(AllDexFiles, AnalysisContextFixture,
                         ::testing::Values("annotated.dex", "casts.dex", "classes.dex",
                                           "fibonacci.dex", "inherit.dex", "inherit_a.dex",
                                           "inherit_b.dex", "multistring.dex", "polymorphic.dex",
                                           "sample.dex", "shapes.dex", "trycatch.dex"),
                         [](const testing::TestParamInfo<std::string> &info) {
                             return info.param.substr(0, info.param.rfind('.'));
                         });

} // namespace
} // namespace dexsplit

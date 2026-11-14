// Tests for Class and ClassRef, run on the files under fixtures/ and on patched copies.

#include "analysis/class.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "analysis/analysis_context.hpp"
#include "analysis/analysis_context_impl.hpp"
#include "analysis/class_ref.hpp"
#include "analysis/instruction.hpp"
#include "analysis/method.hpp"
#include "common/ids.hpp"
#include "raw/parser.hpp"
#include "support/fixtures.hpp"

namespace dexsplit {
namespace {

using support::load_fixture;

constexpr std::string_view kChangePassword = "Lcom/android/insecurebankv2/ChangePassword;";

// Offsets of class_def_items and of what they point at, from dexdump -h.
constexpr std::size_t kClassesClassDef = 0x130;
constexpr std::size_t kClassesTypeIds = 0xb4;
constexpr std::size_t kInheritBaseStaticCode = 0x79c;
constexpr std::size_t kSampleBuildConfigClassDef = 0xc68;
constexpr std::size_t kSampleContextAndClassTypeList = 0x1850;
constexpr std::size_t kShapesAbstractShapeClassDef = 0x1d4;
constexpr std::size_t kShapesAbstractShapeInterfaces = 0x380;

constexpr std::size_t kFileSize = 0x20;
constexpr std::size_t kClassIdx = 0;
constexpr std::size_t kSuperclassIdx = 8;
constexpr std::size_t kInterfacesOff = 12;
constexpr std::size_t kClassDataOff = 24;
constexpr std::size_t kTypeListFirstEntry = 4;
constexpr std::size_t kCodeInsns = 16;
constexpr uint32_t kNoIndex = 0xFFFFFFFF;
constexpr uint32_t kOffsetPastTheFile = 0x00100000;

// Sizes of the id tables of classes.dex.
constexpr uint32_t kClassesStringCount = 17;
constexpr uint32_t kClassesTypeCount = 7;

uint32_t get_u32(const std::vector<uint8_t> &b, std::size_t off)
{
    return b[off] | (uint32_t{b[off + 1]} << 8) | (uint32_t{b[off + 2]} << 16) |
           (uint32_t{b[off + 3]} << 24);
}

void put_u16(std::vector<uint8_t> &b, std::size_t off, uint16_t v)
{
    b[off] = v & 0xFF;
    b[off + 1] = v >> 8;
}

void put_u32(std::vector<uint8_t> &b, std::size_t off, uint32_t v)
{
    put_u16(b, off, v & 0xFFFF);
    put_u16(b, off + 2, v >> 16);
}

AnalysisContext context_of(const std::vector<uint8_t> &bytes)
{
    auto context = AnalysisContext::from_dex_buffers({bytes});
    if (!context.has_value())
        throw std::runtime_error(context.error());
    return std::move(*context);
}

Class class_named(const AnalysisContext &context, std::string_view name)
{
    for (const auto &cls : context.classes())
        if (cls.name() == name)
            return cls;
    throw std::runtime_error("class not found: " + std::string(name));
}

Class class_of_fixture(std::string_view fixture, std::string_view name)
{
    return class_named(context_of(load_fixture(fixture)), name);
}

std::vector<std::string> descriptors_of(const std::vector<ClassRef> &refs)
{
    std::vector<std::string> descriptors;
    for (const auto &ref : refs)
        descriptors.emplace_back(ref.descriptor());
    return descriptors;
}

std::vector<std::vector<uint8_t>> opcodes_of(const std::vector<Method> &methods)
{
    std::vector<std::vector<uint8_t>> bodies;
    for (const auto &method : methods) {
        bodies.emplace_back();
        for (const auto &insn : method.instructions())
            bodies.back().push_back(base_of(insn).opcode);
    }
    return bodies;
}

std::shared_ptr<const detail::AnalysisContextImpl> impl_of(std::vector<uint8_t> bytes)
{
    auto impl = std::make_shared<detail::AnalysisContextImpl>();
    detail::ManagedBuffer buffer(std::move(bytes));
    auto dex = raw::parser::parse_buffer(buffer.bytes(), {.decode_strings = false});
    if (!dex.has_value())
        throw std::runtime_error(dex.error().message);
    impl->dex_files_vec.push_back(std::move(*dex));
    impl->slots.push_back(
        std::make_unique<detail::AnalysisContextImpl::DexSlot>(std::move(buffer)));
    return impl;
}

TEST(Class, constructor_whenGivenAClassDefIndex_refersToThatClassDef)
{
    auto impl = impl_of(load_fixture("shapes.dex"));

    Class cls(impl, 0, 2);

    EXPECT_TRUE(cls.is_valid());
    EXPECT_EQ(cls.name(), "LCircle;");
}

TEST(Class, isValid_whenHandleIsDefaultConstructed_returnsFalse)
{
    Class cls;

    EXPECT_FALSE(cls.is_valid());
}

TEST(Class, isValid_whenHandleHasNoImplementation_returnsFalse)
{
    Class cls(nullptr, 0, 0);

    EXPECT_FALSE(cls.is_valid());
}

TEST(Class, isValid_whenHandleComesFromAContext_returnsTrue)
{
    auto context = context_of(load_fixture("shapes.dex"));

    for (const auto &cls : context.classes())
        EXPECT_TRUE(cls.is_valid());
}

TEST(Class, name_whenClassIsInTheDefaultPackage_returnsItsDescriptor)
{
    auto context = context_of(load_fixture("classes.dex"));

    EXPECT_EQ(context.classes().at(0).name(), "LTestDex;");
}

TEST(Class, name_whenClassIsInAPackage_returnsTheFullDescriptor)
{
    auto context = context_of(load_fixture("sample.dex"));

    EXPECT_EQ(context.classes().at(5).name(), kChangePassword);
}

TEST(Class, name_whenClassIsAnInnerClass_returnsTheDescriptorWithItsDollarSign)
{
    auto context = context_of(load_fixture("sample.dex"));

    EXPECT_EQ(context.classes().at(1).name(), "Lcom/android/insecurebankv2/ChangePassword$1;");
}

// The replacements are the ones analysis_test.py writes over the same class name.
TEST(Class, name_whenNameIsMalformedMutf8_returnsAnEmptyString)
{
    const std::vector<std::vector<uint8_t>> replacements = {
        {0xc2, 0x41},
        {0xc0, 0x41},
        {0xe0, 0x81, 0x81},
        {0xf0, 0x9f, 0x98, 0x80},
        {0xed, 0xa0, 0x80, 0xed, 0xb0, 0x41},
    };
    for (const auto &replacement : replacements) {
        auto bytes = load_fixture("sample.dex");
        auto at =
            std::search(bytes.begin(), bytes.end(), kChangePassword.begin(), kChangePassword.end());
        ASSERT_NE(at, bytes.end());
        std::copy(replacement.begin(), replacement.end(), at + 1);
        auto context = context_of(bytes);

        auto classes = context.classes();

        ASSERT_EQ(classes.size(), 12u);
        EXPECT_EQ(classes[5].name(), "") << "replacement of " << replacement.size() << " bytes";
        EXPECT_EQ(classes[4].name(),
                  "Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;");
    }
}

TEST(Class, name_whenClassIndexIsOutOfRange_returnsAnEmptyString)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kClassIdx, kClassesTypeCount);
    auto context = context_of(bytes);

    EXPECT_EQ(context.classes().at(0).name(), "");
}

TEST(Class, name_whenItsTypeNamesAStringOutOfRange_returnsAnEmptyString)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesTypeIds, kClassesStringCount);
    auto context = context_of(bytes);

    EXPECT_EQ(context.classes().at(0).name(), "");
}

TEST(Class, superclass_whenClassExtendsObject_returnsObject)
{
    auto cls = class_of_fixture("classes.dex", "LTestDex;");

    auto superclass = cls.superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "Ljava/lang/Object;");
}

TEST(Class, superclass_whenClassExtendsAClassOfTheSameFile_returnsItsDescriptor)
{
    auto cls = class_of_fixture("shapes.dex", "LCircle;");

    auto superclass = cls.superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "LAbstractShape;");
}

TEST(Class, superclass_whenClassExtendsAFrameworkClass_returnsItsDescriptor)
{
    auto cls = class_of_fixture("sample.dex", kChangePassword);

    auto superclass = cls.superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "Landroid/app/Activity;");
}

TEST(Class, superclass_whenClassIsAnInterface_returnsObject)
{
    auto cls = class_of_fixture("shapes.dex", "LShape;");

    auto superclass = cls.superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "Ljava/lang/Object;");
}

TEST(Class, superclass_whenSuperclassIndexIsNoIndex_returnsNullopt)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kSuperclassIdx, kNoIndex);
    auto context = context_of(bytes);

    EXPECT_FALSE(context.classes().at(0).superclass().has_value());
}

TEST(Class, superclass_whenSuperclassIndexIsOutOfRange_returnsAnEmptyDescriptor)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kSuperclassIdx, kClassesTypeCount);
    auto context = context_of(bytes);

    auto superclass = context.classes().at(0).superclass();

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "");
}

TEST(Class, interfaces_whenClassImplementsNone_returnsEmpty)
{
    auto cls = class_of_fixture("classes.dex", "LTestDex;");

    EXPECT_TRUE(cls.interfaces().empty());
}

TEST(Class, interfaces_whenClassImplementsOneOfTheSameFile_returnsItsDescriptor)
{
    auto cls = class_of_fixture("shapes.dex", "LAbstractShape;");

    EXPECT_EQ(descriptors_of(cls.interfaces()), (std::vector<std::string>{"LShape;"}));
}

TEST(Class, interfaces_whenClassImplementsAFrameworkInterface_returnsItsDescriptor)
{
    auto cls = class_of_fixture("sample.dex", "Lcom/android/insecurebankv2/ChangePassword$1;");

    EXPECT_EQ(descriptors_of(cls.interfaces()),
              (std::vector<std::string>{"Landroid/view/View$OnClickListener;"}));
}

TEST(Class, interfaces_whenAnInterfaceExtendsAnother_returnsTheExtendedOne)
{
    auto cls = class_of_fixture("inherit.dex", "LTagged;");

    EXPECT_EQ(descriptors_of(cls.interfaces()), (std::vector<std::string>{"LNamed;"}));
}

TEST(Class, interfaces_whenSuperclassImplementsAnInterface_returnsOnlyItsOwn)
{
    auto cls = class_of_fixture("shapes.dex", "LCircle;");

    EXPECT_TRUE(cls.interfaces().empty());
}

// The patched file gives BuildConfig the type list of a prototype; dexdump -i shows both entries.
TEST(Class, interfaces_whenClassImplementsSeveral_returnsThemInTypeListOrder)
{
    auto bytes = load_fixture("sample.dex");
    put_u32(bytes, kSampleBuildConfigClassDef + kInterfacesOff, kSampleContextAndClassTypeList);
    auto context = context_of(bytes);

    auto interfaces = context.classes().at(0).interfaces();

    EXPECT_EQ(descriptors_of(interfaces),
              (std::vector<std::string>{"Landroid/content/Context;", "Ljava/lang/Class;"}));
}

TEST(Class, interfaces_whenInterfacesOffsetIsOutOfFile_returnsEmpty)
{
    auto bytes = load_fixture("shapes.dex");
    put_u32(bytes, kShapesAbstractShapeClassDef + kInterfacesOff, kOffsetPastTheFile);
    auto context = context_of(bytes);

    EXPECT_TRUE(context.classes().at(1).interfaces().empty());
}

TEST(Class, interfaces_whenTypeListIsCutOffByTheEndOfTheFile_returnsEmpty)
{
    auto bytes = load_fixture("shapes.dex");
    put_u32(bytes, kShapesAbstractShapeClassDef + kInterfacesOff, get_u32(bytes, kFileSize) - 2);
    auto context = context_of(bytes);

    EXPECT_TRUE(context.classes().at(1).interfaces().empty());
}

TEST(Class, interfaces_whenAnInterfaceTypeIndexIsOutOfRange_returnsAnEmptyDescriptorForIt)
{
    auto bytes = load_fixture("shapes.dex");
    put_u16(bytes, kShapesAbstractShapeInterfaces + kTypeListFirstEntry, 0xFFFF);
    auto context = context_of(bytes);

    auto interfaces = context.classes().at(1).interfaces();

    EXPECT_EQ(descriptors_of(interfaces), (std::vector<std::string>{""}));
}

// Circle has one direct method, <init>, and three virtual ones: area, getRadius, perimeter.
TEST(Class, methods_whenClassHasDirectAndVirtualMethods_returnsThemAll)
{
    auto cls = class_of_fixture("shapes.dex", "LCircle;");

    auto methods = cls.methods();

    const std::vector<std::vector<uint8_t>> expected = {
        {0x70, 0x5a, 0x0e},
        {0x53, 0x18, 0xad, 0xad, 0x10},
        {0x53, 0x10},
        {0x18, 0x53, 0xad, 0x10},
    };
    EXPECT_EQ(opcodes_of(methods), expected);
}

// The method ids of Base are <init>, m, s; s is direct and m virtual.  The patch makes s a nop.
TEST(Class, methods_whenAVirtualMethodHasALowerIdThanADirectOne_returnsTheDirectOneFirst)
{
    auto bytes = load_fixture("inherit.dex");
    put_u16(bytes, kInheritBaseStaticCode + kCodeInsns, 0x0000);
    auto context = context_of(bytes);

    auto methods = class_named(context, "LBase;").methods();

    const std::vector<std::vector<uint8_t>> expected = {{0x70, 0x0e}, {0x00}, {0x0e}};
    EXPECT_EQ(opcodes_of(methods), expected);
}

TEST(Class, methods_whenClassHasOnlyDirectMethods_returnsThem)
{
    auto cls = class_of_fixture("polymorphic.dex", "LKennel;");

    auto methods = cls.methods();

    const std::vector<std::vector<uint8_t>> expected = {
        {0x70, 0x0e},
        {0x6e, 0x0c, 0x11},
        {0x72, 0x0c, 0x11},
    };
    EXPECT_EQ(opcodes_of(methods), expected);
}

TEST(Class, methods_whenClassIsAnInterface_returnsItsAbstractMethods)
{
    auto cls = class_of_fixture("shapes.dex", "LShape;");

    auto methods = cls.methods();

    ASSERT_EQ(methods.size(), 2u);
    EXPECT_TRUE(methods[0].instructions().empty());
    EXPECT_TRUE(methods[1].instructions().empty());
}

TEST(Class, methods_whenClassHasManyMethods_returnsOneHandlePerMethod)
{
    auto cls = class_of_fixture("sample.dex", kChangePassword);

    EXPECT_EQ(cls.methods().size(), 11u);
}

TEST(Class, methods_whenMethodsCallOtherMethods_returnsHandlesThatResolveTheirCalls)
{
    auto cls = class_of_fixture("shapes.dex", "LCircle;");

    auto calls = cls.methods().at(0).calls();

    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].target, (MethodId{"LAbstractShape;", "<init>", "(Ljava/lang/String;)V"}));
}

TEST(Class, methods_whenClassHasNoClassData_returnsEmpty)
{
    auto cls = class_of_fixture("inherit.dex", "LTagged;");

    EXPECT_TRUE(cls.methods().empty());
}

TEST(Class, methods_whenClassDataOffsetIsOutOfFile_returnsEmpty)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kClassDataOff, kOffsetPastTheFile);
    auto context = context_of(bytes);

    EXPECT_TRUE(context.classes().at(0).methods().empty());
}

TEST(Class, methods_whenClassDataIsCutOffByTheEndOfTheFile_returnsEmpty)
{
    auto bytes = load_fixture("classes.dex");
    put_u32(bytes, kClassesClassDef + kClassDataOff, get_u32(bytes, kFileSize) - 1);
    auto context = context_of(bytes);

    EXPECT_TRUE(context.classes().at(0).methods().empty());
}

TEST(Class, methods_whenCalledTwice_returnsHandlesToTheSameBodies)
{
    auto cls = class_of_fixture("classes.dex", "LTestDex;");

    auto first = cls.methods();
    auto second = cls.methods();

    ASSERT_EQ(first.size(), 3u);
    ASSERT_EQ(second.size(), 3u);
    for (std::size_t i = 0; i < first.size(); ++i)
        EXPECT_EQ(first[i].instructions().data(), second[i].instructions().data());
}

TEST(Class, copyConstructor_whenHandleIsCopied_refersToTheSameClass)
{
    auto cls = class_of_fixture("shapes.dex", "LCircle;");

    Class copy = cls;

    EXPECT_TRUE(copy.is_valid());
    EXPECT_EQ(copy.name().data(), cls.name().data());
    EXPECT_EQ(copy.methods().size(), 4u);
}

TEST(Class, classRefDescriptor_whenRefIsBuiltFromADescriptor_returnsIt)
{
    ClassRef ref("Ljava/lang/Object;");

    EXPECT_EQ(ref.descriptor(), "Ljava/lang/Object;");
}

TEST(Class, classRefDescriptor_whenDescriptorIsEmpty_returnsEmpty)
{
    ClassRef ref("");

    EXPECT_TRUE(ref.descriptor().empty());
}

TEST(Class, classRefDescriptor_whenSourceStringIsChangedAfterwards_keepsItsOwnCopy)
{
    std::string source = "LShape;";
    ClassRef ref(source);

    source = "LOther;";

    EXPECT_EQ(ref.descriptor(), "LShape;");
}

TEST(Class, classRefDescriptor_whenRefIsCopied_returnsTheSameDescriptorFromItsOwnStorage)
{
    ClassRef ref("LShape;");

    ClassRef copy = ref;

    EXPECT_EQ(copy.descriptor(), "LShape;");
    EXPECT_NE(copy.descriptor().data(), ref.descriptor().data());
}

TEST(Class, classRefDescriptor_whenRefComesFromAClass_outlivesTheContext)
{
    std::optional<ClassRef> superclass;
    {
        auto context = context_of(load_fixture("shapes.dex"));
        superclass = class_named(context, "LCircle;").superclass();
    }

    ASSERT_TRUE(superclass.has_value());
    EXPECT_EQ(superclass->descriptor(), "LAbstractShape;");
}

} // namespace
} // namespace dexsplit

// Tests for the DEX parser, run on the files under fixtures/ and on malformed input.

#include "raw/parser.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <ios>
#include <string>
#include <vector>

#include "raw/error.hpp"
#include "raw/types.hpp"
#include "support/fixtures.hpp"

namespace dexsplit::raw {
namespace {

using support::fixture_path;
using support::load_fixture;

constexpr std::size_t kMapOff = 0x34;
constexpr std::size_t kStringIdsOff = 0x3C;
constexpr std::size_t kTypeIdsOff = 0x44;
constexpr std::size_t kProtoIdsOff = 0x4C;
constexpr std::size_t kFieldIdsOff = 0x54;
constexpr std::size_t kMethodIdsOff = 0x5C;
constexpr std::size_t kClassDefsOff = 0x64;
constexpr std::size_t kDataOff = 0x6C;

void put_u32(std::vector<uint8_t> &b, std::size_t off, uint32_t v)
{
    b[off] = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
}

void put_uleb_max(std::vector<uint8_t> &b) { b.insert(b.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0x0F}); }

// Expected values for the fixtures are ground truth from baksmali.
TEST(Parser, parseHeader_whenFileIsClassesDex_returnsEveryField)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_header(buf);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const Header &h = result.value();
    uint8_t expected_magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00};
    uint8_t expected_signature[20] = {0x39, 0x16, 0x6b, 0xa6, 0x5b, 0xc2, 0x42, 0xe1, 0xdb, 0x24,
                                      0xc4, 0x22, 0x8a, 0x1a, 0x05, 0x00, 0x41, 0x9f, 0xfd, 0x21};
    EXPECT_EQ(std::memcmp(h.magic, expected_magic, 8), 0);
    EXPECT_EQ(h.checksum, 0x76bd94d4u);
    EXPECT_EQ(std::memcmp(h.signature, expected_signature, 20), 0);
    EXPECT_EQ(h.file_size, 980u);
    EXPECT_EQ(h.header_size, 112u);
    EXPECT_EQ(h.endian_tag, 0x12345678u);
    EXPECT_EQ(h.link_size, 0u);
    EXPECT_EQ(h.link_off, 0u);
    EXPECT_EQ(h.map_off, 820u);
    EXPECT_EQ(h.string_ids_size, 17u);
    EXPECT_EQ(h.string_ids_off, 112u);
    EXPECT_EQ(h.type_ids_size, 7u);
    EXPECT_EQ(h.type_ids_off, 180u);
    EXPECT_EQ(h.proto_ids_size, 4u);
    EXPECT_EQ(h.proto_ids_off, 208u);
    EXPECT_EQ(h.field_ids_size, 1u);
    EXPECT_EQ(h.field_ids_off, 256u);
    EXPECT_EQ(h.method_ids_size, 5u);
    EXPECT_EQ(h.method_ids_off, 264u);
    EXPECT_EQ(h.class_defs_size, 1u);
    EXPECT_EQ(h.class_defs_off, 304u);
    EXPECT_EQ(h.data_size, 644u);
    EXPECT_EQ(h.data_off, 336u);
}

TEST(Parser, parseHeader_whenFileIsMultistringDex_returnsTwentyNineStringIds)
{
    auto buf = load_fixture("multistring.dex");

    auto header = parser::parse_header(buf);

    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->string_ids_size, 29u);
}

TEST(Parser, parseMapList_whenFileIsClassesDex_returnsItemsOrderedByOffset)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_map_list(buf, header->map_off);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const MapList &ml = result.value();
    EXPECT_GT(ml.size, 0u);
    EXPECT_EQ(ml.items.size(), ml.size);
    EXPECT_EQ(ml.items[0].type, 0x0000u);
    EXPECT_EQ(ml.items[0].size, 1u);
    EXPECT_EQ(ml.items[0].offset, 0u);
    uint32_t prev = 0;
    for (const auto &item : ml.items) {
        EXPECT_GE(item.offset, prev);
        prev = item.offset;
    }
}

TEST(Parser, parseStringIds_whenFileIsClassesDex_returnsEveryStringOffset)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_string_ids(buf, header->string_ids_off, header->string_ids_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(*result,
              (std::vector<uint32_t>{0x1c2, 0x1ca, 0x1d9, 0x1dc, 0x1e7, 0x1fe, 0x212, 0x226, 0x23a,
                                     0x248, 0x24b, 0x24f, 0x264, 0x26e, 0x274, 0x279, 0x282}));
}

TEST(Parser, parseTypeIds_whenFileIsClassesDex_returnsEveryDescriptorIndex)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_type_ids(buf, header->type_ids_off, header->type_ids_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(*result, (std::vector<uint32_t>{3, 4, 5, 6, 7, 9, 11}));
}

TEST(Parser, parseProtoIds_whenFileIsClassesDex_returnsEveryPrototype)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_proto_ids(buf, header->proto_ids_off, header->proto_ids_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &ids = result.value();
    ASSERT_EQ(ids.size(), 4u);
    EXPECT_EQ(ids[0].shorty_idx, 2u);
    EXPECT_EQ(ids[0].return_type_idx, 3u);
    EXPECT_EQ(ids[0].parameters_off, 0u);
    EXPECT_EQ(ids[1].shorty_idx, 9u);
    EXPECT_EQ(ids[1].return_type_idx, 5u);
    EXPECT_EQ(ids[1].parameters_off, 0u);
    EXPECT_EQ(ids[2].shorty_idx, 10u);
    EXPECT_EQ(ids[2].return_type_idx, 5u);
    EXPECT_EQ(ids[2].parameters_off, 436u);
    EXPECT_EQ(ids[3].shorty_idx, 10u);
    EXPECT_EQ(ids[3].return_type_idx, 5u);
    EXPECT_EQ(ids[3].parameters_off, 444u);
}

TEST(Parser, parseFieldIds_whenFileIsClassesDex_returnsTheOnlyField)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_field_ids(buf, header->field_ids_off, header->field_ids_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &ids = result.value();
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(ids[0].class_idx, 4u);
    EXPECT_EQ(ids[0].type_idx, 1u);
    EXPECT_EQ(ids[0].name_idx, 14u);
}

TEST(Parser, parseMethodIds_whenFileIsClassesDex_returnsEveryMethod)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_method_ids(buf, header->method_ids_off, header->method_ids_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &ids = result.value();
    ASSERT_EQ(ids.size(), 5u);
    EXPECT_EQ(ids[0].class_idx, 0u);
    EXPECT_EQ(ids[0].proto_idx, 1u);
    EXPECT_EQ(ids[0].name_idx, 0u);
    EXPECT_EQ(ids[1].class_idx, 0u);
    EXPECT_EQ(ids[1].proto_idx, 0u);
    EXPECT_EQ(ids[1].name_idx, 12u);
    EXPECT_EQ(ids[2].class_idx, 0u);
    EXPECT_EQ(ids[2].proto_idx, 3u);
    EXPECT_EQ(ids[2].name_idx, 13u);
    EXPECT_EQ(ids[3].class_idx, 1u);
    EXPECT_EQ(ids[3].proto_idx, 2u);
    EXPECT_EQ(ids[3].name_idx, 15u);
    EXPECT_EQ(ids[4].class_idx, 2u);
    EXPECT_EQ(ids[4].proto_idx, 1u);
    EXPECT_EQ(ids[4].name_idx, 0u);
}

TEST(Parser, parseClassDefs_whenFileIsClassesDex_returnsTheOnlyClass)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_class_defs(buf, header->class_defs_off, header->class_defs_size);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &defs = result.value();
    ASSERT_EQ(defs.size(), 1u);
    EXPECT_EQ(defs[0].class_idx, 0u);
    EXPECT_EQ(defs[0].access_flags, 0x1u);
    EXPECT_EQ(defs[0].superclass_idx, 2u);
    EXPECT_EQ(defs[0].interfaces_off, 0u);
    EXPECT_EQ(defs[0].source_file_idx, 8u);
    EXPECT_EQ(defs[0].annotations_off, 0u);
    EXPECT_EQ(defs[0].class_data_off, 0x321u);
    EXPECT_EQ(defs[0].static_values_off, 0u);
}

TEST(Parser, parseCallSiteIds_whenCountIsZero_returnsAnEmptyList)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_call_site_ids(buf, header->class_defs_off, 0);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(Parser, parseMethodHandles_whenCountIsZero_returnsAnEmptyList)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());

    auto result = parser::parse_method_handles(buf, header->class_defs_off, 0);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(Parser, parseString_whenOffsetIsAStringDataItem_returnsTheStringAndTheNextOffset)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_string(buf, 0x1ca);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->first, "Hello Dex++!!");
    EXPECT_EQ(result->second, 0x1ca + 15u);
}

TEST(Parser, parseStrings_whenFileIsClassesDex_returnsEveryString)
{
    auto buf = load_fixture("classes.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());
    auto ids = parser::parse_string_ids(buf, header->string_ids_off, header->string_ids_size);
    ASSERT_TRUE(ids.has_value());

    auto result = parser::parse_strings(buf, *ids);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &strings = result.value();
    ASSERT_EQ(strings.size(), 17u);
    EXPECT_EQ(strings[0], "<init>");
    EXPECT_EQ(strings[1], "Hello Dex++!!");
    EXPECT_EQ(strings[3], "LTestDex;");
    EXPECT_EQ(strings[12], "helloDex");
    EXPECT_EQ(strings[13], "main");
}

TEST(Parser, parseStrings_whenFileIsMultistringDex_returnsEveryString)
{
    auto buf = load_fixture("multistring.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());
    auto ids = parser::parse_string_ids(buf, header->string_ids_off, header->string_ids_size);
    ASSERT_TRUE(ids.has_value());

    auto result = parser::parse_strings(buf, *ids);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto &strings = result.value();
    ASSERT_EQ(strings.size(), 29u);
    EXPECT_EQ(strings[0], "");
    EXPECT_EQ(strings[1], "<clinit>");
    EXPECT_EQ(strings[2], "<init>");
    EXPECT_EQ(strings[3], "Goodbye, World!");
    EXPECT_EQ(strings[4], "Hello, World!");
    EXPECT_EQ(strings[5], "How are you?");
    EXPECT_EQ(strings[6], "I am fine, thanks!");
    EXPECT_EQ(strings[7], "LMultiStringTest;");
    EXPECT_EQ(strings[16], "answer");
    EXPECT_EQ(strings[17], "emoji");
    EXPECT_EQ(strings[18], "empty");
    EXPECT_EQ(strings[19], "farewell");
    EXPECT_EQ(strings[20], "greeting");
    EXPECT_EQ(strings[21], "main");
    EXPECT_EQ(strings[24], "question");
    EXPECT_EQ(strings[26], "withNull");
}

TEST(Parser, parseStrings_whenStringHasAnEncodedNul_keepsItAsAZeroByte)
{
    auto buf = load_fixture("multistring.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());
    auto ids = parser::parse_string_ids(buf, header->string_ids_off, header->string_ids_size);
    ASSERT_TRUE(ids.has_value());

    auto result = parser::parse_strings(buf, *ids);

    ASSERT_TRUE(result.has_value());
    const std::string &s = result.value()[25];
    EXPECT_EQ(s.size(), 13u);
    EXPECT_EQ(s.substr(0, 4), "test");
    EXPECT_EQ(s[4], '\0');
    EXPECT_EQ(s.substr(5), "embedded");
}

TEST(Parser, parseStrings_whenStringIsAnEmoji_returnsANonEmptyString)
{
    auto buf = load_fixture("multistring.dex");
    auto header = parser::parse_header(buf);
    ASSERT_TRUE(header.has_value());
    auto ids = parser::parse_string_ids(buf, header->string_ids_off, header->string_ids_size);
    ASSERT_TRUE(ids.has_value());

    auto result = parser::parse_strings(buf, *ids);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value()[28].empty());
}

TEST(Parser, parseTypeList_whenProtoHasOneStringParameter_returnsItsTypeIndex)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_type_list(buf, 436);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->size, 1u);
    ASSERT_EQ(result->type_ids.size(), 1u);
    EXPECT_EQ(result->type_ids[0], 3u);
}

TEST(Parser, parseTypeList_whenProtoHasOneStringArrayParameter_returnsItsTypeIndex)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_type_list(buf, 444);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->size, 1u);
    ASSERT_EQ(result->type_ids.size(), 1u);
    EXPECT_EQ(result->type_ids[0], 6u);
}

TEST(Parser, parseTypeList_whenClassImplementsOneInterface_returnsItsTypeIndex)
{
    auto buf = load_fixture("shapes.dex");
    auto dex = parser::parse_buffer(buf);
    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_NE(dex->class_defs()[1].interfaces_off, 0u);

    auto ifaces = parser::parse_type_list(buf, dex->class_defs()[1].interfaces_off);

    ASSERT_TRUE(ifaces.has_value()) << ifaces.error().message;
    EXPECT_EQ(ifaces->size, 1u);
    EXPECT_EQ(ifaces->type_ids[0], 4u);
}

TEST(Parser, parseClassData_whenClassHasOnlyDirectMethods_returnsEachMethod)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_class_data(buf, 0x321);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const ClassDataItem &cd = result.value();
    EXPECT_EQ(cd.static_fields.size(), 0u);
    EXPECT_EQ(cd.instance_fields.size(), 0u);
    ASSERT_EQ(cd.direct_methods.size(), 3u);
    EXPECT_EQ(cd.virtual_methods.size(), 0u);
    EXPECT_EQ(cd.direct_methods[0].method_idx, 0u);
    EXPECT_EQ(cd.direct_methods[0].access_flags, 0x10001u);
    EXPECT_EQ(cd.direct_methods[0].code_off, 0x168u);
    EXPECT_EQ(cd.direct_methods[1].method_idx, 1u);
    EXPECT_EQ(cd.direct_methods[1].access_flags, 0x9u);
    EXPECT_EQ(cd.direct_methods[1].code_off, 0x150u);
    EXPECT_EQ(cd.direct_methods[2].method_idx, 2u);
    EXPECT_EQ(cd.direct_methods[2].access_flags, 0x9u);
    EXPECT_EQ(cd.direct_methods[2].code_off, 0x180u);
}

TEST(Parser, parseClassData_whenClassHasOneProtectedField_returnsItsAccessFlags)
{
    auto buf = load_fixture("shapes.dex");

    auto cd = parser::parse_class_data(buf, 0x516);

    ASSERT_TRUE(cd.has_value()) << cd.error().message;
    EXPECT_EQ(cd->static_fields.size(), 0u);
    ASSERT_EQ(cd->instance_fields.size(), 1u);
    EXPECT_EQ(cd->direct_methods.size(), 1u);
    EXPECT_EQ(cd->virtual_methods.size(), 1u);
    EXPECT_EQ(cd->instance_fields[0].access_flags, 0x4u);
}

TEST(Parser, parseClassData_whenClassHasOnePrivateField_returnsItsAccessFlags)
{
    auto buf = load_fixture("shapes.dex");

    auto cd = parser::parse_class_data(buf, 0x526);

    ASSERT_TRUE(cd.has_value()) << cd.error().message;
    ASSERT_EQ(cd->instance_fields.size(), 1u);
    EXPECT_EQ(cd->direct_methods.size(), 1u);
    EXPECT_EQ(cd->virtual_methods.size(), 3u);
    EXPECT_EQ(cd->instance_fields[0].access_flags, 0x2u);
}

TEST(Parser, parseClassData_whenClassHasTwoPrivateFields_returnsBothAccessFlags)
{
    auto buf = load_fixture("shapes.dex");

    auto cd = parser::parse_class_data(buf, 0x53e);

    ASSERT_TRUE(cd.has_value()) << cd.error().message;
    ASSERT_EQ(cd->instance_fields.size(), 2u);
    EXPECT_EQ(cd->direct_methods.size(), 1u);
    EXPECT_EQ(cd->virtual_methods.size(), 2u);
    EXPECT_EQ(cd->instance_fields[0].access_flags, 0x2u);
    EXPECT_EQ(cd->instance_fields[1].access_flags, 0x2u);
}

TEST(Parser, parseClassData_whenFileIsTrycatchDex_returnsThreeDirectMethods)
{
    auto buf = load_fixture("trycatch.dex");

    auto cd = parser::parse_class_data(buf, 0x451);

    ASSERT_TRUE(cd.has_value()) << cd.error().message;
    EXPECT_EQ(cd->direct_methods.size(), 3u);
    EXPECT_EQ(cd->virtual_methods.size(), 0u);
}

TEST(Parser, parseClassData_whenMethodCountIsHuge_returnsAnError)
{
    std::vector<uint8_t> buf;
    buf.push_back(0x00);
    buf.push_back(0x00);
    put_uleb_max(buf);
    buf.push_back(0x00);

    auto r = parser::parse_class_data(buf, 0);

    EXPECT_FALSE(r.has_value()) << "a 4-billion method count in an 8-byte buffer must fail";
}

TEST(Parser, parseCodeItem_whenMethodHasNoTryBlock_returnsNoTriesAndNoHandlers)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_code_item(buf, 0x168);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const CodeItem &ci = result.value();
    EXPECT_EQ(ci.registers_size, 1u);
    EXPECT_EQ(ci.ins_size, 1u);
    EXPECT_EQ(ci.outs_size, 1u);
    EXPECT_EQ(ci.tries_size, 0u);
    EXPECT_EQ(ci.debug_info_off, 0x1a8u);
    EXPECT_EQ(ci.insns_size, 4u);
    EXPECT_EQ(ci.insns.size(), 4u);
    EXPECT_TRUE(ci.tries.empty());
    EXPECT_TRUE(ci.handlers.empty());
}

TEST(Parser, parseCodeItem_whenMethodHasOneTryBlock_returnsItsRange)
{
    auto buf = load_fixture("trycatch.dex");

    auto ci = parser::parse_code_item(buf, 0x1a8);

    ASSERT_TRUE(ci.has_value()) << ci.error().message;
    EXPECT_EQ(ci->tries_size, 1u);
    ASSERT_EQ(ci->tries.size(), 1u);
    EXPECT_EQ(ci->tries[0].start_addr, 0u);
    EXPECT_EQ(ci->tries[0].insn_count, 1u);
}

TEST(Parser, parseCodeItem_whenMethodCatchesArithmeticException_returnsItsTypeIndex)
{
    auto buf = load_fixture("trycatch.dex");

    auto ci = parser::parse_code_item(buf, 0x1a8);

    ASSERT_TRUE(ci.has_value()) << ci.error().message;
    ASSERT_FALSE(ci->handlers.empty());
    ASSERT_FALSE(ci->handlers[0].handlers.empty());
    EXPECT_EQ(ci->handlers[0].handlers[0].type_idx, 3u);
}

TEST(Parser, parseCodeItem_whenMethodHasTwoTryBlocks_returnsBoth)
{
    auto buf = load_fixture("trycatch.dex");

    auto ci = parser::parse_code_item(buf, 0x1d0);

    ASSERT_TRUE(ci.has_value()) << ci.error().message;
    EXPECT_EQ(ci->tries_size, 2u);
    EXPECT_EQ(ci->tries.size(), 2u);
}

TEST(Parser, parseCodeItem_whenMethodHasOneTryBlock_returnsTheByteOffsetOfItsHandler)
{
    auto buf = load_fixture("trycatch.dex");

    auto ci = parser::parse_code_item(buf, 0x1a8);

    ASSERT_TRUE(ci.has_value()) << ci.error().message;
    ASSERT_EQ(ci->handler_byte_offsets.size(), ci->handlers.size())
        << "handler_byte_offsets must be one-to-one with handlers";
    ASSERT_EQ(ci->tries.size(), 1u);
    bool found = false;
    for (uint32_t off : ci->handler_byte_offsets) {
        if (off == ci->tries[0].handler_off) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "tries[0].handler_off=0x" << std::hex << ci->tries[0].handler_off
                       << " must appear in handler_byte_offsets";
}

TEST(Parser, parseCodeItem_whenCatchHandlerListSizeIsHuge_returnsAnError)
{
    std::vector<uint8_t> buf;
    auto put_u16 = [&](uint16_t v) { buf.insert(buf.end(), {uint8_t(v), uint8_t(v >> 8)}); };
    put_u16(0);
    put_u16(0);
    put_u16(0);
    put_u16(1);
    buf.insert(buf.end(), 4, 0x00);
    buf.insert(buf.end(), 4, 0x00);
    buf.insert(buf.end(), 8, 0x00);
    put_uleb_max(buf);

    auto r = parser::parse_code_item(buf, 0);

    EXPECT_FALSE(r.has_value());
}

TEST(Parser, parseAnnotationsDirectory_whenFieldCountIsHuge_returnsAnError)
{
    std::vector<uint8_t> buf(16, 0x00);
    put_u32(buf, 4, 0xFFFFFFFF);

    auto r = parser::parse_annotations_directory(buf, 0);

    EXPECT_FALSE(r.has_value());
}

TEST(Parser, parseDebugInfo_whenItemUsesEveryOpcode_returnsEachOperand)
{
    // clang-format off
    const std::vector<uint8_t> item = {
        10,
        2, 0, 5,
        DBG_ADVANCE_PC, 3,
        DBG_ADVANCE_LINE, 0x7e,
        DBG_START_LOCAL, 1, 4, 0,
        DBG_START_LOCAL_EXTENDED, 2, 1, 2, 3,
        DBG_END_LOCAL, 1,
        DBG_RESTART_LOCAL, 1,
        DBG_SET_PROLOGUE_END,
        DBG_SET_EPILOGUE_BEGIN,
        DBG_SET_FILE, 0,
        0x1f,
        DBG_END_SEQUENCE,
    };
    // clang-format on

    auto info = parser::parse_debug_info(item, 0);

    ASSERT_TRUE(info.has_value()) << info.error().message;
    EXPECT_EQ(info->line_start, 10u);
    EXPECT_EQ(info->parameter_names, (std::vector<uint32_t>{NO_INDEX, 4}));
    ASSERT_EQ(info->ops.size(), 10u);
    EXPECT_EQ(info->ops[0].opcode, DBG_ADVANCE_PC);
    EXPECT_EQ(info->ops[0].addr_diff, 3u);
    EXPECT_EQ(info->ops[1].line_diff, -2);
    EXPECT_EQ(info->ops[2].reg, 1u);
    EXPECT_EQ(info->ops[2].name_idx, 3u);
    EXPECT_EQ(info->ops[2].type_idx, NO_INDEX);
    EXPECT_EQ(info->ops[3].opcode, DBG_START_LOCAL_EXTENDED);
    EXPECT_EQ(info->ops[3].name_idx, 0u);
    EXPECT_EQ(info->ops[3].type_idx, 1u);
    EXPECT_EQ(info->ops[3].sig_idx, 2u);
    EXPECT_EQ(info->ops[4].opcode, DBG_END_LOCAL);
    EXPECT_EQ(info->ops[5].opcode, DBG_RESTART_LOCAL);
    EXPECT_EQ(info->ops[8].opcode, DBG_SET_FILE);
    EXPECT_EQ(info->ops[8].name_idx, NO_INDEX);
    EXPECT_EQ(info->ops[9].opcode, 0x1f);
}

TEST(Parser, parseDebugInfo_whenEndSequenceIsMissing_returnsAnError)
{
    const std::vector<uint8_t> item = {1, 0, DBG_ADVANCE_PC, 2};

    EXPECT_FALSE(parser::parse_debug_info(item, 0).has_value());
}

TEST(Parser, parseDebugInfo_whenRunOnEveryFixtureMethod_succeeds)
{
    std::size_t parsed = 0;
    for (const char *name : {"classes.dex", "fibonacci.dex"}) {
        auto buf = load_fixture(name);
        auto dex = parser::parse_buffer(buf);
        ASSERT_TRUE(dex.has_value());
        for (const ClassDefItem &cd : dex->class_defs()) {
            if (cd.class_data_off == 0)
                continue;
            auto data = parser::parse_class_data(buf, cd.class_data_off);
            ASSERT_TRUE(data.has_value());
            for (const auto *list : {&data->direct_methods, &data->virtual_methods})
                for (const EncodedMethod &m : *list) {
                    if (m.code_off == 0)
                        continue;
                    auto code = parser::parse_code_item(buf, m.code_off);
                    ASSERT_TRUE(code.has_value());
                    if (code->debug_info_off == 0)
                        continue;
                    auto info = parser::parse_debug_info(buf, code->debug_info_off);
                    ASSERT_TRUE(info.has_value()) << name;
                    ++parsed;
                }
        }
    }

    EXPECT_EQ(parsed, 6u);
}

TEST(Parser, parseBuffer_whenFileIsClassesDex_returnsEverySection)
{
    auto buf = load_fixture("classes.dex");

    auto result = parser::parse_buffer(buf);

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const DexFile &dex = result.value();
    EXPECT_EQ(dex.strings().size(), 17u);
    EXPECT_EQ(dex.type_ids().size(), 7u);
    EXPECT_EQ(dex.proto_ids().size(), 4u);
    EXPECT_EQ(dex.field_ids().size(), 1u);
    EXPECT_EQ(dex.method_ids().size(), 5u);
    EXPECT_EQ(dex.class_defs().size(), 1u);
    EXPECT_TRUE(dex.call_site_ids().empty());
    EXPECT_TRUE(dex.method_handles().empty());
    EXPECT_EQ(dex.strings()[0], "<init>");
    EXPECT_EQ(dex.strings()[1], "Hello Dex++!!");
    EXPECT_EQ(dex.strings()[13], "main");
    EXPECT_EQ(dex.type_ids()[0], 3u);
    EXPECT_EQ(dex.class_defs()[0].class_idx, 0u);
    EXPECT_EQ(dex.header().file_size, 980u);
    EXPECT_GT(dex.map_list().size, 0u);
}

TEST(Parser, parseBuffer_whenAHeaderOffsetIsNearUint32Max_doesNotCrash)
{
    const std::size_t fields[] = {kMapOff,      kStringIdsOff, kTypeIdsOff,   kProtoIdsOff,
                                  kFieldIdsOff, kMethodIdsOff, kClassDefsOff, kDataOff};
    for (std::size_t field : fields) {
        auto buf = load_fixture("classes.dex");
        put_u32(buf, field, 0xFFFFFFFE);

        auto r = parser::parse_buffer(buf, {});

        SUCCEED() << "field 0x" << std::hex << field << (r.has_value() ? " parsed" : " rejected");
    }
}

TEST(Parser, parseBuffer_whenFileIsTruncated_doesNotCrash)
{
    auto full = load_fixture("classes.dex");
    for (std::size_t len = 0; len < full.size(); len += 17) {
        std::vector<uint8_t> trunc(full.begin(), full.begin() + len);

        (void)parser::parse_buffer(trunc, {});
    }

    SUCCEED();
}

TEST(Parser, parseFile_whenFileIsClassesDex_returnsItsStringsAndClasses)
{
    auto result = parser::parse_file(fixture_path("classes.dex"));

    ASSERT_TRUE(result.has_value()) << result.error().message;
    const DexFile &dex = result.value();
    EXPECT_EQ(dex.strings().size(), 17u);
    EXPECT_EQ(dex.class_defs().size(), 1u);
    EXPECT_EQ(dex.strings()[0], "<init>");
    EXPECT_EQ(dex.strings()[1], "Hello Dex++!!");
}

TEST(Parser, parseFile_whenFileDoesNotExist_returnsNullPointer)
{
    auto result = parser::parse_file(fixture_path("nonexistent.dex"));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ParseError::Code::NullPointer);
}

TEST(Parser, parseFile_whenFileIsShapesDex_returnsFourClassDefs)
{
    auto dex = parser::parse_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->class_defs().size(), 4u);
}

TEST(Parser, parseFile_whenFileIsShapesDex_returnsFourFieldIds)
{
    auto dex = parser::parse_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->field_ids().size(), 4u);
}

TEST(Parser, parseFile_whenClassIsAnInterface_returnsTheInterfaceAndAbstractFlags)
{
    auto dex = parser::parse_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->class_defs()[0].access_flags, 0x0600u);
}

TEST(Parser, parseFile_whenClassIsAbstract_returnsOnlyTheAbstractFlag)
{
    auto dex = parser::parse_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->class_defs()[1].access_flags, 0x0400u);
}

TEST(Parser, parseFile_whenClassHasNoModifier_returnsZeroAccessFlags)
{
    auto dex = parser::parse_file(fixture_path("shapes.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->class_defs()[2].access_flags, 0x0u);
    EXPECT_EQ(dex->class_defs()[3].access_flags, 0x0u);
}

TEST(Parser, parseFile_whenFileIsTrycatchDex_returnsOneClassDef)
{
    auto dex = parser::parse_file(fixture_path("trycatch.dex"));

    ASSERT_TRUE(dex.has_value()) << dex.error().message;
    EXPECT_EQ(dex->class_defs().size(), 1u);
}

// polymorphic.dex is left out: the tool that built it left a stale signature.
TEST(Parser, computeChecksum_whenFileIsUnmodified_returnsTheHeaderChecksum)
{
    for (const char *name : {"classes.dex", "inherit.dex", "fibonacci.dex"}) {
        auto buf = load_fixture(name);
        auto header = parser::parse_header(buf);
        ASSERT_TRUE(header.has_value()) << name;

        auto checksum = parser::compute_checksum(buf);

        ASSERT_TRUE(checksum.has_value());
        EXPECT_EQ(*checksum, header->checksum) << name;
    }
}

TEST(Parser, computeSignature_whenFileIsUnmodified_returnsTheHeaderSignature)
{
    for (const char *name : {"classes.dex", "inherit.dex", "fibonacci.dex"}) {
        auto buf = load_fixture(name);
        auto header = parser::parse_header(buf);
        ASSERT_TRUE(header.has_value()) << name;

        auto signature = parser::compute_signature(buf);

        ASSERT_TRUE(signature.has_value());
        EXPECT_TRUE(std::equal(signature->begin(), signature->end(), header->signature)) << name;
    }
}

class ParserFixture : public ::testing::TestWithParam<std::string>
{
};

TEST_P(ParserFixture, parseFile_whenFileIsWellFormed_succeeds)
{
    auto result = parser::parse_file(fixture_path(GetParam()));

    EXPECT_TRUE(result.has_value()) << result.error().message;
}

TEST_P(ParserFixture, parseBuffer_whenFileIsWellFormed_succeeds)
{
    auto buf = load_fixture(GetParam());

    auto result = parser::parse_buffer(buf);

    EXPECT_TRUE(result.has_value()) << result.error().message;
}

TEST_P(ParserFixture, parseBuffer_whenStringDecodingIsOff_returnsStringIdsButNoStrings)
{
    auto buf = load_fixture(GetParam());

    auto lazy = parser::parse_buffer(buf, {.decode_strings = false});

    ASSERT_TRUE(lazy.has_value()) << lazy.error().message;
    EXPECT_TRUE(lazy->strings().empty());
    EXPECT_FALSE(lazy->string_ids().empty());
    auto eager = parser::parse_buffer(buf);
    ASSERT_TRUE(eager.has_value());
    EXPECT_EQ(eager->strings().size(), lazy->string_ids().size());
}

INSTANTIATE_TEST_SUITE_P(AllDexFiles, ParserFixture,
                         ::testing::Values("classes.dex", "multistring.dex", "shapes.dex",
                                           "trycatch.dex", "polymorphic.dex"),
                         [](const ::testing::TestParamInfo<ParserFixture::ParamType> &info) {
                             return info.param.substr(0, info.param.rfind('.'));
                         });

} // namespace
} // namespace dexsplit::raw

#include "common/budget.hpp"
#ifndef DEX_CONSTANTS_H
#define DEX_CONSTANTS_H

#include <cstdint>

namespace dexsplit::raw {

// DEX file magic and endian constants
constexpr std::uint8_t DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00};
constexpr std::uint32_t ENDIAN_CONSTANT = 0x12345678;
constexpr std::uint32_t REVERSE_ENDIAN_CONSTANT = 0x78563412;

// Map item type codes
constexpr std::uint16_t TYPE_HEADER_ITEM = 0x0000;
constexpr std::uint16_t TYPE_STRING_ID_ITEM = 0x0001;
constexpr std::uint16_t TYPE_TYPE_ID_ITEM = 0x0002;
constexpr std::uint16_t TYPE_PROTO_ID_ITEM = 0x0003;
constexpr std::uint16_t TYPE_FIELD_ID_ITEM = 0x0004;
constexpr std::uint16_t TYPE_METHOD_ID_ITEM = 0x0005;
constexpr std::uint16_t TYPE_CLASS_DEF_ITEM = 0x0006;
constexpr std::uint16_t TYPE_CALL_SITE_ID_ITEM = 0x0007;
constexpr std::uint16_t TYPE_METHOD_HANDLE_ITEM = 0x0008;
constexpr std::uint16_t TYPE_MAP_LIST = 0x1000;
constexpr std::uint16_t TYPE_TYPE_LIST = 0x1001;
constexpr std::uint16_t TYPE_ANNOTATION_SET_REF_LIST = 0x1002;
constexpr std::uint16_t TYPE_ANNOTATION_SET_ITEM = 0x1003;
constexpr std::uint16_t TYPE_CLASS_DATA_ITEM = 0x2000;
constexpr std::uint16_t TYPE_CODE_ITEM = 0x2001;
constexpr std::uint16_t TYPE_STRING_DATA_ITEM = 0x2002;
constexpr std::uint16_t TYPE_DEBUG_INFO_ITEM = 0x2003;
constexpr std::uint16_t TYPE_ANNOTATION_ITEM = 0x2004;
constexpr std::uint16_t TYPE_ENCODED_ARRAY_ITEM = 0x2005;
constexpr std::uint16_t TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006;
constexpr std::uint16_t TYPE_HIDDENAPI_CLASS_DATA_ITEM = 0xF000;

}  // namespace dexsplit::raw

#endif  // DEX_CONSTANTS_H

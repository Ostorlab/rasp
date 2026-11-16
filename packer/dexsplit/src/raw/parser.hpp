#ifndef PARSER_HPP
#define PARSER_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "raw/error.hpp"
#include "raw/types.hpp"

namespace dexsplit::raw::parser {

/** Options controlling how much work parse_buffer / parse_file do up front. */
struct ParseOptions
{
    /** Decode the entire string pool into DexFile::strings() during parsing.
     *  Eager by default.  The analysis layer turns this off and decodes
     *  strings lazily on first access, so a malformed string surfaces as an
     *  empty string at its use site instead of failing the whole parse. */
    bool decode_strings = true;
};

/**
 * Parse entire DEX file from file path
 */
std::expected<DexFile, ParseError> parse_file(const std::string &path, ParseOptions options = {});

/**
 * Parse DEX file from buffer
 */
std::expected<DexFile, ParseError> parse_buffer(std::span<const uint8_t> buffer,
                                                ParseOptions options = {});

/**
 * Parse DEX header from buffer
 * @param buf Buffer containing DEX data
 * @param offset Offset to start parsing from
 * @return Header or error
 */
std::expected<Header, ParseError> parse_header(std::span<const uint8_t> buf, uint32_t offset = 0);

/**
 * Parse map list (DEX file index)
 */
std::expected<MapList, ParseError> parse_map_list(std::span<const uint8_t> buf, uint32_t offset);

/** Parse string ID list */
std::expected<std::vector<uint32_t>, ParseError> parse_string_ids(std::span<const uint8_t> buf,
                                                                  uint32_t offset, uint32_t count);

/** Parse type ID list */
std::expected<std::vector<uint32_t>, ParseError> parse_type_ids(std::span<const uint8_t> buf,
                                                                uint32_t offset, uint32_t count);

/** Parse prototype ID list */
std::expected<std::vector<ProtoIdItem>, ParseError>
parse_proto_ids(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse field ID list */
std::expected<std::vector<FieldIdItem>, ParseError>
parse_field_ids(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse method ID list */
std::expected<std::vector<MethodIdItem>, ParseError>
parse_method_ids(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse class definition list */
std::expected<std::vector<ClassDefItem>, ParseError>
parse_class_defs(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse call site ID list */
std::expected<std::vector<CallSiteIdItem>, ParseError>
parse_call_site_ids(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse method handle list */
std::expected<std::vector<MethodHandleItem>, ParseError>
parse_method_handles(std::span<const uint8_t> buf, uint32_t offset, uint32_t count);

/** Parse single string from string data section */
std::expected<std::pair<std::string, uint32_t>, ParseError>
parse_string(std::span<const uint8_t> buf, uint32_t offset);

/** Parse all strings from string data section */
std::expected<std::vector<std::string>, ParseError>
parse_strings(std::span<const uint8_t> buf, const std::vector<uint32_t> &string_ids);

/** Parse type list (used for prototype parameters and class interfaces) */
std::expected<TypeList, ParseError> parse_type_list(std::span<const uint8_t> buf, uint32_t offset);

/** Parse class data item (fields and methods of a class) */
std::expected<ClassDataItem, ParseError> parse_class_data(std::span<const uint8_t> buf,
                                                          uint32_t offset);

/** Parse code item (method bytecode); offset must be 4-byte aligned. */
std::expected<CodeItem, ParseError> parse_code_item(std::span<const uint8_t> buf, uint32_t offset);

/** Parse a debug_info_item: the line register's start value, the parameter
 *  names, and the state machine's bytecode up to DBG_END_SEQUENCE.  Operands
 *  are decoded but not checked against the id tables. */
std::expected<DebugInfoItem, ParseError> parse_debug_info(std::span<const uint8_t> buf,
                                                          uint32_t offset);

/** Parse annotations directory item */
std::expected<AnnotationsDirectoryItem, ParseError>
parse_annotations_directory(std::span<const uint8_t> buf, uint32_t offset);

/** Parse annotation set item */
std::expected<AnnotationSetItem, ParseError> parse_annotation_set(std::span<const uint8_t> buf,
                                                                  uint32_t offset);

/** Parse annotation set reference list */
std::expected<AnnotationSetRefList, ParseError>
parse_annotation_set_ref_list(std::span<const uint8_t> buf, uint32_t offset);

/** Parse a single encoded_value.  @p offset is advanced past the value.
 *  Nesting (arrays / sub-annotations) is bounded to depth 64 to keep malformed
 *  input from recursing unboundedly; deeper input fails with MalformedData. */
std::expected<EncodedValue, ParseError> parse_encoded_value(std::span<const uint8_t> buf,
                                                            uint32_t &offset);

/** Parse an encoded_array_item (uleb128 count + encoded_values), e.g. the
 *  static-field initializers at ClassDefItem::static_values_off.
 *  @p offset is advanced past the array. */
std::expected<std::vector<EncodedValue>, ParseError>
parse_encoded_array(std::span<const uint8_t> buf, uint32_t &offset);

/** Parse an encoded_annotation (uleb128 type_idx + elements).
 *  @p offset is advanced past the annotation. */
std::expected<EncodedAnnotation, ParseError> parse_encoded_annotation(std::span<const uint8_t> buf,
                                                                      uint32_t &offset);

/** Parse an annotation_item (visibility byte + encoded_annotation) at a fixed
 *  offset, e.g. one entry of an AnnotationSetItem. */
std::expected<AnnotationItem, ParseError> parse_annotation_item(std::span<const uint8_t> buf,
                                                                uint32_t offset);

/** Compute Adler-32 checksum of DEX file. */
std::expected<uint32_t, ParseError> compute_checksum(std::span<const uint8_t> buf);

/** Compute the SHA-1 signature of a DEX file: the digest of every byte after
 *  the signature field (offset 32 to the end). */
std::expected<std::array<uint8_t, 20>, ParseError> compute_signature(std::span<const uint8_t> buf);

} // namespace dexsplit::raw::parser

#endif // PARSER_HPP

#ifndef PARSING_UTILS_H
#define PARSING_UTILS_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "raw/error.hpp"

namespace dexsplit::raw::parse_utils {

/**
 * Reads a 32-bit unsigned integer from the buffer at the given offset.
 * The integer is assumed to be in little-endian byte order.
 * Returns OutOfBounds error if buffer is too small.
 *
 * @param buf The byte buffer to read from
 * @param offset The offset to start reading from; will be advanced by 4 bytes on success
 * @return The 32-bit unsigned integer value, or ParseError on failure
 */
std::expected<std::uint32_t, ParseError> read_uint32(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset);

/**
 * Reads a 16-bit unsigned integer from the buffer at the given offset.
 * The integer is assumed to be in little-endian byte order.
 * Returns OutOfBounds error if buffer is too small.
 *
 * @param buf The byte buffer to read from
 * @param offset The offset to start reading from; will be advanced by 2 bytes on success
 * @return The 16-bit unsigned integer value, or ParseError on failure
 */
std::expected<std::uint16_t, ParseError> read_uint16(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset);

/**
 * Reads an unsigned LEB128 (Little Endian Base 128) value from the buffer.
 * LEB128 is a variable-length encoding for integers used in DEX files.
 * Returns OutOfBounds error if buffer is too small, or InvalidLeb128 if malformed.
 *
 * @param buf The byte buffer to read from
 * @param offset The offset to start reading from; will be advanced past the encoded value
 * @return The decoded 32-bit unsigned integer value, or ParseError on failure
 */
std::expected<std::uint32_t, ParseError> read_uleb128(std::span<const std::uint8_t> buf,
                                                      std::uint32_t &offset);

/**
 * Reads a signed LEB128 (Little Endian Base 128) value from the buffer.
 * LEB128 is a variable-length encoding for integers used in DEX files.
 * Returns OutOfBounds error if buffer is too small, or InvalidLeb128 if malformed.
 *
 * @param buf The byte buffer to read from
 * @param offset The offset to start reading from; will be advanced past the encoded value
 * @return The decoded 32-bit signed integer value, or ParseError on failure
 */
std::expected<std::int32_t, ParseError> read_sleb128(std::span<const std::uint8_t> buf,
                                                     std::uint32_t &offset);

/**
 * Decodes a MUTF-8 (Modified UTF-8) string from the buffer.
 * MUTF-8 is a variant of UTF-8 where null is encoded as 0xC0 0x80.
 * Reads until a null byte is encountered and advances past it.
 * Returns OutOfBounds error if buffer ends before null terminator.
 * Returns InvalidUtf8String error for a malformed sequence: a bad continuation
 * byte, an overlong form other than C0 80, or a 4-byte form.  An unpaired
 * surrogate becomes U+FFFD, so the decoded string is always valid UTF-8.
 *
 * @param buf The byte buffer to read from
 * @param offset The offset to start reading from; will be advanced past the null terminator
 * @return The decoded UTF-8 string, or ParseError on failure
 */
std::expected<std::string, ParseError> decode_mutf8(std::span<const std::uint8_t> buf,
                                                    std::uint32_t &offset);

} // namespace dexsplit::raw::parse_utils

#endif

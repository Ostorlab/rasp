#include "common/budget.hpp"
#ifndef DEX_ERROR_HPP
#define DEX_ERROR_HPP

#include <cstdint>
#include <string>

namespace dexsplit::raw {

/**
 * Parse error with context information
 */
struct ParseError {
  enum class Code {
    InvalidMagic,
    TruncatedFile,
    InvalidOffset,
    InvalidSize,
    MalformedData,
    OutOfBounds,
    UnsupportedVersion,
    InvalidUtf8String,
    InvalidLeb128,
    InvalidOpcode,
    NullPointer,
    UnknownError
  };

  Code code;
  budget::String message;
  uint32_t offset;

  static ParseError invalid_magic(uint32_t offset);
  static ParseError truncated_file(uint32_t expected, uint32_t actual);
  static ParseError invalid_offset(uint32_t offset, uint32_t file_size);
  static ParseError out_of_bounds(uint32_t offset, const char* what);
};

}  // namespace dexsplit::raw

#endif  // DEX_ERROR_HPP

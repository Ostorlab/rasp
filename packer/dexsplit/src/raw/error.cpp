#include "raw/error.hpp"

#include "common/budget.hpp"

namespace dexsplit::raw {

ParseError ParseError::invalid_magic(uint32_t offset) {
  return ParseError{Code::InvalidMagic, "Invalid DEX magic number", offset};
}

ParseError ParseError::truncated_file(uint32_t expected, uint32_t actual) {
  return ParseError{
      Code::TruncatedFile,
      "File too small: expected " + budget::to_string(expected) + " bytes, got " + budget::to_string(actual), actual};
}

ParseError ParseError::invalid_offset(uint32_t offset, uint32_t file_size) {
  return ParseError{
      Code::InvalidOffset,
      "Invalid offset: " + budget::to_string(offset) + " exceeds file size " + budget::to_string(file_size), offset};
}

ParseError ParseError::out_of_bounds(uint32_t offset, const char* what) {
  return ParseError{Code::OutOfBounds,
                    budget::String("Out of bounds at offset ") + budget::to_string(offset) + ": " + what, offset};
}

}  // namespace dexsplit::raw

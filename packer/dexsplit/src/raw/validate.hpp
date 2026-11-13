#pragma once
#include <cstdint>
#include <expected>
#include <span>

#include "raw/error.hpp"
#include "raw/types.hpp"
namespace dexsplit::raw {
/// Parse and retain every code item only after complete mapped validation succeeds.
[[nodiscard]] std::expected<budget::Map<uint32_t, CodeItem>, ParseError> parse_layout(std::span<const uint8_t> bytes);
/// Validate the complete mapped layout, typed references and every item boundary before model reads.
[[nodiscard]] std::expected<void, ParseError> validate_layout(std::span<const uint8_t> bytes);
}  // namespace dexsplit::raw

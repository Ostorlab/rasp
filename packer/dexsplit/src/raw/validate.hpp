#pragma once
#include <cstdint>
#include <expected>
#include <span>

#include "raw/error.hpp"
namespace dexsplit::raw {
/// Validate the complete mapped layout, typed references and every item boundary before model reads.
[[nodiscard]] std::expected<void, ParseError> validate_layout(std::span<const uint8_t> bytes);
}  // namespace dexsplit::raw

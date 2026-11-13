#pragma once

#include "raw/types.hpp"

namespace dexsplit::raw {
/// Validate instruction/register/branch/payload/try structure independently of any owning method.
[[nodiscard]] std::expected<CodeStructure, ParseError> validate_code_structure(const CodeItem& code);
}  // namespace dexsplit::raw

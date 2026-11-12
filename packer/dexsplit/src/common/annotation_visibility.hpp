#include "common/budget.hpp"
#pragma once

#include <cstdint>

namespace dexsplit {

/** Who can see an annotation at runtime, per the DEX visibility byte. */
enum class AnnotationVisibility : uint8_t {
  Build = 0x00,    ///< Compile-time only (e.g. @Override); stripped semantics.
  Runtime = 0x01,  ///< Visible to reflection (RetentionPolicy.RUNTIME).
  System = 0x02,   ///< dalvik.annotation.* metadata (signatures, defaults, ...).
};

}  // namespace dexsplit

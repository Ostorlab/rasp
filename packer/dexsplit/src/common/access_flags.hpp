#include "common/budget.hpp"
#pragma once

#include <cstdint>

namespace dexsplit {

/** Bitmask of DEX access flags, applicable to classes, methods, and fields.
 *  Values mirror the DEX specification (JVMS §4.1, §4.6, §4.7 extended by
 *  the Android runtime for Annotation, Enum, Constructor, and DeclaredSynchronized). */
enum class AccessFlags : uint32_t {
  Public = 0x0001,
  Private = 0x0002,
  Protected = 0x0004,
  Static = 0x0008,
  Final = 0x0010,
  Synchronized = 0x0020,
  Volatile = 0x0040,   ///< Fields only.
  Bridge = 0x0040,     ///< Methods only (same bit as Volatile).
  Transient = 0x0080,  ///< Fields only.
  Varargs = 0x0080,    ///< Methods only (same bit as Transient).
  Native = 0x0100,
  Interface = 0x0200,
  Abstract = 0x0400,
  Strict = 0x0800,
  Synthetic = 0x1000,
  Annotation = 0x2000,
  Enum = 0x4000,
  Constructor = 0x10000,
  DeclaredSynchronized = 0x20000
};

inline AccessFlags operator|(AccessFlags a, AccessFlags b) {
  return static_cast<AccessFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline AccessFlags operator&(AccessFlags a, AccessFlags b) {
  return static_cast<AccessFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/** Returns true if @p flag is set in @p flags. */
inline bool has_flag(AccessFlags flags, AccessFlags flag) {
  return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

}  // namespace dexsplit

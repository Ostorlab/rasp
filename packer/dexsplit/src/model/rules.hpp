#include "common/budget.hpp"
#pragma once

// Rules shared by the writer and validate().  Internal: not part of the API.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "model/io.hpp"
#include "model/types.hpp"
#include "raw/descriptors.hpp"

namespace dexsplit::model::detail {

/** validate() and required_version() in one pass. */
struct Checked {
  budget::Vector<Problem> problems;
  uint32_t needed_version = 35;
  budget::String needed_reason;  ///< The first feature that needs needed_version.
};
Checked check(const Dex& dex);

inline bool has(AccessFlags flags, AccessFlags flag) {
  return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

inline bool is_constructor_name(std::string_view name) { return name == "<init>" || name == "<clinit>"; }

/** A direct method: static, private, or a constructor by name (ART's rule —
 *  an "<init>" without the constructor flag is still direct). */
inline bool is_direct(const MethodDef& m) {
  return has(m.access, AccessFlags::Static) || has(m.access, AccessFlags::Private) || is_constructor_name(m.name);
}

/** Registers the incoming arguments take: `this` for an instance method,
 *  then two per long/double parameter and one per other parameter. */
inline uint32_t ins_words(const MethodDef& m) {
  return raw::parameter_words(m.proto) + (has(m.access, AccessFlags::Static) ? 0 : 1);
}

/** The opposite condition, for a branch turned around a goto/32. */
inline Condition negate(Condition c) {
  switch (c) {
    case Condition::Eq:
      return Condition::Ne;
    case Condition::Ne:
      return Condition::Eq;
    case Condition::Lt:
      return Condition::Ge;
    case Condition::Ge:
      return Condition::Lt;
    case Condition::Gt:
      return Condition::Le;
    case Condition::Le:
      return Condition::Gt;
  }
  return c;
}

/** True if an invoke or filled-new-array argument list can be encoded: up to
 *  five registers below v16, or a run of at most 255 consecutive registers. */
inline bool args_encodable(const RegList& args) {
  if (args.size() <= 5) {
    bool small = true;
    for (Reg r : args) {
      dexsplit::budget::visit();
      small = small && r < 16;
    }
    if (small) {
      return true;
    }
  }
  return args.size() <= 255 && args.is_run() && (args.empty() || uint32_t{args[0]} + args.size() <= 0x10000);
}

/** True if the 35c form (up to five registers below v16) fits @p args. */
inline bool args_fit_35c(const RegList& args) {
  if (args.size() > 5) {
    return false;
  }
  for (Reg r : args) {
    dexsplit::budget::visit();
    if (r >= 16) {
      return false;
    }
  }
  return true;
}

}  // namespace dexsplit::model::detail

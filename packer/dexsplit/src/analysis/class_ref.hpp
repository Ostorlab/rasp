#include "common/budget.hpp"
#pragma once

#include <string>
#include <string_view>

namespace dexsplit {

/** A lightweight reference to a class by its 'L...;' type descriptor.
 *
 *  Returned by Class::superclass() and Class::interfaces().  The descriptor is
 *  owned (copied in), so the reference is safe to keep and compare on its own. */
class ClassRef {
 public:
  /** Construct a reference from a class type descriptor ("Ljava/lang/Object;"). */
  explicit ClassRef(std::string_view descriptor) : descriptor_(descriptor) {}

  /** The 'L...;' type descriptor this reference names. */
  std::string_view descriptor() const { return descriptor_; }

 private:
  budget::String descriptor_;
};

}  // namespace dexsplit

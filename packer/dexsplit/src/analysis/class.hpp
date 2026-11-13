#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "class_ref.hpp"
#include "method.hpp"

namespace dexsplit {

namespace detail {
struct AnalysisContextImpl;
} // namespace detail

/** A lightweight, non-owning handle to a single DEX class definition.
 *
 *  Instances come from AnalysisContext::classes().  The handle keeps shared
 *  ownership of the underlying implementation, so it stays valid for as long as
 *  any handle into the same context is alive.
 *
 *  A default-constructed Class has is_valid() == false and must not have any
 *  other method called on it. */
class Class
{
  public:
    /** Construct a handle to class_defs[@p class_def_idx] of DEX file @p dex_idx. */
    Class(std::shared_ptr<const detail::AnalysisContextImpl> impl, std::size_t dex_idx,
          uint32_t class_def_idx);

    /** The 'L...;' type descriptor that names this class (e.g. "LTestDex;"). */
    std::string_view name() const;

    /** A ClassRef for the direct superclass, or std::nullopt for java.lang.Object
     *  itself (its superclass index is NO_INDEX). */
    std::optional<ClassRef> superclass() const;

    /** The interfaces implemented by this class, in declaration order. */
    std::vector<ClassRef> interfaces() const;

    /** All direct and virtual methods defined in this class, in that order. */
    std::vector<Method> methods() const;

    /** Returns false for a default-constructed "null" Class handle. */
    bool is_valid() const { return impl_ != nullptr; }

    /** Default constructor produces an invalid handle (is_valid() == false). */
    Class() : impl_(nullptr), dex_idx_(0), class_def_idx_(0) {}

  private:
    std::shared_ptr<const detail::AnalysisContextImpl> impl_;
    std::size_t dex_idx_;
    uint32_t class_def_idx_;
};

} // namespace dexsplit

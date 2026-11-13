#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "class.hpp"

namespace dexsplit {

namespace detail {
struct AnalysisContextImpl;
} // namespace detail

/** The entry point for analysis.
 *
 *  AnalysisContext owns one or more parsed DEX files and exposes the classes in
 *  them.  It is the root object that every Class / Method handle points back to.
 *
 *  Internally the context uses a shared_ptr to a private Impl, so copying is
 *  cheap (shared ownership) and handles stay valid even after every
 *  AnalysisContext wrapper has been destroyed. */
class AnalysisContext
{
  public:
    /** Parse a set of in-memory DEX files into one context, in the given order
     *  (multidex order: classes.dex, classes2.dex, ...).  Each buffer is copied
     *  in and kept for the context's lifetime.
     *  @return the context on success, or an error message if a buffer is not a
     *          valid DEX file. */
    static std::expected<AnalysisContext, std::string>
    from_dex_buffers(const std::vector<std::span<const uint8_t>> &buffers);

    /** All classes across every loaded DEX file, in file / definition order. */
    [[nodiscard]] std::vector<Class> classes() const;

  private:
    explicit AnalysisContext(std::shared_ptr<detail::AnalysisContextImpl> impl);

    std::shared_ptr<detail::AnalysisContextImpl> impl_;
};

} // namespace dexsplit

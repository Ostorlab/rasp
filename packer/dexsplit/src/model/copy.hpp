#pragma once
#include "model/io.hpp"
namespace dexsplit::model {
namespace detail {
/// Charge owned class values before either direct model copies or grouping copies.
void charge_class_copy(const ClassDef& value);
}  // namespace detail
/// Retain a single request across copied models; unrelated requests require explicit grouping before reads.
std::shared_ptr<budget::State> copy_request(Dex& destination, const Dex& source);
/// Copy complete classes with charged owned-value copies and shared copy-on-write method bodies.
[[nodiscard]] std::expected<void, Error> copy_classes(Dex& destination, const Dex& source,
                                                      std::span<const std::string_view> descriptors);
}  // namespace dexsplit::model

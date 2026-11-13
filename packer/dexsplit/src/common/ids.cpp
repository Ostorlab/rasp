#include "common/ids.hpp"

#include <functional>

#include "common/budget.hpp"

namespace dexsplit {

namespace {

// Standard hash combiner (boost-style xor-shift mixer).
inline void hash_combine(std::size_t& seed, std::size_t v) noexcept {
  seed ^= v + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U);
}

}  // namespace

std::size_t MethodIdHash::operator()(const MethodId& m) const {
  std::size_t h = budget::Hash<budget::String>{}(m.class_descriptor);
  hash_combine(h, budget::Hash<budget::String>{}(m.name));
  hash_combine(h, budget::Hash<budget::String>{}(m.proto));
  return h;
}

std::size_t FieldIdHash::operator()(const FieldId& f) const {
  std::size_t h = budget::Hash<budget::String>{}(f.class_descriptor);
  hash_combine(h, budget::Hash<budget::String>{}(f.name));
  hash_combine(h, budget::Hash<budget::String>{}(f.type));
  return h;
}

}  // namespace dexsplit

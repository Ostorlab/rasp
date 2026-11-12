#include "common/ids.hpp"

#include <functional>

namespace dexsplit {

namespace {

// Standard hash combiner (boost-style xor-shift mixer).
inline void hash_combine(std::size_t &seed, std::size_t v) noexcept
{
    seed ^= v + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

} // namespace

std::size_t MethodIdHash::operator()(const MethodId &m) const noexcept
{
    std::size_t h = std::hash<std::string>{}(m.class_descriptor);
    hash_combine(h, std::hash<std::string>{}(m.name));
    hash_combine(h, std::hash<std::string>{}(m.proto));
    return h;
}

std::size_t FieldIdHash::operator()(const FieldId &f) const noexcept
{
    std::size_t h = std::hash<std::string>{}(f.class_descriptor);
    hash_combine(h, std::hash<std::string>{}(f.name));
    hash_combine(h, std::hash<std::string>{}(f.type));
    return h;
}

} // namespace dexsplit

#pragma once

#include <cstddef>

namespace dexsplit {
/// Distinguish the input file index from an index into a DEX table.
struct DexIndex {
  std::size_t value;
};
}  // namespace dexsplit

/// is_check_enabled: whether the runtime's config enables a check group, by its name or its mask position.

#include "rasp/config.h"

#include <algorithm>
#include <cstdint>
#include <string_view>

namespace rasp {

bool is_check_enabled(const Config& config, std::string_view group) {
  return config.checks.has_value() && std::ranges::find(*config.checks, group) != config.checks->end();
}

bool is_check_enabled(const Config& config, unsigned bit, std::string_view group) {
  if (bit >= 64) {
    return false;
  }
  if (config.checks_mask.has_value()) {
    return (*config.checks_mask & (std::uint64_t{1} << bit)) != 0;
  }
  return is_check_enabled(config, group);
}

}  // namespace rasp

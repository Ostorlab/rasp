/// is_check_enabled: whether the runtime's config enables a check group.

#include "rasp/config.h"

#include <algorithm>
#include <string_view>

namespace rasp {

bool is_check_enabled(const Config& config, std::string_view group) {
  return !config.checks.has_value() || std::ranges::find(*config.checks, group) != config.checks->end();
}

}  // namespace rasp

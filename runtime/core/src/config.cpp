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
  if (config.checks.has_value()) {
    return is_check_enabled(config, group);
  }
  // Neither a mask nor a list: the config names no selection at all, which is how a missing, blank, or unparsable
  // config parses (parse_config leaves both unset, and the embedded section ships as "{}"). A correctly packed app
  // always carries a mask, so this is the degenerate case; the runtime fails closed and every group runs, rather than
  // silently running no check — the backstop the start-up sweep and the loader checkpoints once gave by running
  // unconditionally.
  return true;
}

}  // namespace rasp

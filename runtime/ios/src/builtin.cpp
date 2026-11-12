/// The iOS built-in check dispatch, shared by monitoring and compiled host integration tests.

#include "builtin.h"

#include <algorithm>
#include <iterator>
#include <string_view>
#include <vector>

#include "checks/capture.h"
#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/integrity.h"
#include "checks/jailbreak.h"
#include "checks/mitm.h"
#include "checks/virtualizer.h"
#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::ios {

std::vector<Observation> run_checks(const Config& config, std::string_view inserted_libraries,
                                    const capture::Input* capture_input) {
  std::vector<Observation> builtin;
  if (is_check_enabled(config, "jailbreak")) {
    std::ranges::move(checks::jailbreak(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "debugger")) {
    std::ranges::move(checks::debugger(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "hooks")) {
    std::ranges::move(checks::hooks(inserted_libraries), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "integrity")) {
    std::ranges::move(checks::integrity(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "identity")) {
    std::ranges::move(checks::identity(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "emulator")) {
    std::ranges::move(checks::emulator(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "virtualizer")) {
    std::ranges::move(checks::virtualizer(), std::back_inserter(builtin));
  }
  if (is_check_enabled(config, "mitm")) {
    std::ranges::move(checks::mitm(), std::back_inserter(builtin));
  }
  const bool screenshots = is_check_enabled(config, "screenshot");
  const bool recording = is_check_enabled(config, "screen_recording");
  if (screenshots || recording) {
    std::ranges::move(checks::capture(screenshots, recording, capture_input), std::back_inserter(builtin));
  }
  return builtin;
}

}  // namespace rasp::ios

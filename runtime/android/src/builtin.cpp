/// Android built-in selection shared by production monitoring and compiled dispatch tests.

#include "builtin.h"

#include <algorithm>
#include <iterator>
#include <vector>

#include "checks/debugger.h"
#include "checks/emulator.h"
#include "checks/hooks.h"
#include "checks/identity.h"
#include "checks/integrity.h"
#include "checks/mitm.h"
#include "checks/root.h"
#include "checks/service_exposure.h"
#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::android {

/// Runs the built-in check groups that the runtime's config enables.
///
/// @param config The runtime's config.
/// @return Selected groups' typed observations, preserving errors and unsupported service/API states.
std::vector<Observation> run_checks(const Config& config) {
  std::vector<Observation> observations;
  if (is_check_enabled(config, "root")) {
    std::ranges::move(checks::root(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "debugger")) {
    std::ranges::move(checks::debugger(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "hooks")) {
    std::ranges::move(checks::hooks(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "integrity")) {
    std::ranges::move(checks::integrity(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "mitm")) {
    std::ranges::move(checks::mitm(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "identity")) {
    std::ranges::move(checks::identity(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "emulator")) {
    std::ranges::move(checks::emulator(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "accessibility")) {
    std::ranges::move(checks::accessibility(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "input_method")) {
    std::ranges::move(checks::input_method(), std::back_inserter(observations));
  }
  if (is_check_enabled(config, "notification_access")) {
    std::ranges::move(checks::notification_access(), std::back_inserter(observations));
  }
  return observations;
}

}  // namespace rasp::android

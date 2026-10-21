/// The example check, a placeholder until the first real check ships.

#include "checks/example.h"

#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

std::vector<Observation> example() {
  return std::vector<Observation>{
      Observation{.signal = "example.loaded", .source = "runtime", .status = Status::kOk, .value = true},
  };
}

}  // namespace rasp::android::checks

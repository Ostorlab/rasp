/// Compiled tests of iOS check selection and dispatch, including the integrity group.

#include "builtin.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp::ios {
namespace {
TEST(Builtin, runChecks_whenIntegritySelected_dispatchesTypedObservations) {
  Config config;
  config.checks = {"integrity"};
  EXPECT_EQ(run_checks(config, ""), (std::vector<Observation>{unsupported("integ.text_sha256", "file"),
                                                              unsupported("integ.text_sha256", "memory")}));
}
TEST(Builtin, runChecks_whenIntegrityNotSelected_doesNotDispatchIntegrity) {
  Config config;
  config.checks = {"debugger"};
  const auto observations = run_checks(config, "");
  ASSERT_FALSE(observations.empty());
  for (const auto& observation : observations) {
    EXPECT_NE(observation.signal, "integ.text_sha256");
  }
}
TEST(Builtin, runChecks_whenNoChecksSelected_returnsNoObservations) { EXPECT_TRUE(run_checks(Config{}, "").empty()); }
}  // namespace
}  // namespace rasp::ios

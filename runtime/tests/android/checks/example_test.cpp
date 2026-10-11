/// Tests for the example check.

#include "checks/example.h"

#include <gtest/gtest.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {
namespace {

TEST(ExampleCheck, example_whenCalled_reportsTheRuntimeAsLoaded) {
  const std::vector<Observation> observations = example();

  ASSERT_EQ(observations.size(), 1U);
  EXPECT_EQ(observations[0],
            (Observation{.signal = "example.loaded", .source = "runtime", .status = Status::kOk, .value = true}));
}

}  // namespace
}  // namespace rasp::android::checks

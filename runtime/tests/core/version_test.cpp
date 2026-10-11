/// Tests that the runtime version is the project version CMake sets.

#include "rasp/version.h"

#include <gtest/gtest.h>

TEST(RuntimeVersion, IsTheProjectVersion) { EXPECT_EQ(rasp::kRuntimeVersion, RASP_EXPECTED_VERSION); }

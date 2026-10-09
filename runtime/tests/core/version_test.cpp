#include "rasp/version.h"

#include <gtest/gtest.h>

TEST(RuntimeVersion, IsTheProjectVersion) { EXPECT_EQ(rasp::kRuntimeVersion, RASP_EXPECTED_VERSION); }

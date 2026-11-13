/// Install once per process, including shuffled/repeated tests, and check the real facade on every invocation.
#include "rasp/local_policy_host.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/local_policy.h"
#include "rasp/parse_config.h"

namespace {
TEST(LocalPolicyHost, info_whenInstalledOnce_preservesProcessLifetimeAndFullUint32Version) {
  const auto config = rasp::parse_config(
      R"({"build_id":"host","checks":[],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"max-version","policy_version":4294967295,"mode":"report_only","scope":"host_calls_only","platform":"android","catalogue_id":"e24617864ef1929ecca4d84ed0b62d530ca2ad602859272acd8f0aee3afc7733","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[]}})");
  static auto* const kInstalled =
      rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(config, "android"));
  ASSERT_NE(kInstalled, nullptr);
  EXPECT_EQ(rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(config, "android")), nullptr);
  auto output = std::make_unique<struct RaspLocalPolicyInfoV1>();
  EXPECT_EQ(rasp_local_policy_info_v1(output.get(), sizeof(*output)), RASP_LOCAL_OK);
  EXPECT_EQ(output->checks_known, 1U);
  EXPECT_EQ(output->check_count, 0U);
  EXPECT_EQ(output->policy_version, std::numeric_limits<std::uint32_t>::max());
  EXPECT_STREQ(std::span(output->policy_sha256).data(),
               rasp::local_policy_hash(config.local_policy.canonical_json).c_str());
  struct RaspLocalGateRequestV1 request{};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  std::ranges::copy(std::string_view("append_demo_receipt"), std::span(request.operation).begin());
  std::ranges::copy(std::span(output->policy_sha256), std::span(request.expected_policy_sha256).begin());
  auto decision = std::make_unique<struct RaspLocalGateResultV1>();
  EXPECT_EQ(rasp_local_policy_gate_v1(&request, sizeof(request), decision.get(), sizeof(*decision)), RASP_LOCAL_OK);
  EXPECT_EQ(decision->action, RASP_LOCAL_REPORT);
  EXPECT_EQ(decision->policy_version, std::numeric_limits<std::uint32_t>::max());
  request.abi_version = 2;
  EXPECT_EQ(rasp_local_policy_gate_v1(&request, sizeof(request), decision.get(), sizeof(*decision)),
            RASP_LOCAL_UNSUPPORTED_ABI);
  EXPECT_EQ(decision->action, RASP_LOCAL_DENY);
}
}  // namespace

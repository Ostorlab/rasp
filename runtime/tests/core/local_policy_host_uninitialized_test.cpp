/// Isolated startup/ABI checks against the real facade; this process never installs a policy.
#include <gtest/gtest.h>
#include <memory>

#include "rasp/local_policy_host.h"

namespace {
TEST(LocalPolicyHost, gate_whenUninitializedOrBadAbi_neverAllows) {
  auto output = std::make_unique<struct RaspLocalGateResultV1>();
  struct RaspLocalGateRequestV1 request{};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  EXPECT_EQ(rasp_local_policy_gate_v1(&request, sizeof(request), output.get(), sizeof(*output)), RASP_LOCAL_NOT_READY);
  EXPECT_EQ(output->action, RASP_LOCAL_DENY);
  EXPECT_EQ(rasp_local_policy_gate_v1(nullptr, 0, output.get(), sizeof(*output)), RASP_LOCAL_INVALID_ARGUMENT);
  EXPECT_EQ(output->action, RASP_LOCAL_DENY);
  EXPECT_EQ(rasp_local_policy_gate_v1(&request, sizeof(request), output.get(), sizeof(*output) - 1),
            RASP_LOCAL_INVALID_ARGUMENT);
}
}  // namespace

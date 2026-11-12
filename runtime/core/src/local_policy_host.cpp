/// Exactly two exported primitive host entry points; no private C++ ownership escapes.
#include "rasp/local_policy_host.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "local_policy_state.h"

static_assert(sizeof(struct RaspLocalGateRequestV1) == 112);
static_assert(sizeof(struct RaspLocalGateDetailV1) == 204);
static_assert(sizeof(struct RaspLocalGateResultV1) == 2104);
static_assert(sizeof(struct RaspLocalPolicyInfoV1) == 6532);
static_assert(offsetof(struct RaspLocalGateResultV1, sequence) == 72);
static_assert(offsetof(struct RaspLocalGateResultV1, details) == 472);
static_assert(std::is_trivially_copyable_v<struct RaspLocalGateResultV1>);
static_assert(std::is_standard_layout_v<struct RaspLocalPolicyInfoV1>);

std::int32_t rasp_local_policy_info_v1(struct RaspLocalPolicyInfoV1* out, std::uint32_t out_size) {
  if (out == nullptr || out_size != sizeof(*out)) {
    return RASP_LOCAL_INVALID_ARGUMENT;
  }
  std::memset(out, 0, sizeof(*out));
  out->abi_version = 1;
  out->struct_size = sizeof(*out);
  out->status = RASP_LOCAL_NOT_READY;
  const auto* const state = rasp::process_local_policy();
  return state == nullptr ? RASP_LOCAL_NOT_READY : state->info(*out);
}
std::int32_t rasp_local_policy_gate_v1(const struct RaspLocalGateRequestV1* request, std::uint32_t request_size,
                                       struct RaspLocalGateResultV1* out, std::uint32_t out_size) {
  if (out == nullptr || out_size != sizeof(*out)) {
    return RASP_LOCAL_INVALID_ARGUMENT;
  }
  if (request == nullptr || request_size != sizeof(*request)) {
    std::memset(out, 0, sizeof(*out));
    out->status = RASP_LOCAL_INVALID_ARGUMENT;
    return RASP_LOCAL_INVALID_ARGUMENT;
  }
  const auto input = *request;
  std::memset(out, 0, sizeof(*out));
  out->abi_version = 1;
  out->struct_size = sizeof(*out);
  out->status = RASP_LOCAL_NOT_READY;
  auto* const state = rasp::process_local_policy();
  return state == nullptr ? RASP_LOCAL_NOT_READY : state->gate(input, *out);
}

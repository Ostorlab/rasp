/// Actual C++ host-source consumer; only primitive C values cross the native gate boundary.
#include "local_policy_host.h"
#include "rasp/host_events.h"

static_assert(sizeof(RaspHostEventV1) == 80);
static_assert(sizeof(RaspHostContextViewV1) == 120);
static_assert(sizeof(RaspHostContextV1) <= 512);

/// One synchronous host mutation after actual context/native admission, never a cached permit.
int main() {
  RaspHostContextV1 owner{};
  const RaspHostBindingV1 binding{
      .version = 1,
      .struct_size = 116,
      .require_secure_input = 0,
      .reserved = 0,
      .operation = "append_demo_receipt",
      .expected_policy_sha256 = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81",
      .reserved_tail = {0, 0},
  };
  if (rasp_host_context_init_v1(&owner, &binding, sizeof(binding)) != 0) {
    return 1;
  }
  RaspHostEventV1 event{};
  RaspHostContextViewV1 context{};
  event.version = 1;
  event.struct_size = sizeof(event);
  event.kind = 1;
  event.lifecycle = 1;
  event.generation = 1;
  event.event_sequence = 1;
  event.session_ref[0] = 1;
  if (rasp_host_context_apply_v1(&owner, &event, sizeof(event), &context, sizeof(context)) != 0) {
    return 2;
  }
  event.kind = 2;
  event.lifecycle = 0;
  event.purpose = 6;
  event.secure_entry = 4;
  event.event_sequence = 2;
  event.action_ref[0] = 2;
  event.attempt = 1;
  if (rasp_host_context_apply_v1(&owner, &event, sizeof(event), &context, sizeof(context)) != 0) {
    return 3;
  }
  RaspLocalGateResultV1 native{};
  const auto status = rasp_host_context_gate_v1(&owner, 1, 2, 1, &context, sizeof(context), &native, sizeof(native));
  auto receipts = 0;
  if (status == 0 && native.status == RASP_LOCAL_OK && native.action == RASP_LOCAL_ALLOW) {
    ++receipts;
  }
  if (context.state != 9 || receipts > 1) {
    return 4;
  }
  if (rasp_host_context_gate_v1(&owner, 1, 2, 1, &context, sizeof(context), &native, sizeof(native)) != 10 ||
      native.abi_version != 0) {
    return 5;
  }
  return rasp_host_context_dispose_v1(&owner);
}

/// Actual C/ObjC/C++/ObjC++ host-source consumer, no mocked runtime or device execution claim.
#include <stddef.h>
#include <stdint.h>

#include "local_policy_host.h"
#include "rasp/host_events.h"

#ifdef __cplusplus
static_assert(sizeof(struct RaspHostEventV1) == 80);
static_assert(sizeof(struct RaspHostContextViewV1) == 120);
static_assert(sizeof(struct RaspHostBindingV1) == 116);
static_assert(sizeof(struct RaspHostContextV1) <= 512);
#else
_Static_assert(sizeof(struct RaspHostEventV1) == 80, "event");
_Static_assert(sizeof(struct RaspHostContextViewV1) == 120, "view");
_Static_assert(sizeof(struct RaspHostBindingV1) == 116, "binding");
_Static_assert(sizeof(struct RaspHostContextV1) <= 512, "owner");
#endif

/// Explicit actual gate before a harmless host-owned receipt mutation.
#ifdef __cplusplus
int main() {
#else
int main(void) {
#endif
  const struct RaspHostBindingV1 binding = {
      .version = 1,
      .struct_size = 116,
      .require_secure_input = 0,
      .reserved = 0,
      .operation = "append_demo_receipt",
      .expected_policy_sha256 = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81",
      .reserved_tail = {0, 0},
  };
#ifdef __cplusplus
  struct RaspHostContextV1 owner{};
  struct RaspHostContextViewV1 view{};
  struct RaspHostEventV1 event{};
  struct RaspLocalGateResultV1 gate{};
#else
  struct RaspHostContextV1 owner = {0};
  struct RaspHostContextViewV1 view = {0};
  struct RaspHostEventV1 event = {0};
  struct RaspLocalGateResultV1 gate = {0};
#endif
  uint32_t receipts = 0;
  if (rasp_host_context_init_v1(&owner, &binding, sizeof(binding)) != 0) {
    return 1;
  }
  event.version = 1;
  event.struct_size = sizeof(event);
  event.kind = 1;
  event.lifecycle = 1;
  event.generation = 1;
  event.event_sequence = 1;
  event.session_ref[0] = 1;
  if (rasp_host_context_apply_v1(&owner, &event, sizeof(event), &view, sizeof(view)) != 0) {
    return 2;
  }
  event.kind = 2;
  event.lifecycle = 0;
  event.event_sequence = 2;
  event.purpose = 6;
  event.secure_entry = 4;
  event.action_ref[0] = 2;
  event.attempt = 1;
  if (rasp_host_context_apply_v1(&owner, &event, sizeof(event), &view, sizeof(view)) != 0) {
    return 3;
  }
  const int32_t status = rasp_host_context_gate_v1(&owner, 1, 2, 1, &view, sizeof(view), &gate, sizeof(gate));
  if (status == 0 && gate.status == RASP_LOCAL_OK && gate.action == RASP_LOCAL_ALLOW) {
    ++receipts;
  }
  if (receipts > 1) {
    return 4;
  }
  if (view.state != 9) {
    return 5;
  }
  if (rasp_host_context_gate_v1(&owner, 1, 2, 1, &view, sizeof(view), &gate, sizeof(gate)) != 10 || view.reason != 13 ||
      gate.abi_version != 0) {
    return 6;
  }
  return rasp_host_context_dispose_v1(&owner);
}

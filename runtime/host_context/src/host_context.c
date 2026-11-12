/// Bounded host-source reducer and real gate delegation; no heap, registry, I/O or telemetry.
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "local_policy_host.h"
#include "rasp/host_events.h"

_Static_assert(sizeof(struct RaspHostEventV1) == 80, "event layout");
_Static_assert(sizeof(struct RaspHostContextViewV1) == 120, "view layout");
_Static_assert(sizeof(struct RaspHostBindingV1) == 116, "binding layout");
_Static_assert(sizeof(struct RaspHostContextV1) <= 512, "finite owner");

_Static_assert(offsetof(struct RaspHostEventV1, version) == 0, "RaspHostEventV1.version");
_Static_assert(offsetof(struct RaspHostEventV1, struct_size) == 4, "RaspHostEventV1.struct_size");
_Static_assert(offsetof(struct RaspHostEventV1, kind) == 8, "RaspHostEventV1.kind");
_Static_assert(offsetof(struct RaspHostEventV1, purpose) == 12, "RaspHostEventV1.purpose");
_Static_assert(offsetof(struct RaspHostEventV1, secure_entry) == 16, "RaspHostEventV1.secure_entry");
_Static_assert(offsetof(struct RaspHostEventV1, lifecycle) == 20, "RaspHostEventV1.lifecycle");
_Static_assert(offsetof(struct RaspHostEventV1, attempt) == 24, "RaspHostEventV1.attempt");
_Static_assert(offsetof(struct RaspHostEventV1, completion) == 28, "RaspHostEventV1.completion");
_Static_assert(offsetof(struct RaspHostEventV1, generation) == 32, "RaspHostEventV1.generation");
_Static_assert(offsetof(struct RaspHostEventV1, event_sequence) == 40, "RaspHostEventV1.event_sequence");
_Static_assert(offsetof(struct RaspHostEventV1, session_ref) == 48, "RaspHostEventV1.session_ref");
_Static_assert(offsetof(struct RaspHostEventV1, action_ref) == 64, "RaspHostEventV1.action_ref");
_Static_assert(offsetof(struct RaspHostContextViewV1, version) == 0, "RaspHostContextViewV1.version");
_Static_assert(offsetof(struct RaspHostContextViewV1, struct_size) == 4, "RaspHostContextViewV1.struct_size");
_Static_assert(offsetof(struct RaspHostContextViewV1, status) == 8, "RaspHostContextViewV1.status");
_Static_assert(offsetof(struct RaspHostContextViewV1, reason) == 12, "RaspHostContextViewV1.reason");
_Static_assert(offsetof(struct RaspHostContextViewV1, state) == 16, "RaspHostContextViewV1.state");
_Static_assert(offsetof(struct RaspHostContextViewV1, purpose) == 20, "RaspHostContextViewV1.purpose");
_Static_assert(offsetof(struct RaspHostContextViewV1, secure_entry) == 24, "RaspHostContextViewV1.secure_entry");
_Static_assert(offsetof(struct RaspHostContextViewV1, lifecycle) == 28, "RaspHostContextViewV1.lifecycle");
_Static_assert(offsetof(struct RaspHostContextViewV1, attempt) == 32, "RaspHostContextViewV1.attempt");
_Static_assert(offsetof(struct RaspHostContextViewV1, sequence_present) == 36,
               "RaspHostContextViewV1.sequence_present");
_Static_assert(offsetof(struct RaspHostContextViewV1, timing_present) == 40, "RaspHostContextViewV1.timing_present");
_Static_assert(offsetof(struct RaspHostContextViewV1, trust) == 44, "RaspHostContextViewV1.trust");
_Static_assert(offsetof(struct RaspHostContextViewV1, generation) == 48, "RaspHostContextViewV1.generation");
_Static_assert(offsetof(struct RaspHostContextViewV1, event_sequence) == 56, "RaspHostContextViewV1.event_sequence");
_Static_assert(offsetof(struct RaspHostContextViewV1, session_age_ns) == 64, "RaspHostContextViewV1.session_age_ns");
_Static_assert(offsetof(struct RaspHostContextViewV1, action_age_ns) == 72, "RaspHostContextViewV1.action_age_ns");
_Static_assert(offsetof(struct RaspHostContextViewV1, last_event_age_ns) == 80,
               "RaspHostContextViewV1.last_event_age_ns");
_Static_assert(offsetof(struct RaspHostContextViewV1, session_ref) == 88, "RaspHostContextViewV1.session_ref");
_Static_assert(offsetof(struct RaspHostContextViewV1, action_ref) == 104, "RaspHostContextViewV1.action_ref");
_Static_assert(offsetof(struct RaspHostBindingV1, version) == 0, "RaspHostBindingV1.version");
_Static_assert(offsetof(struct RaspHostBindingV1, struct_size) == 4, "RaspHostBindingV1.struct_size");
_Static_assert(offsetof(struct RaspHostBindingV1, require_secure_input) == 8, "RaspHostBindingV1.require_secure_input");
_Static_assert(offsetof(struct RaspHostBindingV1, reserved) == 12, "RaspHostBindingV1.reserved");
_Static_assert(offsetof(struct RaspHostBindingV1, operation) == 16, "RaspHostBindingV1.operation");
_Static_assert(offsetof(struct RaspHostBindingV1, expected_policy_sha256) == 49,
               "RaspHostBindingV1.expected_policy_sha256");
_Static_assert(offsetof(struct RaspHostBindingV1, reserved_tail) == 114, "RaspHostBindingV1.reserved_tail");
#ifdef __i386__
_Static_assert(_Alignof(struct RaspHostEventV1) == 4, "native x86 event alignment");
_Static_assert(_Alignof(struct RaspHostContextViewV1) == 4, "native x86 view alignment");
#else
_Static_assert(_Alignof(struct RaspHostEventV1) == 8, "native event alignment");
_Static_assert(_Alignof(struct RaspHostContextViewV1) == 8, "native view alignment");
#endif
_Static_assert(_Alignof(struct RaspHostBindingV1) == 4, "native binding alignment");

/// Clear only a statically bounded host structure or field; no forensic zeroization claim.
static void clear_bytes(void* destination, size_t size) {
  unsigned char* bytes = (unsigned char*)destination;
  if (size > 512) {
    return;
  }
  for (size_t index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}
/// Copy fixed bounded fields after public memory validation; no borrowed pointer survives.
static void copy_bytes(void* destination, size_t size, const void* source) {
  unsigned char* output = (unsigned char*)destination;
  const unsigned char* input = (const unsigned char*)source;
  if (size > 512) {
    return;
  }
  for (size_t index = 0; index < size; ++index) {
    output[index] = input[index];
  }
}
/// Independent status and reason fields, named at call sites.
struct HostViewStatus {
  uint32_t status, reason;
};
/// Independent terminal state and reason, named at call sites.
struct HostCloseReason {
  uint32_t state, reason;
};
/// Compare fixed-size opaque refs without reading caller content.
static int equal_ref(const uint8_t* left, const uint8_t* right) { return memcmp(left, right, 16) == 0; }
/// Check unused refs without a global constructor.
static int zero_ref(const uint8_t* value) {
  uint8_t combined = 0;
  for (size_t index = 0; index < 16; ++index) {
    combined |= value[index];
  }
  return combined == 0;
}
/// Validate non-overlapping borrowed/caller-owned ranges without pointer arithmetic overflow.
static int overlaps(const void* left, size_t left_size, const void* right, size_t right_size) {
  const uintptr_t first = (uintptr_t)left;
  const uintptr_t second = (uintptr_t)right;
  return first <= second ? second - first < left_size : first - second < right_size;
}
/// Copy an unavailable/current owned view; errors never disclose a newer flow's refs.
static int32_t output_view(const struct RaspHostContextV1* owner, struct HostViewStatus result,
                           struct RaspHostContextViewV1* out, int timing) {
  const uint32_t status = result.status;
  const uint32_t reason = result.reason;
  *out = owner->view;
  out->version = 1;
  out->struct_size = sizeof(*out);
  out->status = status;
  out->reason = reason;
  out->timing_present = timing != 0 ? 1U : 0U;
  if (!timing) {
    out->session_age_ns = 0;
    out->action_age_ns = 0;
    out->last_event_age_ns = 0;
  }
  if (status != 0 || (out->state != 1 && out->state != 2 && out->state != 9)) {
    clear_bytes(out->session_ref, 16);
    clear_bytes(out->action_ref, 16);
  }
  return (int32_t)status;
}
/// Close a current flow without retaining raw event/ref state or repairing its generation.
static void close_flow(struct RaspHostContextV1* owner, struct HostCloseReason result) {
  const uint32_t state = result.state;
  const uint32_t reason = result.reason;
  owner->view.state = state;
  owner->view.reason = reason;
  owner->view.purpose = 0;
  owner->view.secure_entry = 0;
  owner->view.attempt = 0;
  owner->view.timing_present = 0;
  clear_bytes(owner->view.session_ref, 16);
  clear_bytes(owner->view.action_ref, 16);
  clear_bytes(&owner->last_event, sizeof(owner->last_event));
  owner->has_last = 0;
  owner->session_start = 0;
  owner->action_start = 0;
  owner->event_tick = 0;
}
/// Sample checked platform time; faults latch on this attributable current flow only.
static int32_t sample(struct RaspHostContextV1* owner, int starting) {
  int64_t now = 0;
  if (rasp_host_clock_v1(&now) != 1 || now < 0 || (owner->has_clock && now < owner->last_tick)) {
    close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 9});
    return 9;
  }
  owner->last_tick = now;
  owner->has_clock = 1;
  if (starting) {
    return 0;
  }
  owner->view.session_age_ns = (uint64_t)(now - owner->session_start);
  owner->view.last_event_age_ns = (uint64_t)(now - owner->event_tick);
  owner->view.action_age_ns = owner->view.attempt == 0 ? 0 : (uint64_t)(now - owner->action_start);
  uint32_t reason = 0;
  if (owner->view.session_age_ns > UINT64_C(300000000000)) {
    reason = 6;
  } else if (owner->view.attempt != 0 && owner->view.action_age_ns > UINT64_C(120000000000)) {
    reason = 7;
  } else if (owner->view.last_event_age_ns > UINT64_C(30000000000)) {
    reason = 8;
  }
  if (reason != 0) {
    close_flow(owner, (struct HostCloseReason){.state = 7, .reason = reason});
    return 8;
  }
  return 0;
}
/// Validate exact grammar and zero tails, preserving the existing gate operation/hash rules.
static int text_valid(const char* text, size_t size, int hash) {
  size_t length = 0;
  while (length < size && text[length] != 0) {
    const char c = text[length];
    if (hash ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
             : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' ||
                 c == '-')) {
      return 0;
    }
    ++length;
  }
  if (length == 0 || length == size || (hash && length != 64)) {
    return 0;
  }
  for (size_t index = length; index < size; ++index) {
    if (text[index] != 0) {
      return 0;
    }
  }
  return 1;
}
/// Reject schema violations independently of current owner state.
static int canonical(const struct RaspHostEventV1* event) {
  if (event->kind < 1 || event->kind > 8 || event->purpose > 6 || event->secure_entry > 4 || event->lifecycle > 4 ||
      event->generation == 0 || event->generation > INT64_MAX || event->event_sequence == 0 ||
      event->event_sequence > INT64_MAX) {
    return 0;
  }
  if (event->kind == 8) {
    return zero_ref(event->session_ref) && zero_ref(event->action_ref) && event->attempt == 0 && event->purpose == 0 &&
           event->secure_entry == 0 && event->lifecycle == 0 && event->completion == 0;
  }
  if (zero_ref(event->session_ref)) {
    return 0;
  }
  if (event->kind == 1) {
    return zero_ref(event->action_ref) && event->attempt == 0 && event->purpose == 0 && event->secure_entry == 0 &&
           event->completion == 0 && event->lifecycle == 1 && event->event_sequence == 1;
  }
  if (event->kind == 4) {
    return event->purpose == 0 && event->secure_entry == 0 && event->completion == 0 &&
           ((event->attempt == 0 && zero_ref(event->action_ref)) ||
            (event->attempt >= 1 && event->attempt <= 3 && !zero_ref(event->action_ref)));
  }
  if (event->attempt < 1 || event->attempt > 3 || zero_ref(event->action_ref) || event->lifecycle != 0) {
    return 0;
  }
  if (event->kind == 2 || event->kind == 3 || event->kind == 7) {
    return event->completion == 0;
  }
  return event->purpose == 0 && event->secure_entry == 0 &&
         (event->kind == 5 ? event->completion >= 1 && event->completion <= 2 : event->completion == 0);
}
/// Attribute malformed calls conservatively; foreign/stale identities cannot poison current state.
static int attributable(const struct RaspHostContextV1* owner, const struct RaspHostEventV1* event) {
  if (event->generation != owner->view.generation || owner->view.state == 0 ||
      (owner->view.state == 6 || owner->view.state == 7 || owner->view.state == 8)) {
    return 0;
  }
  if (event->kind == 8) {
    return zero_ref(event->session_ref) && zero_ref(event->action_ref);
  }
  if (!equal_ref(event->session_ref, owner->view.session_ref)) {
    return 0;
  }
  if (event->kind == 3 || event->kind == 5 || event->kind == 6 || event->kind == 7) {
    return equal_ref(event->action_ref, owner->view.action_ref) &&
           (event->attempt == owner->view.attempt || (event->kind == 7 && event->attempt == owner->view.attempt + 1));
  }
  return 1;
}
/// Compare terminal tombstones after erasure; no refs or readiness are accepted by a repeat.
static int terminal_repeat(const struct RaspHostContextV1* owner, const struct RaspHostEventV1* event) {
  return (owner->view.state == 3 || owner->view.state == 5) && owner->has_last &&
         event->kind == owner->last_event.kind && event->generation == owner->last_event.generation &&
         event->event_sequence == owner->last_event.event_sequence && event->attempt == owner->last_event.attempt &&
         event->completion == owner->last_event.completion;
}
/// Validate an action transition without mutating state.
static int valid_action_transition(const struct RaspHostContextV1* owner, const struct RaspHostEventV1* event) {
  const uint32_t state = owner->view.state;
  switch (event->kind) {
    case 2:
      return (state == 1 || state == 3 || state == 4 || state == 5) && event->attempt == 1 && event->purpose != 0 &&
             !equal_ref(event->action_ref, owner->view.action_ref);
    case 3:
      return state == 2 && event->purpose == owner->view.purpose;
    case 7:
      return (state == 9 || state == 4) && event->attempt == owner->view.attempt + 1 &&
             event->purpose == owner->view.purpose;
    case 5:
    case 6:
      return state == 2 || state == 9;
    default:
      return 0;
  }
}
/// Preserve only retry-eligible failed action identity, otherwise erase it.
static void finish_action(struct RaspHostContextV1* owner, const struct RaspHostEventV1* event) {
  owner->view.state = event->completion == 1 ? 3U : 4U;
  if (event->kind == 6) {
    owner->view.state = 5;
  }
  owner->view.secure_entry = 0;
  if (owner->view.state != 4 || event->attempt == 3) {
    clear_bytes(owner->view.action_ref, 16);
    owner->view.purpose = 0;
    owner->view.attempt = 0;
    owner->action_start = 0;
  }
}
/// Apply a validated expected transition; no native calls, observers or host callbacks.
static int transition(struct RaspHostContextV1* owner, const struct RaspHostEventV1* event) {
  if (event->kind == 8) {
    close_flow(owner, (struct HostCloseReason){.state = 6, .reason = 16});
    return 1;
  }
  if (event->kind == 4) {
    owner->view.lifecycle = event->lifecycle;
    if (event->lifecycle != 1) {
      close_flow(owner, (struct HostCloseReason){.state = 6, .reason = 3});
    }
    return 1;
  }
  if (!valid_action_transition(owner, event)) {
    return 0;
  }
  if (event->kind == 5 || event->kind == 6) {
    finish_action(owner, event);
    return 1;
  }
  if (event->kind == 2) {
    copy_bytes(owner->view.action_ref, 16, event->action_ref);
    owner->action_start = owner->last_tick;
  }
  owner->view.state = 2;
  owner->view.purpose = event->purpose;
  owner->view.secure_entry = event->secure_entry;
  owner->view.attempt = event->attempt;
  return 1;
}

int32_t rasp_host_context_init_v1(struct RaspHostContextV1* owner, const struct RaspHostBindingV1* binding,
                                  uint32_t binding_size) {
  if (rasp_host_is_owner_thread_v1() != 1) {
    return 4;
  }
  if (owner == NULL || binding == NULL || binding_size != sizeof(*binding) ||
      overlaps(owner, sizeof(*owner), binding, sizeof(*binding))) {
    return 2;
  }
  if (owner->initialized != 0) {
    return 7;
  }
  if (binding->version != 1 || binding->struct_size != sizeof(*binding)) {
    return 3;
  }
  if (binding->require_secure_input > 1 || binding->reserved != 0 || binding->reserved_tail[0] != 0 ||
      binding->reserved_tail[1] != 0 || !text_valid(binding->operation, 33, 0) ||
      !text_valid(binding->expected_policy_sha256, 65, 1)) {
    return 2;
  }
  clear_bytes(owner, sizeof(*owner));
  owner->binding = *binding;
  owner->initialized = 1;
  owner->view.version = 1;
  owner->view.struct_size = sizeof(owner->view);
  return 0;
}
/// Admit an explicit next generation; duplicate START never refreshes age.
static int32_t start_event(struct RaspHostContextV1* owner, const struct RaspHostEventV1* event,
                           struct RaspHostContextViewV1* out) {
  if (owner->has_last && memcmp(event, &owner->last_event, sizeof(*event)) == 0) {
    return output_view(owner, (struct HostViewStatus){.status = 1, .reason = 0}, out, 0);
  }
  if (owner->view.generation == INT64_MAX) {
    return output_view(owner, (struct HostViewStatus){.status = 11, .reason = 15}, out, 0);
  }
  if (event->generation != owner->view.generation + 1) {
    if (event->generation == owner->view.generation && owner->view.event_sequence == 1 &&
        equal_ref(event->session_ref, owner->view.session_ref)) {
      close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 12});
    }
    return output_view(owner, (struct HostViewStatus){.status = 5, .reason = 10}, out, 0);
  }
  if (!zero_ref(owner->view.session_ref) && equal_ref(event->session_ref, owner->view.session_ref)) {
    return output_view(owner, (struct HostViewStatus){.status = 2, .reason = 12}, out, 0);
  }
  if (sample(owner, 1) != 0) {
    return output_view(owner, (struct HostViewStatus){.status = 9, .reason = 9}, out, 0);
  }
  const int64_t now = owner->last_tick;
  clear_bytes(&owner->view, sizeof(owner->view));
  owner->view.version = 1;
  owner->view.struct_size = sizeof(owner->view);
  owner->view.state = 1;
  owner->view.lifecycle = 1;
  owner->view.generation = event->generation;
  copy_bytes(owner->view.session_ref, 16, event->session_ref);
  owner->session_start = now;
  owner->action_start = 0;
  return -1;
}
/// Reject foreign identities before ordering/clock mutation; admit only the exact current flow.
static int32_t current_event(struct RaspHostContextV1* owner, const struct RaspHostEventV1* event,
                             struct RaspHostContextViewV1* out) {
  if (event->generation != owner->view.generation) {
    return output_view(owner, (struct HostViewStatus){.status = 5, .reason = 10}, out, 0);
  }
  if (terminal_repeat(owner, event)) {
    return output_view(owner, (struct HostViewStatus){.status = 1, .reason = 0}, out, 0);
  }
  if (event->kind != 8 && !equal_ref(event->session_ref, owner->view.session_ref)) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = 10}, out, 0);
  }
  if (owner->has_last && memcmp(event, &owner->last_event, sizeof(*event)) == 0) {
    return output_view(owner, (struct HostViewStatus){.status = 1, .reason = 0}, out, 0);
  }
  if (owner->view.state == 0 || owner->view.state == 6 || owner->view.state == 7 || owner->view.state == 8) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = owner->view.reason}, out, 0);
  }
  if (event->kind != 2 && event->kind != 8 &&
      (!equal_ref(event->action_ref, owner->view.action_ref) ||
       event->attempt != (event->kind == 7 ? owner->view.attempt + 1 : owner->view.attempt))) {
    return output_view(owner, (struct HostViewStatus){.status = 7, .reason = 12}, out, 0);
  }
  if (event->event_sequence < owner->view.event_sequence) {
    return output_view(owner, (struct HostViewStatus){.status = 6, .reason = 11}, out, 0);
  }
  if (event->event_sequence != owner->view.event_sequence + 1) {
    close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 11});
    return output_view(owner, (struct HostViewStatus){.status = 6, .reason = 11}, out, 0);
  }
  if (event->kind != 4 && event->kind != 8 && !valid_action_transition(owner, event)) {
    close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 12});
    return output_view(owner, (struct HostViewStatus){.status = 7, .reason = 12}, out, 0);
  }
  const int32_t clock_status = sample(owner, 0);
  if (clock_status != 0) {
    return output_view(owner, (struct HostViewStatus){.status = (uint32_t)clock_status, .reason = owner->view.reason},
                       out, 0);
  }
  if (!transition(owner, event)) {
    close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 12});
    return output_view(owner, (struct HostViewStatus){.status = 7, .reason = 12}, out, 0);
  }
  return -1;
}
int32_t rasp_host_context_apply_v1(struct RaspHostContextV1* owner, const struct RaspHostEventV1* event,
                                   uint32_t event_size, struct RaspHostContextViewV1* out, uint32_t out_size) {
  if (out == NULL || out_size != sizeof(*out) || owner == NULL || overlaps(owner, sizeof(*owner), out, sizeof(*out))) {
    return 2;
  }
  clear_bytes(out, sizeof(*out));
  out->status = 10;
  if (rasp_host_is_owner_thread_v1() != 1) {
    out->status = 4;
    return 4;
  }
  if (owner->initialized != 1) {
    return 10;
  }
  if (event == NULL || event_size != sizeof(*event) || overlaps(event, sizeof(*event), owner, sizeof(*owner)) ||
      overlaps(event, sizeof(*event), out, sizeof(*out))) {
    return 2;
  }
  const struct RaspHostEventV1 input = *event;
  if (input.version != 1 || input.struct_size != sizeof(input)) {
    return output_view(owner, (struct HostViewStatus){.status = 3, .reason = 12}, out, 0);
  }
  if (!canonical(&input)) {
    if (attributable(owner, &input)) {
      close_flow(owner, (struct HostCloseReason){.state = 8, .reason = 12});
    }
    return output_view(owner, (struct HostViewStatus){.status = 2, .reason = 12}, out, 0);
  }
  const int32_t admission = input.kind == 1 ? start_event(owner, &input, out) : current_event(owner, &input, out);
  if (admission != -1) {
    return admission;
  }

  owner->view.event_sequence = input.event_sequence;
  owner->view.sequence_present = 1;
  if (owner->view.state != 6) {
    owner->event_tick = owner->last_tick;
  }
  owner->last_event = input;
  owner->has_last = 1;
  if (owner->view.state == 3 || owner->view.state == 5 || (owner->view.state == 4 && input.attempt == 3)) {
    clear_bytes(owner->last_event.session_ref, 16);
    clear_bytes(owner->last_event.action_ref, 16);
    owner->last_event.purpose = 0;
    owner->last_event.secure_entry = 0;
    owner->last_event.lifecycle = 0;
  }
  if (owner->view.state == 6 && input.kind != 8) {
    clear_bytes(&owner->last_event, sizeof(owner->last_event));
    owner->has_last = 0;
  }
  return output_view(owner, (struct HostViewStatus){.status = 0, .reason = owner->view.reason}, out, 0);
}
int32_t rasp_host_context_gate_v1(struct RaspHostContextV1* owner, uint64_t generation, uint64_t sequence,
                                  uint32_t attempt, struct RaspHostContextViewV1* out, uint32_t out_size,
                                  struct RaspLocalGateResultV1* gate_out, uint32_t gate_size) {
  if (owner == NULL || out == NULL || gate_out == NULL || out_size != sizeof(*out) || gate_size != sizeof(*gate_out) ||
      overlaps(owner, sizeof(*owner), out, sizeof(*out)) ||
      overlaps(owner, sizeof(*owner), gate_out, sizeof(*gate_out)) ||
      overlaps(out, sizeof(*out), gate_out, sizeof(*gate_out))) {
    return 2;
  }
  clear_bytes(out, sizeof(*out));
  out->status = 10;
  *gate_out = (struct RaspLocalGateResultV1){0};
  gate_out->status = RASP_LOCAL_NOT_READY;
  if (rasp_host_is_owner_thread_v1() != 1) {
    out->status = 4;
    return 4;
  }
  if (owner->initialized != 1) {
    return 10;
  }
  if (generation == 0 || generation > INT64_MAX || sequence == 0 || sequence > INT64_MAX || attempt < 1 ||
      attempt > 3) {
    return output_view(owner, (struct HostViewStatus){.status = 2, .reason = 12}, out, 0);
  }
  if (generation != owner->view.generation) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = 10}, out, 0);
  }
  if (sequence != owner->view.event_sequence) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = 11}, out, 0);
  }
  if (attempt != owner->view.attempt) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = 12}, out, 0);
  }
  if (owner->view.state != 2) {
    return output_view(
        owner, (struct HostViewStatus){.status = 10, .reason = owner->view.state == 9 ? 13U : owner->view.reason}, out,
        0);
  }
  const int32_t clock_status = sample(owner, 0);
  if (clock_status != 0) {
    return output_view(owner, (struct HostViewStatus){.status = (uint32_t)clock_status, .reason = owner->view.reason},
                       out, 0);
  }
  uint32_t reason = 0;
  if (owner->view.lifecycle != 1) {
    reason = 3;
  } else if (owner->view.purpose == 0) {
    reason = 4;
  } else if (owner->binding.require_secure_input && (owner->view.purpose > 2 || owner->view.secure_entry != 1)) {
    reason = 5;
  }
  if (reason != 0) {
    return output_view(owner, (struct HostViewStatus){.status = 10, .reason = reason}, out, 1);
  }
  struct RaspLocalGateRequestV1 request = {0};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  copy_bytes(request.operation, 33, owner->binding.operation);
  copy_bytes(request.expected_policy_sha256, 65, owner->binding.expected_policy_sha256);
  owner->view.state = 9;
  const int32_t native_status = rasp_local_policy_gate_v1(&request, sizeof(request), gate_out, sizeof(*gate_out));
  if (native_status != RASP_LOCAL_OK || gate_out->status != RASP_LOCAL_OK || gate_out->abi_version != 1 ||
      gate_out->struct_size != sizeof(*gate_out) || gate_out->action > 2) {
    return output_view(owner, (struct HostViewStatus){.status = 12, .reason = 14}, out, 1);
  }
  return output_view(owner, (struct HostViewStatus){.status = 0, .reason = 0}, out, 1);
}
int32_t rasp_host_context_dispose_v1(struct RaspHostContextV1* owner) {
  if (rasp_host_is_owner_thread_v1() != 1) {
    return 4;
  }
  if (owner == NULL) {
    return 2;
  }
  clear_bytes(owner, sizeof(*owner));
  owner->initialized = 2;
  return 0;
}

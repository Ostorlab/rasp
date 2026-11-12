/// The only four public companion symbols; strict primitive validation precedes every call.
#include <algorithm>
#include <bit>
#include <cstdint>
#include <limits>
#include <span>

#include "encoding.h"
#include "entry.h"
#include "rasp/scoped_key.h"
#include "service.h"

namespace {
/// Check ranges/alignment without dereferencing hostile addresses or overflowing uintptr_t.
template <typename Input, typename Output>
std::int32_t prepare(const Input* input, std::uint32_t input_size, Output* output, std::uint32_t output_size) {
  const auto input_address = std::bit_cast<std::uintptr_t>(input);
  const auto output_address = std::bit_cast<std::uintptr_t>(output);
  if (input == nullptr || output == nullptr || input_size != sizeof(Input) || output_size != sizeof(Output) ||
      input_address % alignof(Input) != 0 || output_address % alignof(Output) != 0 ||
      input_address > std::numeric_limits<std::uintptr_t>::max() - sizeof(Input) ||
      output_address > std::numeric_limits<std::uintptr_t>::max() - sizeof(Output) ||
      (input_address < output_address + sizeof(Output) && output_address < input_address + sizeof(Input))) {
    return RASP_SK_CALL_INVALID_ARGUMENT;
  }
  *output = {};
  output->abi_version = 1;
  output->struct_size = sizeof(Output);
  if (input->abi_version != 1 || input->struct_size != sizeof(Input)) {
    return RASP_SK_CALL_UNSUPPORTED_ABI;
  }
  return RASP_SK_CALL_OK;
}
/// Validate mandatory zero bytes without interpreting them as a weaker option.
bool zero(std::span<const std::uint8_t> bytes) {
  return std::ranges::all_of(bytes, [](auto value) { return value == 0; });
}
}  // namespace
std::int32_t rasp_scoped_key_client_open_v1(const RaspScopedKeyClientSpecV1* input, std::uint32_t input_size,
                                            RaspScopedKeyClientOpenedV1* output, std::uint32_t output_size) {
  rasp::keys::EntryLease const entry;
  const auto status = prepare(input, input_size, output, output_size);
  if (status != RASP_SK_CALL_OK) {
    return status;
  }
  auto* owner = entry.get();
  if (owner == nullptr) {
    return entry.busy() ? RASP_SK_CALL_BUSY : RASP_SK_CALL_NOT_READY;
  }
  return owner->open(*input, *output);
}
std::int32_t rasp_scoped_key_submit_v1(const RaspScopedKeySubmitV1* input, std::uint32_t input_size,
                                       RaspScopedKeyAdmissionV1* output, std::uint32_t output_size) {
  rasp::keys::EntryLease const entry;
  const auto status = prepare(input, input_size, output, output_size);
  if (status != RASP_SK_CALL_OK) {
    return status;
  }
  auto* owner = entry.get();
  if (owner == nullptr) {
    return entry.busy() ? RASP_SK_CALL_BUSY : RASP_SK_CALL_NOT_READY;
  }
  return owner->submit(*input, *output);
}
std::int32_t rasp_scoped_key_take_v1(const RaspScopedKeyTakeRequestV1* input, std::uint32_t input_size,
                                     RaspScopedKeyTakeResultV1* output, std::uint32_t output_size) {
  rasp::keys::EntryLease const entry;
  const auto status = prepare(input, input_size, output, output_size);
  if (status != RASP_SK_CALL_OK) {
    return status;
  }
  if (std::ranges::any_of(input->reserved, [](auto value) { return value != 0; })) {
    return RASP_SK_CALL_INVALID_ARGUMENT;
  }
  auto* owner = entry.get();
  if (owner == nullptr) {
    return entry.busy() ? RASP_SK_CALL_BUSY : RASP_SK_CALL_NOT_READY;
  }
  return owner->take(*input, *output);
}
std::int32_t rasp_scoped_key_control_v1(const RaspScopedKeyControlV1* input, std::uint32_t input_size,
                                        RaspScopedKeyControlResultV1* output, std::uint32_t output_size) {
  rasp::keys::EntryLease const entry;
  const auto status = prepare(input, input_size, output, output_size);
  if (status != RASP_SK_CALL_OK) {
    return status;
  }
  if (input->action < RASP_SK_CANCEL || input->action > RASP_SK_CLOSE_CLIENT || input->reserved0 != 0 ||
      !zero(input->reserved) ||
      (input->action == RASP_SK_CLOSE_CLIENT ? rasp::keys::nonzero(input->target)
                                             : !rasp::keys::nonzero(input->target))) {
    return RASP_SK_CALL_INVALID_ARGUMENT;
  }
  auto* owner = entry.get();
  if (owner == nullptr) {
    return entry.busy() ? RASP_SK_CALL_BUSY : RASP_SK_CALL_NOT_READY;
  }
  return owner->control(*input, *output);
}

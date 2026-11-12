/// Exact versioned profile/message bytes and hostile input validation.
#include "encoding.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mbedtls/private/sha256.h>
#include <span>
#include <string_view>

#include "rasp/scoped_key.h"

namespace rasp::keys {
namespace {
/// Zero tails and reserved storage are mandatory, including inactive union arms.
bool zero(std::span<const std::uint8_t> bytes) {
  return std::ranges::all_of(bytes, [](auto byte) { return byte == 0; });
}
/// Finite writer over a caller-owned scratch lease.
class Writer {
 public:
  /// Borrow scratch for this encoding only.
  explicit Writer(std::span<std::uint8_t> output) : output_(output) {}
  /// Append an unsigned big-endian length or enum.
  void number(std::uint32_t value) {
    const std::array<std::uint8_t, 4> bytes{
        static_cast<std::uint8_t>(value >> 24U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value),
    };
    raw(bytes);
  }
  /// Append bytes with checked capacity.
  void raw(std::span<const std::uint8_t> bytes) {
    if (!valid_ || bytes.size() > output_.size() - used_) {
      valid_ = false;
      return;
    }
    std::ranges::copy(bytes, output_.subspan(used_).begin());
    used_ += bytes.size();
  }
  /// Append an ASCII domain and its single NUL delimiter.
  void domain(std::string_view name) {
    for (char const value : name) {
      const auto byte = static_cast<std::uint8_t>(value);
      raw(std::span{&byte, 1});
    }
    const std::uint8_t terminator = 0;
    raw(std::span{&terminator, 1});
    number(1);
    number(1);
  }
  /// Append explicit length followed by exact bytes.
  void field(std::span<const std::uint8_t> bytes) {
    number(static_cast<std::uint32_t>(bytes.size()));
    raw(bytes);
  }
  /// Return zero for any overflow rather than partial success.
  [[nodiscard]] std::size_t size() const { return valid_ ? used_ : 0; }

 private:
  std::span<std::uint8_t> output_;
  std::size_t used_ = 0;
  bool valid_ = true;
};
/// Encode the common public application identity and namespace strings.
void binding(Writer& writer, const Application& app, const RaspScopedKeyClientSpecV1& client,
             const RaspScopedKeyNamespaceSpecV1& space, bool selector) {
  writer.number(8 + app.length + client.signing_scope_length);
  writer.field(std::span(app.name).first(app.length));
  writer.field(std::span(client.signing_scope).first(client.signing_scope_length));
  if (selector) {
    writer.number(space.selector);
  }
  writer.field(std::span(space.namespace_name).first(space.namespace_length));
  writer.field(std::span(space.purpose).first(space.purpose_length));
  writer.field(std::span(space.gate_operation).first(space.gate_operation_length));
  writer.raw(space.expected_policy_sha256);
  writer.number(space.gate_mode);
}
/// Validate an exact public uncompressed P-256 point shape; provider verifies curve membership.
bool point(const RaspScopedKeyInfoV1& info) { return info.public_key_x963[0] == 4; }
}  // namespace

bool digest(std::span<const std::uint8_t> input, std::span<std::uint8_t, 32> output) {
  return mbedtls_sha256(input.data(), input.size(), output.data(), 0) == 0;
}
void wipe(std::span<std::uint8_t> memory) {
  for (volatile auto& byte : memory) {
    byte = 0;
  }
}

bool same(const RaspScopedKeyTokenV1& left, const RaspScopedKeyTokenV1& right) {
  return std::ranges::equal(left.bytes, right.bytes);
}
bool nonzero(const RaspScopedKeyTokenV1& token) { return !zero(token.bytes); }
bool text(std::span<const std::uint8_t> bytes, std::uint32_t length, bool audience) {
  if (length == 0 || length > bytes.size() || !zero(bytes.subspan(length))) {
    return false;
  }
  return std::ranges::all_of(bytes.first(length), [audience](auto value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') ||
           value == '_' || value == '.' || value == '-' || (audience && value == ':');
  });
}
bool utf8(std::span<const std::uint8_t> bytes) {
  std::size_t cursor = 0;
  while (cursor < bytes.size()) {
    const std::uint8_t lead = bytes[cursor++];
    if (lead >= 32 && lead < 127) {
      continue;
    }
    std::uint32_t value = 0;
    std::size_t count = 0;
    std::uint32_t minimum = 0;
    if (lead >= 0xc2 && lead <= 0xdf) {
      value = lead & 0x1fU;
      count = 1;
      minimum = 0x80;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      value = lead & 0x0fU;
      count = 2;
      minimum = 0x800;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      value = lead & 0x07U;
      count = 3;
      minimum = 0x10000;
    } else {
      return false;
    }
    if (count > bytes.size() - cursor) {
      return false;
    }
    for (std::size_t index = 0; index < count; ++index) {
      const auto next = bytes[cursor++];
      if ((next & 0xc0U) != 0x80U) {
        return false;
      }
      value = (value << 6U) | (next & 0x3fU);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) ||
        (value >= 0x80 && value <= 0x9f)) {
      return false;
    }
  }
  return !bytes.empty();
}
bool valid_spec(const RaspScopedKeyClientSpecV1& input) {
  if (input.namespace_count == 0 || input.namespace_count > 4 || input.signing_scope_length == 0 ||
      input.signing_scope_length > 120 || !zero(input.reserved) ||
      !zero(std::span(input.signing_scope).subspan(input.signing_scope_length)) ||
      !utf8(std::span(input.signing_scope).first(input.signing_scope_length))) {
    return false;
  }
  std::uint32_t prior = 0;
  for (std::size_t index = 0; index < input.namespace_count; ++index) {
    const auto& space = std::span(input.namespaces)[index];
    if (space.selector <= prior || space.backend_requirement < 1 || space.backend_requirement > 3 ||
        space.auth_requirement < 1 || space.auth_requirement > 2 || space.lock_requirement < 1 ||
        space.lock_requirement > 2 || space.gate_mode < 1 || space.gate_mode > 2 || !zero(space.reserved) ||
        !text(space.namespace_name, space.namespace_length) || !text(space.purpose, space.purpose_length) ||
        !text(space.gate_operation, space.gate_operation_length)) {
      return false;
    }
    for (std::size_t earlier = 0; earlier < index; ++earlier) {
      if (std::ranges::equal(space.namespace_name, std::span(input.namespaces)[earlier].namespace_name)) {
        return false;
      }
    }
    prior = space.selector;
  }
  const auto unused = std::span(input.namespaces).subspan(input.namespace_count);
  return std::ranges::all_of(unused, [](const auto& space) {
    return std::ranges::all_of(std::as_bytes(std::span{&space, 1}),
                               [](std::byte byte) { return byte == std::byte{0}; });
  });
}
bool valid_submit(const RaspScopedKeySubmitV1& input) {
  if (input.operation < RASP_SK_CREATE || input.operation > RASP_SK_RESET_NAMESPACE || input.request_ttl_ms == 0 ||
      input.request_ttl_ms > 60000) {
    return false;
  }
  const auto bytes = std::span(input.input.raw);
  if (input.operation == RASP_SK_CREATE || input.operation == RASP_SK_RESET_NAMESPACE) {
    return zero(bytes);
  }
  if (input.operation != RASP_SK_SIGN) {
    return !zero(bytes.first(16)) && zero(bytes.subspan(16));
  }
  const auto& sign = input.input.sign;
  return nonzero(sign.key) && text(sign.expected_purpose, sign.expected_purpose_length) &&
         text(sign.audience, sign.audience_length, true) && sign.transaction_length <= 4096 &&
         zero(std::span(sign.transaction).subspan(sign.transaction_length)) && !zero(sign.transaction_id) &&
         !zero(sign.challenge) &&
         (sign.interaction == RASP_SK_FORBID || sign.interaction == RASP_SK_ALLOW_SYSTEM_BIOMETRY);
}
std::size_t profile_bytes(const Application& app, const RaspScopedKeyClientSpecV1& client,
                          const RaspScopedKeyNamespaceSpecV1& space, std::span<std::uint8_t> output) {
  if (app.length == 0 || app.length > app.name.size() || !utf8(std::span(app.name).first(app.length))) {
    return 0;
  }
  Writer writer(output);
  writer.domain("Ostorlab.RASP.KeyProfile");
  binding(writer, app, client, space, true);
  writer.number(space.backend_requirement);
  writer.number(space.auth_requirement);
  writer.number(space.lock_requirement);
  return writer.size();
}
std::size_t message_bytes(const Application& app, const RaspScopedKeyClientSpecV1& client,
                          const RaspScopedKeyNamespaceSpecV1& space, const RaspScopedKeyInfoV1& key,
                          const RaspScopedKeySignInputV1& input, std::span<std::uint8_t> output) {
  Writer writer(output);
  writer.domain("Ostorlab.RASP.ScopedSign");
  binding(writer, app, client, space, false);
  writer.raw(key.profile_sha256);
  writer.raw(key.key_id.bytes);
  writer.raw(key.public_key_x963);
  writer.field(std::span(input.audience).first(input.audience_length));
  writer.raw(input.transaction_id);
  writer.raw(input.challenge);
  writer.field(std::span(input.transaction).first(input.transaction_length));
  return writer.size();
}
bool valid_binding(const RaspScopedKeyInfoV1& info, const RaspScopedKeyNamespaceSpecV1& space) {
  return info.algorithm == RASP_SK_P256_SHA256_MESSAGE_DER && info.namespace_selector == space.selector &&
         info.backend_requirement == space.backend_requirement && info.auth_requirement == space.auth_requirement &&
         info.lock_requirement == space.lock_requirement && info.purpose_length == space.purpose_length &&
         std::ranges::equal(info.purpose, space.purpose) && nonzero(info.key_id) && zero(info.reserved);
}
bool valid_info(const RaspScopedKeyInfoV1& info, const RaspScopedKeyNamespaceSpecV1& space) {
  const auto& facts = info.provenance;
  if (!valid_binding(info, space) || !point(info) || !zero(facts.reserved) || facts.backend == 0 || facts.backend > 3 ||
      facts.security_level > 5 || facts.source == 0 || facts.source > 2 || facts.key_origin != 1 ||
      facts.private_export == 0 || facts.private_export > 2 || facts.auth_observed_present != 1 ||
      facts.auth_observed != space.auth_requirement || facts.auth_hardware_enforced_present > 1 ||
      facts.auth_hardware_enforced > facts.auth_hardware_enforced_present || facts.lock_observed_present != 1 ||
      (facts.lock_observed < RASP_SK_PLATFORM_DEFAULT || facts.lock_observed > RASP_SK_UNLOCKED_REQUIRED ||
       (space.lock_requirement == RASP_SK_UNLOCKED_REQUIRED && facts.lock_observed != RASP_SK_UNLOCKED_REQUIRED)) ||
      facts.accessibility == 0 || facts.accessibility > 2 || facts.backup == 0 || facts.backup > 2 ||
      facts.attestation != 0) {
    return false;
  }
  const bool android = facts.backend == RASP_SK_ANDROID_KEYSTORE;
  const bool enclave = facts.backend == RASP_SK_APPLE_SECURE_ENCLAVE;
  if ((android &&
       (facts.source != RASP_SK_ANDROID_KEYINFO || facts.security_level == RASP_SK_SECURE_ENCLAVE ||
        facts.accessibility != RASP_SK_ANDROID_PLATFORM_PROFILE || facts.backup != RASP_SK_NO_PORTABLE_KEY_EXPORT)) ||
      (!android &&
       (facts.source != RASP_SK_APPLE_ATTRIBUTES_AND_CREATION ||
        facts.accessibility != RASP_SK_APPLE_PASSCODE_DEVICE_ONLY || facts.backup != RASP_SK_APPLE_NO_SYNC_NO_BACKUP ||
        facts.security_level == RASP_SK_TEE || facts.security_level == RASP_SK_STRONGBOX)) ||
      (enclave != (facts.security_level == RASP_SK_SECURE_ENCLAVE))) {
    return false;
  }
  const bool hardware = facts.security_level == RASP_SK_TEE || facts.security_level == RASP_SK_STRONGBOX ||
                        facts.security_level == RASP_SK_SECURE_ENCLAVE;
  return (space.backend_requirement != RASP_SK_HARDWARE_REQUIRED || hardware) &&
         (space.backend_requirement != RASP_SK_STRONGBOX_REQUIRED || facts.security_level == RASP_SK_STRONGBOX);
}
bool valid_signature(std::span<const std::uint8_t> der) {
  constexpr std::array<std::uint8_t, 32> kOrder{
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
  };
  if (der.size() < 8 || der.size() > 72 || der[0] != 0x30 || der[1] != der.size() - 2) {
    return false;
  }
  std::size_t cursor = 2;
  for (std::size_t index = 0; index < 2; ++index) {
    if (der.size() - cursor < 2 || der[cursor] != 2) {
      return false;
    }
    ++cursor;
    const std::size_t length = der[cursor];
    ++cursor;
    if (length == 0 || length > 33 || length > der.size() - cursor) {
      return false;
    }
    auto scalar = der.subspan(cursor, length);
    if ((scalar[0] & 0x80U) != 0 || (scalar.size() > 1 && scalar[0] == 0 && scalar[1] < 0x80)) {
      return false;
    }
    if (scalar[0] == 0) {
      scalar = scalar.subspan(1);
    }
    if (scalar.empty() || scalar.size() > 32 || zero(scalar) ||
        (scalar.size() == 32 && !std::ranges::lexicographical_compare(scalar, kOrder))) {
      return false;
    }
    cursor += length;
  }
  return cursor == der.size();
}
}  // namespace rasp::keys

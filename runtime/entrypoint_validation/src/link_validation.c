/// Bounded host-only ASCII tuple classifier; never caller, gate or replay authority.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rasp/entrypoint_validation.h"

_Static_assert(sizeof(struct RaspEntryRuleV1) == 676, "rule size");
_Static_assert(_Alignof(struct RaspEntryRuleV1) == 4, "rule alignment");
_Static_assert(sizeof(struct RaspEntryCheckV1) == 32, "check size");
_Static_assert(offsetof(struct RaspEntryRuleV1, scheme) == 32, "rule fields");

/// Validate distinct bounded regions without overflowing address arithmetic.
static int overlaps(const void* left, size_t left_size, const void* right, size_t right_size) {
  const uintptr_t a = (uintptr_t)left;
  const uintptr_t b = (uintptr_t)right;
  if (left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) {
    return 1;
  }
  return a < b + right_size && b < a + left_size;
}
/// Return canonical text length or capacity for an unterminated/nonzero-tail field.
static size_t text_length(const char* text, size_t capacity) {
  size_t length = 0;
  while (length < capacity && text[length] != 0) {
    ++length;
  }
  for (size_t index = length; index < capacity; ++index) {
    if (text[index] != 0) {
      return capacity;
    }
  }
  return length;
}
/// ASCII lower-case letter only, independent of process locale.
static int lower(uint8_t byte) { return byte >= 'a' && byte <= 'z'; }
/// ASCII digit only.
static int digit(uint8_t byte) { return byte >= '0' && byte <= '9'; }
/// Exact borrowed span comparison, never prefix/suffix matching.
static int equal(const uint8_t* bytes, size_t length, const char* literal, size_t capacity) {
  const size_t expected = text_length(literal, capacity);
  return expected < capacity && expected == length && memcmp(bytes, literal, length) == 0;
}
/// Accept only the delivery's exact scheme family; custom schemes start app.
static int scheme_valid(uint32_t delivery, const uint8_t* bytes, size_t length) {
  if (length == 0 || length > 32 || !lower(bytes[0])) {
    return 0;
  }
  for (size_t index = 1; index < length; ++index) {
    if (!lower(bytes[index]) && !digit(bytes[index]) && bytes[index] != '.' && bytes[index] != '-') {
      return 0;
    }
  }
  const int https = length == 5 && memcmp(bytes, "https", 5) == 0;
  const int custom = length > 4 && memcmp(bytes, "app.", 4) == 0;
  const int content = length == 7 && memcmp(bytes, "content", 7) == 0;
  if (delivery == kRaspEntryAndroidLink) {
    return https || custom;
  }
  if (delivery == kRaspEntryIosCustom) {
    return custom;
  }
  return delivery == kRaspEntryIosWeb ? https : delivery == kRaspEntryAndroidProvider && content;
}
/// Validate the terminal alphabetic DNS label without Unicode mapping.
static int final_label(const uint8_t* bytes, size_t length) {
  if (length < 2) {
    return 0;
  }
  for (size_t index = 0; index < length; ++index) {
    if (!lower(bytes[index])) {
      return 0;
    }
  }
  return 1;
}
/// Strict LDH domain with alphabetic final label; no IDNA, addresses or ports.
static int authority_valid(const uint8_t* bytes, size_t length) {
  if (length == 0 || length > 253) {
    return 0;
  }
  size_t begin = 0;
  uint32_t labels = 0;
  for (size_t index = 0; index <= length; ++index) {
    if (index != length && bytes[index] != '.') {
      if (!lower(bytes[index]) && !digit(bytes[index]) && bytes[index] != '-') {
        return 0;
      }
      continue;
    }
    const size_t count = index - begin;
    if (count == 0 || count > 63 || bytes[begin] == '-' || bytes[index - 1] == '-' ||
        (count >= 4 && memcmp(bytes + begin, "xn--", 4) == 0)) {
      return 0;
    }
    ++labels;
    if (index == length && !final_label(bytes + begin, count)) {
      return 0;
    }
    begin = index + 1;
  }
  return labels >= 2;
}
/// Strict literal path, retaining case and rejecting empty/dot segments.
static int path_valid(const uint8_t* bytes, size_t length) {
  if (length == 0 || length > 256 || bytes[0] != '/') {
    return 0;
  }
  if (length == 1) {
    return 1;
  }
  size_t begin = 1;
  uint32_t segments = 0;
  for (size_t index = 1; index <= length; ++index) {
    if (index != length && bytes[index] != '/') {
      const uint8_t byte = bytes[index];
      if (!lower(byte) && !digit(byte) && !(byte >= 'A' && byte <= 'Z') && byte != '.' && byte != '_' && byte != '~' &&
          byte != '-') {
        return 0;
      }
      continue;
    }
    const size_t count = index - begin;
    if (count == 0 || count > 64 || (count == 1 && bytes[begin] == '.') ||
        (count == 2 && bytes[begin] == '.' && bytes[begin + 1] == '.') || ++segments > 16) {
      return 0;
    }
    begin = index + 1;
  }
  return 1;
}
/// Existing native operation grammar and exact lower-case equality hash.
static int native_binding_valid(const struct RaspEntryRuleV1* rule) {
  const size_t count = text_length(rule->operation, sizeof(rule->operation));
  if (count == 0 || count > 32 || text_length(rule->expected_policy_sha256, 65) != 64) {
    return 0;
  }
  for (size_t index = 0; index < count; ++index) {
    const uint8_t byte = (uint8_t)rule->operation[index];
    if (!lower(byte) && !digit(byte) && !(byte >= 'A' && byte <= 'Z') && byte != '_' && byte != '.' && byte != '-') {
      return 0;
    }
  }
  for (size_t index = 0; index < 64; ++index) {
    const uint8_t byte = (uint8_t)rule->expected_policy_sha256[index];
    if (!digit(byte) && !(byte >= 'a' && byte <= 'f')) {
      return 0;
    }
  }
  return 1;
}
/// Return the exact local method for a previously range-validated delivery.
static uint32_t delivery_method(uint32_t delivery) {
  if (delivery == 2) {
    return 3;
  }
  return delivery == 3 ? 2U : 1U;
}
/// Validate one complete compiled rule, including unused fields and method shape.
static int rule_valid(const struct RaspEntryRuleV1* rule) {
  if (rule->version != 1 || rule->struct_size != sizeof(*rule) || rule->route_id < 1 || rule->route_id > 16 ||
      rule->delivery < 1 || rule->delivery > 5 || rule->dispatch_class < 1 || rule->dispatch_class > 4 ||
      rule->reserved != 0 || rule->reserved_tail[0] != 0 || rule->reserved_tail[1] != 0 || rule->caller_profile > 4 ||
      (rule->dispatch_class == 2 ? rule->caller_profile == 0 : rule->caller_profile != 0) ||
      !native_binding_valid(rule)) {
    return 0;
  }
  const uint32_t method = delivery_method(rule->delivery);
  if (rule->method != method ||
      ((rule->delivery == 2 || rule->delivery == 3) && rule->dispatch_class != 2 && rule->dispatch_class != 4)) {
    return 0;
  }
  const size_t scheme = text_length(rule->scheme, sizeof(rule->scheme));
  const size_t authority = text_length(rule->authority, sizeof(rule->authority));
  const size_t path = text_length(rule->path, sizeof(rule->path));
  if (rule->delivery == 2) {
    return scheme == 0 && authority == 0 && path == 0;
  }
  return scheme < sizeof(rule->scheme) && authority < sizeof(rule->authority) && path < sizeof(rule->path) &&
         scheme_valid(rule->delivery, (const uint8_t*)rule->scheme, scheme) &&
         authority_valid((const uint8_t*)rule->authority, authority) && path_valid((const uint8_t*)rule->path, path);
}
/// Reject all duplicate tuples before selecting any rule.
static int table_valid(const struct RaspEntryRuleV1* rules, uint32_t count) {
  for (uint32_t index = 0; index < count; ++index) {
    if (!rule_valid(&rules[index])) {
      return 0;
    }
    for (uint32_t prior = 0; prior < index; ++prior) {
      if (rules[index].route_id == rules[prior].route_id ||
          (rules[index].delivery == rules[prior].delivery && rules[index].method == rules[prior].method &&
           memcmp(rules[index].scheme, rules[prior].scheme, sizeof(rules[index].scheme)) == 0 &&
           memcmp(rules[index].authority, rules[prior].authority, sizeof(rules[index].authority)) == 0 &&
           memcmp(rules[index].path, rules[prior].path, sizeof(rules[index].path)) == 0)) {
        return 0;
      }
    }
  }
  return 1;
}
/// Set finite failure diagnostics without copying input or retaining a route.
static int32_t reject(struct RaspEntryCheckV1* out, uint32_t reason) {
  out->status = kRaspEntryRejected;
  out->reason = reason;
  return kRaspEntryRejected;
}
/// Private borrowed tuple offsets; no public authority, storage or binary layout.
struct EntryUrlParts {
  uint32_t colon, host_start, slash;
};
/// Validate exactly one bounded delivered URL and return finite failure reason.
static uint32_t parse_url(uint32_t delivery, const uint8_t* url, uint32_t url_size, struct EntryUrlParts* parts) {
  uint32_t colon = url_size;
  uint32_t slash = url_size;
  for (uint32_t index = 0; index < url_size; ++index) {
    const uint8_t byte = url[index];
    if (byte <= 32 || byte >= 127 || byte == '\\' || byte == '+' || byte == '%') {
      return kRaspEntryBadEncoding;
    }
    if (byte == '?' || byte == '#') {
      return kRaspEntryQueryOrFragment;
    }
    if (byte == ':' && colon == url_size) {
      colon = index;
    }
  }
  if (colon > 32 || colon + 3 >= url_size || url[colon + 1] != '/' || url[colon + 2] != '/' ||
      !scheme_valid(delivery, url, colon)) {
    return kRaspEntryBadEncoding;
  }
  for (uint32_t index = colon + 3; index < url_size; ++index) {
    if (url[index] == '/') {
      slash = index;
      break;
    }
  }
  const uint32_t host_start = colon + 3;
  if (!authority_valid(url + host_start, slash - host_start)) {
    return kRaspEntryBadAuthority;
  }
  if (slash == url_size || !path_valid(url + slash, url_size - slash)) {
    return kRaspEntryBadPath;
  }
  *parts = (struct EntryUrlParts){.colon = colon, .host_start = host_start, .slash = slash};
  return 0;
}
/// Match a parameter-free Binder route; the host must still obtain live identity.
static int32_t classify_binder(const struct RaspEntryRuleV1* rules, uint32_t count, const uint8_t* url, uint32_t size,
                               struct RaspEntryCheckV1* out) {
  if (url != NULL || size != 0) {
    return reject(out, kRaspEntryBadArgument);
  }
  for (uint32_t index = 0; index < count; ++index) {
    if (rules[index].delivery == 2 && rules[index].method == 3) {
      out->route_id = rules[index].route_id;
      out->status = kRaspEntryMatch;
      return kRaspEntryMatch;
    }
  }
  return reject(out, kRaspEntryNoRoute);
}
/// Validate and match a borrowed URL against the already checked immutable table.
static int32_t classify_url(const struct RaspEntryRuleV1* rules, uint32_t count, const uint8_t* url, uint32_t size,
                            struct RaspEntryCheckV1* out) {
  if (url == NULL || size == 0) {
    return reject(out, kRaspEntryBadArgument);
  }
  if (size > 1024) {
    return reject(out, kRaspEntryTooLong);
  }
  struct EntryUrlParts parts = {0};
  const uint32_t reason = parse_url(out->delivery, url, size, &parts);
  if (reason != 0) {
    return reject(out, reason);
  }
  for (uint32_t index = 0; index < count; ++index) {
    const struct RaspEntryRuleV1* rule = &rules[index];
    if (rule->delivery == out->delivery && rule->method == out->method && equal(url, parts.colon, rule->scheme, 33) &&
        equal(url + parts.host_start, parts.slash - parts.host_start, rule->authority, 254) &&
        equal(url + parts.slash, size - parts.slash, rule->path, 257)) {
      out->status = kRaspEntryMatch;
      out->route_id = rule->route_id;
      return kRaspEntryMatch;
    }
  }
  return reject(out, kRaspEntryNoRoute);
}
int32_t rasp_entry_classify_v1(const struct RaspEntryRuleV1* rules, uint32_t rule_count, uint32_t rule_size,
                               uint32_t rule_delivery, uint32_t rule_method, const uint8_t* url, uint32_t url_size,
                               struct RaspEntryCheckV1* out, uint32_t out_size) {
  if (out == NULL || out_size != sizeof(*out) || (uintptr_t)out % _Alignof(struct RaspEntryCheckV1) != 0 ||
      (rules != NULL &&
       overlaps(out, sizeof(*out), rules, (size_t)(rule_count <= 16 ? rule_count : 16) * sizeof(*rules))) ||
      (url != NULL && overlaps(out, sizeof(*out), url, url_size))) {
    return kRaspEntryRejected;
  }
  *out = (struct RaspEntryCheckV1){.version = 1, .struct_size = sizeof(*out), .status = kRaspEntryRejected};
  if (rules == NULL || rule_count == 0 || rule_count > 16 || rule_size != sizeof(*rules) ||
      (uintptr_t)rules % _Alignof(struct RaspEntryRuleV1) != 0 || rule_delivery < 1 || rule_delivery > 5 ||
      rule_method < 1 || rule_method > 3) {
    return reject(out, kRaspEntryBadArgument);
  }
  out->delivery = rule_delivery;
  out->method = rule_method;
  if (url != NULL && overlaps(rules, (size_t)rule_count * sizeof(*rules), url, url_size)) {
    return reject(out, kRaspEntryBadArgument);
  }
  if (!table_valid(rules, rule_count)) {
    return reject(out, kRaspEntryBadBinding);
  }
  if (rule_method != delivery_method(rule_delivery)) {
    return reject(out, kRaspEntryMethodMismatch);
  }
  return rule_delivery == 2 ? classify_binder(rules, rule_count, url, url_size, out)
                            : classify_url(rules, rule_count, url, url_size, out);
}

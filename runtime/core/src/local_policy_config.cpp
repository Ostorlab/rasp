/// Strict bounded policy parsing over yyjson and canonical typed configuration identity.
#include "local_policy_config.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <yyjson.h>

#include "local_policy_selectors.h"
#include "rasp/config.h"
#include "rasp/local_policy.h"

namespace rasp::policy_internal {
namespace {
/// Read exact decoded UTF-8 text without treating a wrong variant as a string.
std::string_view text(const yyjson_val* value) {
  return yyjson_is_str(value) ? std::string_view(yyjson_get_str(value), yyjson_get_len(value)) : std::string_view{};
}
/// Restrict operation/config identifiers to the closed ASCII name grammar.
bool name(std::string_view value, std::size_t maximum) {
  return !value.empty() && value.size() <= maximum && std::ranges::all_of(value, [](char character) {
    return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
           (character >= '0' && character <= '9') || character == '_' || character == '.' || character == '-';
  });
}
/// Check exact object keys, including decoded-key duplicates and unknown members.
bool keys(const yyjson_val* value, std::span<const std::string_view> expected) {
  if (!yyjson_is_obj(value) || yyjson_obj_size(value) != expected.size()) {
    return false;
  }
  for (const auto key : expected) {
    std::size_t count = 0;
    auto iterator = yyjson_obj_iter_with(value);
    for (const yyjson_val* member = yyjson_obj_iter_next(&iterator); member != nullptr;
         member = yyjson_obj_iter_next(&iterator)) {
      if (text(member) == key) {
        ++count;
      }
    }
    if (count != 1) {
      return false;
    }
  }
  return true;
}
/// Read a positive unsigned JSON integer without bool/float/signed coercion.
bool number(const yyjson_val* value, std::uint32_t minimum, std::uint32_t maximum, std::uint32_t& output) {
  if (!yyjson_is_uint(value)) {
    return false;
  }
  const std::uint64_t parsed = yyjson_get_uint(value);
  if (parsed < minimum || parsed > maximum) {
    return false;
  }
  output = static_cast<std::uint32_t>(parsed);
  return true;
}
/// Validate independent semantic pins before accepting any operation policy.
bool compatible_versions(const yyjson_val* value, Config& config) {
  static constexpr std::array<std::string_view, 5> kVersions{
      "schema_version", "engine_version", "report_schema_version", "report_reason_version", "native_metadata_version",
  };
  for (const auto version : kVersions) {
    std::uint32_t number_value = 0;
    if (!number(yyjson_obj_getn(value, version.data(), version.size()), 1, std::numeric_limits<std::uint32_t>::max(),
                number_value)) {
      return false;
    }
    if (number_value != 1) {
      config.local_policy.state = LocalPolicyStateKind::kUnsupported;
      return false;
    }
  }
  return true;
}
/// Find a reviewed platform rule; unknown/context/capture rows have no fallback.
const Selector* selector(std::string_view platform, std::string_view rule_id) {
  for (const auto& candidate : kSelectors) {
    if (candidate.platform == platform && candidate.rule_id == rule_id) {
      return &candidate;
    }
  }
  return nullptr;
}
/// Parse exact versioned rules and reject duplicate entries before canonical sorting.
bool rules(const yyjson_val* values, std::string_view platform, const Config& config, LocalPolicyOperation& operation) {
  if (!yyjson_is_arr(values) || yyjson_arr_size(values) == 0 || yyjson_arr_size(values) > 8) {
    return false;
  }
  auto iterator = yyjson_arr_iter_with(values);
  for (const yyjson_val* value = yyjson_arr_iter_next(&iterator); value != nullptr;
       value = yyjson_arr_iter_next(&iterator)) {
    constexpr std::array<std::string_view, 2> kKeys{"rule_id", "rule_version"};
    if (!keys(value, kKeys)) {
      return false;
    }
    const auto rule_id = text(yyjson_obj_get(value, "rule_id"));
    const Selector* const found = selector(platform, rule_id);
    std::uint32_t version = 0;
    if (!name(rule_id, 128) || found == nullptr || !number(yyjson_obj_get(value, "rule_version"), 1, 1, version) ||
        !is_check_enabled(config, found->group) ||
        std::ranges::find(operation.rules, rule_id, &LocalPolicyRule::rule_id) != operation.rules.end()) {
      return false;
    }
    operation.rules.push_back(
        {.rule_id = std::string(rule_id), .rule_version = version, .group = std::string(found->group)});
  }
  std::ranges::sort(operation.rules, {}, &LocalPolicyRule::rule_id);
  return true;
}
/// Parse at most four operations with at most eight total exact semantic selectors.
bool operations(const yyjson_val* values, const Config& config, LocalPolicy& policy) {
  if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 4 ||
      (policy.state == LocalPolicyStateKind::kGate && yyjson_arr_size(values) == 0)) {
    return false;
  }
  std::size_t total_rules = 0;
  auto iterator = yyjson_arr_iter_with(values);
  for (const yyjson_val* value = yyjson_arr_iter_next(&iterator); value != nullptr;
       value = yyjson_arr_iter_next(&iterator)) {
    constexpr std::array<std::string_view, 4> kKeys{"name", "max_evidence_age_ms", "max_cycle_duration_ms", "rules"};
    if (!keys(value, kKeys)) {
      return false;
    }
    LocalPolicyOperation operation;
    operation.name = text(yyjson_obj_get(value, "name"));
    if (!name(operation.name, 32) ||
        std::ranges::find(policy.operations, operation.name, &LocalPolicyOperation::name) != policy.operations.end() ||
        !number(yyjson_obj_get(value, "max_evidence_age_ms"), 1000, 120000, operation.max_evidence_age_ms) ||
        !number(yyjson_obj_get(value, "max_cycle_duration_ms"), 1, std::min(operation.max_evidence_age_ms, 10000U),
                operation.max_cycle_duration_ms) ||
        !rules(yyjson_obj_get(value, "rules"), policy.platform, config, operation)) {
      return false;
    }
    total_rules += operation.rules.size();
    if (total_rules > 8) {
      return false;
    }
    policy.operations.push_back(std::move(operation));
  }
  std::ranges::sort(policy.operations, {}, &LocalPolicyOperation::name);
  return true;
}
/// Quote already validated UTF-8 text with Python canonical JSON's escaping rules.
void quote(std::string& output, std::string_view value) {
  constexpr std::string_view kHex = "0123456789abcdef";
  output += '"';
  for (const char character : value) {
    switch (character) {
      case '"':
        output += "\\\"";
        break;
      case '\\':
        output += "\\\\";
        break;
      case '\b':
        output += "\\b";
        break;
      case '\f':
        output += "\\f";
        break;
      case '\n':
        output += "\\n";
        break;
      case '\r':
        output += "\\r";
        break;
      case '\t':
        output += "\\t";
        break;
      default: {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 32) {
          output += "\\u00";
          output += kHex[byte >> 4U];
          output += kHex[byte & 15U];
        } else {
          output += character;
        }
      }
    }
  }
  output += '"';
}
/// Serialize exact typed schema fields in lexical order; identifiers are ASCII.
std::string canonical_policy(const LocalPolicy& policy) {
  std::string output = "{\"catalogue_id\":";
  quote(output, kCatalogue);
  output += R"(,"engine_version":1,"mode":)";
  quote(output, policy.state == LocalPolicyStateKind::kGate ? "gate" : "report_only");
  output += R"(,"native_metadata_version":1,"operations":[)";
  bool first_operation = true;
  for (const auto& operation : policy.operations) {
    if (!first_operation) {
      output += ',';
    }
    first_operation = false;
    output += "{\"max_cycle_duration_ms\":" + std::to_string(operation.max_cycle_duration_ms) +
              ",\"max_evidence_age_ms\":" + std::to_string(operation.max_evidence_age_ms) + ",\"name\":";
    quote(output, operation.name);
    output += ",\"rules\":[";
    bool first_rule = true;
    for (const auto& rule : operation.rules) {
      if (!first_rule) {
        output += ',';
      }
      first_rule = false;
      output += "{\"rule_id\":";
      quote(output, rule.rule_id);
      output += ",\"rule_version\":" + std::to_string(rule.rule_version) + '}';
    }
    output += "]}";
  }
  output += "],\"platform\":";
  quote(output, policy.platform);
  output += ",\"policy_id\":";
  quote(output, policy.policy_id);
  output += ",\"policy_version\":" + std::to_string(policy.policy_version) +
            R"(,"report_reason_version":1,"report_schema_version":1,"schema_version":1,"scope":"host_calls_only"})";
  return output;
}
/// Verify strict explicit config without inheriting legacy mixed-array filtering.
bool explicit_config(const yyjson_val* root, const Config& config, std::string_view platform) {
  constexpr std::array<std::string_view, 3> kKeys{"build_id", "checks", "local_policy"};
  const auto* const checks = yyjson_obj_get(root, "checks");
  if (!keys(root, kKeys) || config.build_id.empty() || config.build_id.size() > 256 ||
      !yyjson_is_str(yyjson_obj_get(root, "build_id")) || !config.checks.has_value() || !yyjson_is_arr(checks) ||
      yyjson_arr_size(checks) != config.checks->size() || config.checks->size() > 64 ||
      std::ranges::any_of(config.build_id,
                          [](char value) { return static_cast<unsigned char>(value) < 32 || value == 127; })) {
    return false;
  }
  const std::span<const std::string_view> groups = platform == "android"
                                                       ? std::span<const std::string_view>(kAndroidGroups)
                                                       : std::span<const std::string_view>(kIosGroups);
  for (std::size_t index = 0; index < config.checks->size(); ++index) {
    const auto& group = (*config.checks)[index];
    if (!name(group, 96) || std::ranges::find(groups, group) == groups.end()) {
      return false;
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if ((*config.checks)[previous] == group) {
        return false;
      }
    }
  }
  return true;
}
/// Fill bounded target/operation fields separately from the policy envelope.
bool read_fields(const yyjson_val* root, Config& config, LocalPolicy& policy) {
  const auto* const value = yyjson_obj_get(root, "local_policy");
  policy.platform = text(yyjson_obj_get(value, "platform"));
  if ((policy.platform != "android" && policy.platform != "ios") ||
      text(yyjson_obj_get(value, "catalogue_id")) != kCatalogue) {
    config.local_policy.state = LocalPolicyStateKind::kUnsupported;
    return false;
  }
  const auto mode = text(yyjson_obj_get(value, "mode"));
  if ((mode != "gate" && mode != "report_only") || text(yyjson_obj_get(value, "scope")) != "host_calls_only") {
    return false;
  }
  policy.state = mode == "gate" ? LocalPolicyStateKind::kGate : LocalPolicyStateKind::kReportOnly;
  policy.policy_id = text(yyjson_obj_get(value, "policy_id"));
  return name(policy.policy_id, 64) && number(yyjson_obj_get(value, "policy_version"), 1,
                                              std::numeric_limits<std::uint32_t>::max(), policy.policy_version);
}
}  // namespace

bool config_envelope(std::string_view json) {
  if (json.empty() || json.size() > 4095) {
    return false;
  }
  int depth = 0;
  bool quoted = false;
  bool escaped = false;
  for (const char character : json) {
    if (quoted) {
      if (escaped) {
        escaped = false;
      } else if (character == '\\') {
        escaped = true;
      } else if (character == '"') {
        quoted = false;
      }
    } else if (character == '"') {
      quoted = true;
    } else if (character == '[' || character == '{') {
      if (++depth > 8) {
        return false;
      }
    } else if (character == ']' || character == '}') {
      --depth;
    }
  }
  return true;
}

void read_policy(const yyjson_val* root, Config& config) {
  const auto* const value = yyjson_obj_get(root, "local_policy");
  if (value == nullptr) {
    return;
  }
  LocalPolicy policy;
  policy.state = LocalPolicyStateKind::kInvalid;
  config.local_policy = policy;
  static constexpr std::array<std::string_view, 12> kKeys{
      "schema_version",
      "engine_version",
      "policy_id",
      "policy_version",
      "mode",
      "scope",
      "platform",
      "catalogue_id",
      "report_schema_version",
      "report_reason_version",
      "native_metadata_version",
      "operations",
  };
  if (!keys(value, kKeys)) {
    return;
  }
  if (!compatible_versions(value, config)) {
    return;
  }
  if (!read_fields(root, config, policy) || !explicit_config(root, config, policy.platform) ||
      !operations(yyjson_obj_get(value, "operations"), config, policy)) {
    return;
  }
  policy.canonical_json = canonical_policy(policy);
  if (policy.canonical_json.size() > 2048) {
    return;
  }
  config.local_policy = std::move(policy);
}

std::string canonical_config(const Config& config) {
  if (config.build_id.size() > 4095 || config.local_policy.canonical_json.size() > 2048 ||
      (config.checks.has_value() && config.checks->size() > 64)) {
    return {};
  }
  std::string output = "{\"build_id\":";
  quote(output, config.build_id);
  output += config.checks.has_value() ? ",\"checks\":[" : ",\"checks\":null";
  if (config.checks.has_value()) {
    auto groups = *config.checks;
    std::ranges::sort(groups);
    bool first = true;
    for (const auto& group : groups) {
      if (group.size() > 96) {
        return {};
      }
      if (!first) {
        output += ',';
      }
      first = false;
      quote(output, group);
    }
  }
  output += (config.checks.has_value() ? "],\"local_policy\":" : ",\"local_policy\":") +
            config.local_policy.canonical_json + '}';
  return output.size() <= 8192 ? output : std::string{};
}
}  // namespace rasp::policy_internal

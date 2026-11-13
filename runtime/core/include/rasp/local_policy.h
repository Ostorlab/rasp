/// Bounded embedded host-operation configuration; never server authority or attestation.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rasp {
/// Parsing state is independent of report availability; invalid never means absent.
enum class LocalPolicyStateKind : std::uint8_t { kAbsentReportOnly, kReportOnly, kGate, kInvalid, kUnsupported };
/// Exact reviewed rule and enabling group, never a raw-field expression.
struct LocalPolicyRule {
  std::string rule_id;
  std::uint32_t rule_version = 1;
  std::string group;
};
/// One explicitly adapted operation, bounded to eight selected rules.
struct LocalPolicyOperation {
  std::string name;
  std::uint32_t max_evidence_age_ms = 0;
  std::uint32_t max_cycle_duration_ms = 0;
  std::vector<LocalPolicyRule> rules;
};
/// Immutable after worker initialization; no live setter, remote source or trusted secret.
struct LocalPolicy {
  LocalPolicyStateKind state = LocalPolicyStateKind::kAbsentReportOnly;
  std::string policy_id;
  std::uint32_t policy_version = 0;
  std::string platform;
  std::string canonical_json = R"({"engine_version":1,"mode":"report_only","schema_version":1})";
  std::vector<LocalPolicyOperation> operations;
};
/// Hashes bounded configuration through vendored PSA SHA-256; empty on failure.
/// @param text Call-lifetime bytes, at most 8192.
/// @return Lowercase digest for configuration equality, never authenticity.
[[nodiscard]] std::string local_policy_hash(std::string_view text);
}  // namespace rasp

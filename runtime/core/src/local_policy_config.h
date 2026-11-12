/// Internal strict policy/config parsing and canonical serialization, never a host ABI.
#pragma once
#include <string>
#include <string_view>
#include <yyjson.h>

#include "rasp/config.h"

namespace rasp::policy_internal {
/// Validate exact explicit policy and its effective enabled group prerequisites.
void read_policy(const yyjson_val* root, Config& config);
/// Serialize effective config with normalized policy, excluding install identity.
[[nodiscard]] std::string canonical_config(const Config& config);
/// Reject inputs exceeding the embedded byte/depth envelope before parsing.
[[nodiscard]] bool config_envelope(std::string_view json);
}  // namespace rasp::policy_internal

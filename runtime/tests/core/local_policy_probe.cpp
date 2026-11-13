/// Actual native config/info probe for paired Python/native schema and canonical-hash fixtures.
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "local_policy_state.h"
#include "rasp/config.h"
#include "rasp/embedded_config.h"
#include "rasp/local_policy_host.h"
#include "rasp/parse_config.h"
#include "rasp/util/read_file.h"

/// Read bounded fixture bytes and print only owned status/hash scalars, never raw input.
int main(int argc, char* argv[]) {
  if (argc != 3) {
    return 2;
  }
  const auto arguments = std::span(argv, static_cast<std::size_t>(argc));
  rasp::Config config;
  if (std::string_view(arguments[1]) == "--embedded") {
    config = rasp::read_embedded_config();
  } else {
    const auto input = rasp::util::read_file(arguments[1], 4096);
    if (!input.has_value()) {
      return 2;
    }
    config = rasp::parse_config(*input);
  }
  const rasp::LocalPolicyState state(std::move(config), arguments[2]);
  auto output = std::make_unique<struct RaspLocalPolicyInfoV1>();
  static_cast<void>(state.info(*output));
  const auto text = [](std::span<const char> bytes) {
    return std::string(bytes.begin(), std::ranges::find(bytes, '\0'));
  };
  const std::string json = "{\"status\":" + std::to_string(output->status) +
                           ",\"config_state\":" + std::to_string(output->config_state) + R"(,"policy_sha256":")" +
                           text(output->policy_sha256) + R"(","effective_config_sha256":")" +
                           text(output->effective_config_sha256) + "\"}\n";
  return std::fputs(json.c_str(), stdout) < 0 ? 1 : 0;
}

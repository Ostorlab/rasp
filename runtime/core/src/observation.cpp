#include "rasp/observation.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rasp {

namespace {

[[nodiscard]] constexpr std::string_view status_name(Status status) {
  switch (status) {
    case Status::kOk:
      return "ok";
    case Status::kUnsupported:
      return "unsupported";
    case Status::kError:
      return "error";
    case Status::kTimeout:
      return "timeout";
  }
  return "unknown";
}

struct ValueText {
  [[nodiscard]] std::string operator()([[maybe_unused]] std::monostate empty) const { return ""; }
  [[nodiscard]] std::string operator()(bool value) const { return value ? "true" : "false"; }
  [[nodiscard]] std::string operator()(std::int32_t value) const { return std::to_string(value); }
  [[nodiscard]] std::string operator()(std::int64_t value) const { return std::to_string(value); }
  [[nodiscard]] std::string operator()(const std::string& value) const { return value; }
  [[nodiscard]] std::string operator()(const std::vector<std::string>& values) const {
    std::string text = "[";
    std::string_view separator;
    for (const std::string& item : values) {
      text += separator;
      text += item;
      separator = ", ";
    }
    return text + "]";
  }
};

}  // namespace

std::string describe(const Observation& observation) {
  const std::string text =
      observation.signal + "/" + observation.source + " " + std::string(status_name(observation.status));
  const std::string value = std::visit(ValueText{}, observation.value);
  return value.empty() ? text : text + " " + value;
}

}  // namespace rasp

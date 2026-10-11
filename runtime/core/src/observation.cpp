/// observed, unsupported and failed: build an observation. describe: writes one as one line of text, for logs.

#include "rasp/observation.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rasp {

namespace {

/// The lowercase name of `status`, as logs show it.
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

/// Writes each kind of observation value as text.
struct ValueText {
  /// An empty value has no text.
  [[nodiscard]] std::string operator()([[maybe_unused]] std::monostate empty) const { return ""; }
  /// A boolean as true or false.
  [[nodiscard]] std::string operator()(bool value) const { return value ? "true" : "false"; }
  /// A 64-bit integer in decimal.
  [[nodiscard]] std::string operator()(std::int64_t value) const { return std::to_string(value); }
  /// A string as it is.
  [[nodiscard]] std::string operator()(const std::string& value) const { return value; }
  /// A list of strings as [a, b, c].
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

Observation observed(std::string_view signal, std::string_view source, Value value) {
  return Observation{
      .signal = std::string(signal),
      .source = std::string(source),
      .status = Status::kOk,
      .value = std::move(value),
  };
}

Observation unsupported(std::string_view signal, std::string_view source) {
  return Observation{
      .signal = std::string(signal),
      .source = std::string(source),
      .status = Status::kUnsupported,
      .value = {},
  };
}

Observation failed(std::string_view signal, std::string_view source) {
  return Observation{
      .signal = std::string(signal),
      .source = std::string(source),
      .status = Status::kError,
      .value = {},
  };
}

std::string describe(const Observation& observation) {
  const std::string text =
      observation.signal + "/" + observation.source + " " + std::string(status_name(observation.status));
  const std::string value = std::visit(ValueText{}, observation.value);
  return value.empty() ? text : text + " " + value;
}

}  // namespace rasp

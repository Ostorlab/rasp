/// CBOR encoder: writes observations as a CBOR array of arrays for the DNS report protocol.

#include "rasp/reporting/cbor.h"

#include <cstdint>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "rasp/observation.h"

namespace rasp::reporting {

namespace {

/// Major type 0: unsigned integer.
constexpr std::uint8_t kMajorUnsigned = 0U << 5U;

/// Major type 1: negative integer.
constexpr std::uint8_t kMajorNegative = 1U << 5U;

/// Major type 3: text string.
constexpr std::uint8_t kMajorText = 3U << 5U;

/// Major type 4: array.
constexpr std::uint8_t kMajorArray = 4U << 5U;

/// Simple value false (major 7, additional 20).
constexpr std::uint8_t kFalse = 0xF4;

/// Simple value true (major 7, additional 21).
constexpr std::uint8_t kTrue = 0xF5;

/// Simple value null (major 7, additional 22).
constexpr std::uint8_t kNull = 0xF6;

/// Writes a CBOR head in shortest form: the major type combined with the argument.
///
/// @param output The byte buffer to append to.
/// @param major The major type, already shifted to the top 3 bits.
/// @param argument The argument value.
void write_head(std::vector<std::uint8_t>& output, std::uint8_t major, std::uint64_t argument) {
  if (argument < 24U) {
    output.push_back(static_cast<std::uint8_t>(major | static_cast<std::uint8_t>(argument)));
  } else if (argument < 256U) {
    output.push_back(static_cast<std::uint8_t>(major | 24U));
    output.push_back(static_cast<std::uint8_t>(argument));
  } else if (argument < 65536U) {
    output.push_back(static_cast<std::uint8_t>(major | 25U));
    output.push_back(static_cast<std::uint8_t>(argument >> 8U));
    output.push_back(static_cast<std::uint8_t>(argument));
  } else if (argument < 4294967296U) {
    output.push_back(static_cast<std::uint8_t>(major | 26U));
    output.push_back(static_cast<std::uint8_t>(argument >> 24U));
    output.push_back(static_cast<std::uint8_t>(argument >> 16U));
    output.push_back(static_cast<std::uint8_t>(argument >> 8U));
    output.push_back(static_cast<std::uint8_t>(argument));
  } else {
    output.push_back(static_cast<std::uint8_t>(major | 27U));
    output.push_back(static_cast<std::uint8_t>(argument >> 56U));
    output.push_back(static_cast<std::uint8_t>(argument >> 48U));
    output.push_back(static_cast<std::uint8_t>(argument >> 40U));
    output.push_back(static_cast<std::uint8_t>(argument >> 32U));
    output.push_back(static_cast<std::uint8_t>(argument >> 24U));
    output.push_back(static_cast<std::uint8_t>(argument >> 16U));
    output.push_back(static_cast<std::uint8_t>(argument >> 8U));
    output.push_back(static_cast<std::uint8_t>(argument));
  }
}

/// Writes a CBOR unsigned integer (major 0).
///
/// @param output The byte buffer to append to.
/// @param value The unsigned value to encode.
void write_unsigned(std::vector<std::uint8_t>& output, std::uint64_t value) {
  write_head(output, kMajorUnsigned, value);
}

/// Writes a CBOR negative integer (major 1) for a negative int64_t.
///
/// @param output The byte buffer to append to.
/// @param value The negative value to encode (must be < 0).
void write_negative(std::vector<std::uint8_t>& output, std::int64_t value) {
  write_head(output, kMajorNegative, static_cast<std::uint64_t>(-(value + 1)));
}

/// Writes a CBOR text string (major 3).
///
/// @param output The byte buffer to append to.
/// @param text The text string to encode.
void write_text(std::vector<std::uint8_t>& output, const std::string& text) {
  write_head(output, kMajorText, text.size());
  output.insert(output.end(), text.begin(), text.end());
}

/// Maps Status to its protocol integer.
///
/// @param status The observation status.
/// @return The integer the server expects: 0 ok, 1 unsupported, 2 error, 3 timeout.
[[nodiscard]] constexpr std::uint64_t status_to_uint(Status status) {
  switch (status) {
    case Status::kOk:
      return 0;
    case Status::kUnsupported:
      return 1;
    case Status::kError:
      return 2;
    case Status::kTimeout:
      return 3;
  }
  return 2;
}

/// Writes a Value variant as CBOR.
///
/// @param output The byte buffer to append to.
/// @param value The value to encode.
void write_value(std::vector<std::uint8_t>& output, const Value& value) {
  std::visit(
      [&output](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
          output.push_back(kNull);
        } else if constexpr (std::is_same_v<T, bool>) {
          output.push_back(item ? kTrue : kFalse);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
          if (item >= 0) {
            write_unsigned(output, static_cast<std::uint64_t>(item));
          } else {
            write_negative(output, item);
          }
        } else if constexpr (std::is_same_v<T, std::string>) {
          write_text(output, item);
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
          write_head(output, kMajorArray, item.size());
          for (const std::string& element : item) {
            write_text(output, element);
          }
        }
      },
      value);
}

/// Writes one observation as a 4-element CBOR array: [signal, source, status, value].
///
/// @param output The byte buffer to append to.
/// @param observation The observation to encode.
void write_observation(std::vector<std::uint8_t>& output, const Observation& observation) {
  write_head(output, kMajorArray, 4);
  write_text(output, observation.signal);
  write_text(output, observation.source);
  write_unsigned(output, status_to_uint(observation.status));
  write_value(output, observation.value);
}

}  // namespace

std::vector<std::uint8_t> encode_observations(const std::vector<Observation>& observations) {
  std::vector<std::uint8_t> output;
  write_head(output, kMajorArray, observations.size());
  for (const Observation& observation : observations) {
    write_observation(output, observation);
  }
  return output;
}

}  // namespace rasp::reporting

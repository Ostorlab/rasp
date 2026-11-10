/// spki_of: a bounded walk through the DER of an X.509 certificate, down to its SubjectPublicKeyInfo.

#include "der.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rasp::plugins::adr_pin {

namespace {

/// The tag of a SEQUENCE.
constexpr std::uint8_t kSequence = 0x30;
/// The tag of an INTEGER.
constexpr std::uint8_t kInteger = 0x02;
/// The tag of the optional version of a tbsCertificate, `[0] EXPLICIT`.
constexpr std::uint8_t kVersion = 0xa0;
/// The low five bits of a tag that mean the tag number continues in the next bytes.
constexpr std::uint8_t kMultiByteTag = 0x1f;
/// The bit of a first length byte that means the length is in the bytes after it.
constexpr std::uint8_t kLongLength = 0x80;
/// The most bytes of a long length the walk accepts: four already allow 4 GiB, far more than a certificate.
constexpr std::size_t kMaxLengthBytes = 4;

/// One DER element.
struct Element {
  /// Its tag.
  std::uint8_t tag = 0;
  /// Its content, after the tag and the length.
  std::span<const std::uint8_t> content;
  /// The whole element: tag, length and content.
  std::span<const std::uint8_t> whole;
  /// What follows the element.
  std::span<const std::uint8_t> rest;
};

/// Reads the element at the start of `input`.
///
/// @param input The bytes, starting at a tag.
/// @return The element, or nothing when it is cut short, has a multi-byte tag, or an indefinite or too long length.
[[nodiscard]] std::optional<Element> read_element(std::span<const std::uint8_t> input) {
  if (input.size() < 2) {
    return std::nullopt;
  }
  const std::uint8_t tag = input[0];
  if ((tag & kMultiByteTag) == kMultiByteTag) {
    return std::nullopt;
  }
  std::size_t header = 2;
  std::size_t length = input[1];
  if ((input[1] & kLongLength) != 0) {
    const std::size_t length_bytes = input[1] & static_cast<std::uint8_t>(~kLongLength);
    if (length_bytes == 0 || length_bytes > kMaxLengthBytes || input.size() - header < length_bytes) {
      return std::nullopt;
    }
    length = 0;
    for (const std::uint8_t byte : input.subspan(header, length_bytes)) {
      length = (length << 8U) | byte;
    }
    header += length_bytes;
  }
  if (input.size() - header < length) {
    return std::nullopt;
  }
  return Element{
      .tag = tag,
      .content = input.subspan(header, length),
      .whole = input.first(header + length),
      .rest = input.subspan(header + length),
  };
}

/// Reads the element at the start of `input` and checks its tag.
///
/// @param input The bytes, starting at a tag.
/// @param tag The tag the element must have.
/// @return The element, or nothing when it can't be read or has another tag.
[[nodiscard]] std::optional<Element> expect(std::span<const std::uint8_t> input, std::uint8_t tag) {
  std::optional<Element> element = read_element(input);
  if (!element.has_value() || element->tag != tag) {
    return std::nullopt;
  }
  return element;
}

}  // namespace

std::optional<std::span<const std::uint8_t>> spki_of(std::span<const std::uint8_t> certificate) {
  const std::optional<Element> outer = expect(certificate, kSequence);
  if (!outer.has_value() || !outer->rest.empty()) {
    return std::nullopt;
  }
  const std::optional<Element> tbs = expect(outer->content, kSequence);
  if (!tbs.has_value()) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> fields = tbs->content;
  if (!fields.empty() && fields[0] == kVersion) {
    const std::optional<Element> version = read_element(fields);
    if (!version.has_value()) {
      return std::nullopt;
    }
    fields = version->rest;
  }
  // serialNumber, then signature, issuer, validity and subject, each a SEQUENCE.
  constexpr std::array<std::uint8_t, 5> kSkipped{kInteger, kSequence, kSequence, kSequence, kSequence};
  for (const std::uint8_t tag : kSkipped) {
    const std::optional<Element> field = expect(fields, tag);
    if (!field.has_value()) {
      return std::nullopt;
    }
    fields = field->rest;
  }
  const std::optional<Element> spki = expect(fields, kSequence);
  if (!spki.has_value()) {
    return std::nullopt;
  }
  return spki->whole;
}

}  // namespace rasp::plugins::adr_pin

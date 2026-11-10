/// read_fixture and element: the certificates of tests/data, and DER elements built by hand.

#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace rasp::plugins::adr_pin {

/// Reads a file of tests/data.
///
/// The certificates there were made with `openssl req -x509 -newkey rsa:2048` (rsa.der) and with `-newkey ec -pkeyopt
/// ec_paramgen_curve:prime256v1` (ec.der). Their `.spki.der` files are the public keys openssl extracts, with
/// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der`.
///
/// @param name The file's name.
/// @return Its bytes, or nothing when it can't be read.
[[nodiscard]] inline std::vector<std::uint8_t> read_fixture(const std::string& name) {
  std::ifstream file(std::string(RASP_ADR_PIN_TEST_DATA) + "/" + name, std::ios::binary);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

/// A DER element: the tag, the length in the shortest form, and the content.
///
/// @param tag The tag.
/// @param content The content.
/// @return The element.
[[nodiscard]] inline std::vector<std::uint8_t> element(std::uint8_t tag, std::span<const std::uint8_t> content) {
  std::vector<std::uint8_t> bytes{tag};
  if (content.size() < 0x80) {
    bytes.push_back(static_cast<std::uint8_t>(content.size()));
  } else {
    bytes.push_back(0x82);
    bytes.push_back(static_cast<std::uint8_t>(content.size() >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(content.size()));
  }
  bytes.insert(bytes.end(), content.begin(), content.end());
  return bytes;
}

/// The elements one after the other.
///
/// @param elements The elements.
/// @return Their bytes, concatenated.
[[nodiscard]] inline std::vector<std::uint8_t> join(std::initializer_list<std::vector<std::uint8_t>> elements) {
  std::vector<std::uint8_t> bytes;
  for (const std::vector<std::uint8_t>& part : elements) {
    bytes.insert(bytes.end(), part.begin(), part.end());
  }
  return bytes;
}

}  // namespace rasp::plugins::adr_pin

/// Host integration driver: load real public-packer key/map/DEX entries with the production native readers and PSA.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>

#include "apk/archive.h"
#include "payload/assets.h"
#include "payload/cipher.h"
#include "payload/dex_store.h"
#include "rasp/util/read_file.h"

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: archive_probe packed.apk binary.class.Name expected.dex\n";
    return 2;
  }
  const std::span arguments(argv, static_cast<std::size_t>(argc));
  const std::string apk(arguments[1]);
  const auto key =
      rasp::android::apk::read_stored_entry(apk, rasp::android::payload::kKeyEntry, rasp::android::payload::kKeySize);
  if (!key.has_value() || key->size() != rasp::android::payload::kKeySize) {
    return 1;
  }
  const auto store = rasp::android::payload::open_dex_store(apk, *key);
  if (!store.has_value()) {
    return 1;
  }
  const auto* dex = rasp::android::payload::dex_of(*store, std::string(arguments[2]));
  if (dex == nullptr) {
    return 1;
  }
  const auto plain = rasp::android::payload::decrypt_dex(*store, *dex);
  const auto expected = rasp::util::read_file(std::string(arguments[3]), 67108864);
  if (!plain.has_value() || !expected.has_value() ||
      !std::ranges::equal(*plain, *expected,
                          [](std::uint8_t left, char right) { return left == static_cast<std::uint8_t>(right); })) {
    return 1;
  }
  std::cout << "PASS production native key/map/DEX read and PSA decryption: " << plain->size() << " DEX bytes\n";
  return 0;
}

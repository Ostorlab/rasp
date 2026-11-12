#include "common/budget.hpp"
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "raw/types.hpp"  // NO_INDEX

namespace dexsplit::raw {

/** Appends DEX-encoded values to a byte buffer: the inverse of the readers in
 *  parsing_utils.hpp.  All multi-byte integers are little-endian. */
class ByteWriter {
 public:
  std::size_t size() const noexcept { return bytes_.size(); }
  const budget::Vector<uint8_t>& bytes() const noexcept { return bytes_; }
  budget::Vector<uint8_t> take() noexcept { return std::move(bytes_); }

  void u8(uint8_t v) {
    ensure(1);
    bytes_.push_back(v);
  }
  void u16(uint16_t v) {
    ensure(2);
    bytes_.push_back(static_cast<uint8_t>(v));
    bytes_.push_back(static_cast<uint8_t>(v >> 8));
  }
  void u32(uint32_t v) {
    ensure(4);
    budget::visit();
    for (int i = 0; i < 4; ++i) {
      bytes_.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
  }
  void uleb128(uint32_t v) {
    do {
      uint8_t b = v & 0x7F;
      v >>= 7;
      u8(v != 0 ? (b | 0x80) : b);
    } while (v != 0);
  }
  void sleb128(int32_t v) {
    while (true) {
      dexsplit::budget::visit();
      uint8_t b = static_cast<uint8_t>(v) & 0x7F;
      v >>= 7;  // arithmetic shift
      bool done = (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0);
      u8(done ? b : (b | 0x80));
      if (done) {
        return;
      }
    }
  }
  /** uleb128 of value + 1, so NO_INDEX is written as 0. */
  void uleb128p1(uint32_t v) { uleb128(v + 1); }
  void append(std::span<const uint8_t> data) {
    ensure(data.size());
    budget::visit(data.size() / 64 + 1);
    bytes_.insert(bytes_.end(), data.begin(), data.end());
  }

  /** Pad with zero bytes to a multiple of @p alignment. */
  void align(std::size_t alignment) {
    while (bytes_.size() % alignment != 0) {
      dexsplit::budget::visit();
      u8(0);
    }
  }

  /** Overwrite the 4 bytes at @p at, which were written before. */
  void put_u32(std::size_t at, uint32_t v) {
    if (at > bytes_.size() || bytes_.size() - at < 4) {
      throw std::out_of_range("writer patch range");
    }
    budget::visit();
    for (int i = 0; i < 4; ++i) {
      bytes_[at + i] = static_cast<uint8_t>(v >> (8 * i));
    }
  }

 private:
  void ensure(std::size_t count) const {
    if (count > budget::kDexBytes - bytes_.size()) {
      throw budget::OutputLimit();
    }
  }
  budget::Vector<uint8_t> bytes_;
};

}  // namespace dexsplit::raw

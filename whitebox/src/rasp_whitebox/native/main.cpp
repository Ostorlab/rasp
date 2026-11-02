/// Standalone Linux AES-GCM research harness using key-specific encoded AES tables.
#include "whitebox_aes.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
using Block = std::array<std::uint8_t, 16>;
using Bytes = std::vector<std::uint8_t>;
constexpr std::size_t kMaxPlaintext = 16U * 1024U * 1024U;
constexpr std::size_t kOverhead = 32;
constexpr std::array<std::uint8_t, 4> kMagic{'W', 'B', 'X', '1'};

/// Close a descriptor on every path through file processing.
struct File {
  int descriptor;
  ~File() { if (descriptor >= 0) { close(descriptor); } }
  File(const File&) = delete;
  File& operator=(const File&) = delete;
  explicit File(int value) : descriptor(value) {}
};

/// Read a regular file into a bounded owned snapshot.
Bytes read_file(const char* path, std::size_t maximum) {
  File file(open(path, O_RDONLY | O_CLOEXEC));
  struct stat info {};
  if (file.descriptor < 0 || fstat(file.descriptor, &info) != 0 ||
      !S_ISREG(info.st_mode) || info.st_size < 0 ||
      static_cast<std::uint64_t>(info.st_size) > maximum) {
    throw std::runtime_error("cannot read input or input exceeds size limit");
  }
  Bytes result(static_cast<std::size_t>(info.st_size));
  std::size_t offset = 0;
  while (offset < result.size()) {
    const ssize_t count = read(file.descriptor, result.data() + offset, result.size() - offset);
    if (count < 0 && errno == EINTR) { continue; }
    if (count <= 0) { throw std::runtime_error("input changed or read failed"); }
    offset += static_cast<std::size_t>(count);
  }
  std::uint8_t extra = 0;
  ssize_t count;
  do { count = read(file.descriptor, &extra, 1); } while (count < 0 && errno == EINTR);
  if (count != 0) { throw std::runtime_error("input changed or read failed"); }
  return result;
}

/// Create a new private output, preserving every pre-existing path.
void write_file(const char* path, const Bytes& data) {
  File file(open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
  if (file.descriptor < 0) { throw std::runtime_error("cannot create output; it may already exist"); }
  try {
    std::size_t offset = 0;
    while (offset < data.size()) {
      const ssize_t count = write(file.descriptor, data.data() + offset, data.size() - offset);
      if (count < 0 && errno == EINTR) { continue; }
      if (count <= 0) { throw std::runtime_error("output write failed"); }
      offset += static_cast<std::size_t>(count);
    }
    const int descriptor = file.descriptor;
    file.descriptor = -1;
    if (close(descriptor) != 0) { throw std::runtime_error("output close failed"); }
  } catch (...) {
    unlink(path);
    throw;
  }
}

/// Obtain fresh public nonces; failures never substitute predictable bytes.
void random_bytes(std::uint8_t* destination, std::size_t length) {
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = getrandom(destination + offset, length - offset, 0);
    if (count < 0 && errno == EINTR) { continue; }
    if (count <= 0) { throw std::runtime_error("randomness unavailable"); }
    offset += static_cast<std::size_t>(count);
  }
}

/// Multiply in the binary field with GCM's specified bit ordering.
Block multiply(const Block& x, const Block& y) {
  Block result{};
  Block value = y;
  for (std::size_t bit = 0; bit < 128; ++bit) {
    const unsigned selected = (x[bit / 8] >> (7U - bit % 8)) & 1U;
    const auto mask = static_cast<std::uint8_t>(0U - selected);
    for (std::size_t i = 0; i < 16; ++i) { result[i] ^= value[i] & mask; }
    const unsigned low = value[15] & 1U;
    unsigned carry = 0;
    for (std::size_t i = 0; i < 16; ++i) {
      const unsigned next = value[i] & 1U;
      value[i] = static_cast<std::uint8_t>((value[i] >> 1U) | (carry << 7U));
      carry = next;
    }
    value[0] ^= static_cast<std::uint8_t>(0xe1U & (0U - low));
  }
  return result;
}

/// Absorb bytes into GHASH, padding a final partial block with zeros.
void absorb(Block& state, const Block& hash_key, const std::uint8_t* data, std::size_t length) {
  for (std::size_t offset = 0; offset < length; offset += 16) {
    const std::size_t count = std::min<std::size_t>(16, length - offset);
    for (std::size_t i = 0; i < count; ++i) { state[i] ^= data[offset + i]; }
    state = multiply(state, hash_key);
  }
}

/// Store a bit length in the GCM length block.
void put_u64(std::uint8_t* destination, std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    destination[7 - i] = static_cast<std::uint8_t>(value & 255U);
    value >>= 8U;
  }
}

/// Form J0 for a 96-bit nonce.
Block initial_counter(const std::uint8_t* nonce) {
  Block result{};
  std::copy_n(nonce, 12, result.begin());
  result[15] = 1;
  return result;
}

/// Authenticate the header and ciphertext; this baseline exposes GHASH state.
Block authentication_tag(const Bytes& record, std::size_t plaintext_size) {
  const Block zero{};
  Block hash_key{};
  wb::encrypt_block(zero.data(), hash_key.data());
  Block state{};
  absorb(state, hash_key, record.data(), 16);
  absorb(state, hash_key, record.data() + 16, plaintext_size);
  Block lengths{};
  put_u64(lengths.data(), 128);
  put_u64(lengths.data() + 8, static_cast<std::uint64_t>(plaintext_size) * 8U);
  absorb(state, hash_key, lengths.data(), lengths.size());
  const Block counter = initial_counter(record.data() + 4);
  Block mask{};
  wb::encrypt_block(counter.data(), mask.data());
  for (std::size_t i = 0; i < 16; ++i) { state[i] ^= mask[i]; }
  return state;
}

/// Apply GCM counter mode; bounded inputs cannot exhaust the 32-bit counter.
void transform(const std::uint8_t* nonce, const std::uint8_t* source,
               std::uint8_t* destination, std::size_t length) {
  Block counter = initial_counter(nonce);
  for (std::size_t offset = 0; offset < length; offset += 16) {
    for (std::size_t index = 16; index > 12; --index) {
      counter[index - 1] = static_cast<std::uint8_t>(counter[index - 1] + 1U);
      if (counter[index - 1] != 0) { break; }
    }
    Block stream{};
    wb::encrypt_block(counter.data(), stream.data());
    const std::size_t count = std::min<std::size_t>(16, length - offset);
    for (std::size_t i = 0; i < count; ++i) {
      destination[offset + i] = source[offset + i] ^ stream[i];
    }
  }
}

/// Encrypt an input with a fresh nonce and a full authentication tag.
Bytes encrypt(const Bytes& plaintext) {
  Bytes record(plaintext.size() + kOverhead);
  std::copy(kMagic.begin(), kMagic.end(), record.begin());
  random_bytes(record.data() + 4, 12);
  transform(record.data() + 4, plaintext.data(), record.data() + 16, plaintext.size());
  const Block tag = authentication_tag(record, plaintext.size());
  std::copy(tag.begin(), tag.end(), record.begin() + 16 + plaintext.size());
  return record;
}

/// Verify authentication before allocating and returning any plaintext.
Bytes decrypt(const Bytes& record) {
  if (record.size() < kOverhead || !std::equal(kMagic.begin(), kMagic.end(), record.begin())) {
    throw std::runtime_error("invalid record");
  }
  const std::size_t length = record.size() - kOverhead;
  const Block expected = authentication_tag(record, length);
  unsigned difference = 0;
  for (std::size_t i = 0; i < 16; ++i) { difference |= expected[i] ^ record[16 + length + i]; }
  if (difference != 0) { throw std::runtime_error("authentication failed"); }
  Bytes plaintext(length);
  transform(record.data() + 4, record.data() + 16, plaintext.data(), length);
  return plaintext;
}
}

/// Run one operation; the executable's key is fixed at generation time.
int main(int argc, char** argv) {
  if (argc != 4 || (std::string_view(argv[1]) != "encrypt" && std::string_view(argv[1]) != "decrypt")) {
    std::fputs("usage: whitebox encrypt|decrypt INPUT OUTPUT\n", stderr);
    return 2;
  }
  try {
    const bool encrypting = std::string_view(argv[1]) == "encrypt";
    const Bytes input = read_file(argv[2], kMaxPlaintext + (encrypting ? 0 : kOverhead));
    const Bytes output = encrypting ? encrypt(input) : decrypt(input);
    write_file(argv[3], output);
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "whitebox: %s\n", error.what());
    return 1;
  }
}

/// The Android integrity check: the file and memory hashes of librasp.so's `.text`, and its unsupported result off
/// Android. It reads the library's ELF headers through the shared reader in util/elf.h.

#include "checks/integrity.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "util/apk_file.h"
#include "util/elf.h"

#ifdef __ANDROID__
#include <algorithm>
#include <bit>
#include <dlfcn.h>
#include <link.h>
#endif

namespace rasp::android::checks {

namespace {

using util::ElfHeaders;
using util::ElfSection;
using util::find_code;
using util::find_section;
using util::read_elf_headers;
using util::read_library_file;

/// The signal of the integrity check: the hash of librasp.so's executable code.
constexpr std::string_view kTextHashSignal = "integ.text_sha256";
/// The source that reads the hash from the installed file.
constexpr std::string_view kFileSource = "file";
/// The source that reads the hash from the process's memory.
constexpr std::string_view kMemorySource = "memory";

/// The largest library file read. librasp.so is well under this, and the limit bounds what the read allocates for a
/// forged file.
constexpr std::size_t kMaxLibrarySize = std::size_t{64} << 20U;

/// The length of a SHA-256 digest, in bytes.
constexpr std::size_t kDigestSize = 32;

/// SHF_WRITE, the section flag of a writable section.
constexpr std::uint64_t kShfWrite = 0x1;
/// SHF_ALLOC, the section flag of a section the loader maps into memory.
constexpr std::uint64_t kShfAlloc = 0x2;

/// The name of the executable code section.
constexpr std::string_view kTextSectionName = ".text";

}  // namespace

std::optional<TextRegion> find_text_region(std::span<const std::uint8_t> image, std::uintptr_t load_bias) {
  const std::optional<ElfHeaders> headers = read_elf_headers(image);
  if (!headers) {
    return std::nullopt;
  }
  const std::optional<ElfSection> text = find_section(image, *headers, kTextSectionName);
  if (!text || text->size == 0 || (text->flags & kShfAlloc) == 0U || (text->flags & kShfWrite) != 0U ||
      text->file_offset > image.size() || text->size > image.size() - text->file_offset ||
      !std::in_range<std::uintptr_t>(text->address)) {
    return std::nullopt;
  }
  if (!find_code(image, *headers, {.address = text->address, .length = text->size})) {
    return std::nullopt;
  }

  return TextRegion{
      .file_offset = text->file_offset,
      .memory_address = load_bias + static_cast<std::uintptr_t>(text->address),
      .size = text->size,
  };
}

std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kDigestSize> digest{};
  std::size_t length = 0;
  const psa_status_t status =
      psa_hash_compute(PSA_ALG_SHA_256, bytes.data(), bytes.size(), digest.data(), digest.size(), &length);
  if (status != PSA_SUCCESS || length != digest.size()) {
    return std::nullopt;
  }
  constexpr std::string_view kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(digest.size() * 2);
  for (const std::uint8_t byte : digest) {
    hex.push_back(kDigits[byte >> 4U]);
    hex.push_back(kDigits[byte & 0x0FU]);
  }
  return hex;
}

std::vector<Observation> observe_text_hashes(std::string_view library_path, std::span<const std::uint8_t> text_memory) {
  const std::optional<std::vector<std::uint8_t>> file = read_library_file(library_path, kMaxLibrarySize);
  if (!file) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::span<const std::uint8_t> image(*file);
  const std::optional<TextRegion> region = find_text_region(image, 0);
  if (!region || region->memory_address > text_memory.size() ||
      region->size > text_memory.size() - region->memory_address) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }

  const std::span<const std::uint8_t> file_bytes =
      image.subspan(static_cast<std::size_t>(region->file_offset), static_cast<std::size_t>(region->size));
  const std::span<const std::uint8_t> memory_bytes =
      text_memory.subspan(static_cast<std::size_t>(region->memory_address), static_cast<std::size_t>(region->size));
  const std::optional<std::string> file_hash = sha256_hex(file_bytes);
  const std::optional<std::string> memory_hash = sha256_hex(memory_bytes);
  return {
      file_hash ? observed(kTextHashSignal, kFileSource, *file_hash) : failed(kTextHashSignal, kFileSource),
      memory_hash ? observed(kTextHashSignal, kMemorySource, *memory_hash) : failed(kTextHashSignal, kMemorySource),
  };
}

#ifdef __ANDROID__

namespace {

/// Where librasp.so is loaded: its on-disk path and its loaded image as a span starting at its load address.
struct LoadedLibrary {
  /// The path of the installed library file, under lib/<abi>/ inside the APK.
  std::string path;
  /// The load address of the library: its load bias, where the span of its image begins.
  std::uintptr_t load_bias = 0;
  /// The highest virtual address any of its loadable segments reaches, relative to the load address, which bounds the
  /// span of its image.
  std::uint64_t image_size = 0;
};

/// What dl_iterate_phdr looks for and fills in while it visits each loaded object.
struct LibrarySearch {
  /// The load address of librasp.so, found through a symbol in it.
  std::uintptr_t load_bias = 0;
  /// The library, set when the visitor finds the object whose load address matches.
  std::optional<LoadedLibrary> found;
};

/// Visits one loaded object: when its load address is the one being looked for, records its path and the extent of its
/// loadable segments. The callback dl_iterate_phdr runs for each object, so it takes C linkage and a void cookie.
// NOLINTNEXTLINE(misc-const-correctness): dl_iterate_phdr's callback takes a non-const dl_phdr_info* by its C signature.
[[nodiscard]] int visit_object(dl_phdr_info* info, std::size_t /*size*/, void* cookie) {
  auto* const search = static_cast<LibrarySearch*>(cookie);
  const dl_phdr_info& object = *info;
  if (object.dlpi_addr != search->load_bias || object.dlpi_name == nullptr) {
    return 0;
  }
  std::uint64_t image_size = 0;
  const std::span<const ElfW(Phdr)> headers(object.dlpi_phdr, object.dlpi_phnum);
  for (const ElfW(Phdr) & header : headers) {
    // NOLINTNEXTLINE(misc-include-cleaner): PT_LOAD comes from the included <link.h>.
    if (header.p_type == PT_LOAD) {
      image_size = std::max<std::uint64_t>(image_size, header.p_vaddr + header.p_memsz);
    }
  }
  search->found = LoadedLibrary{
      .path = object.dlpi_name,
      .load_bias = search->load_bias,
      .image_size = image_size,
  };
  return 1;
}

/// Finds where librasp.so is loaded, through the address of a symbol in it.
///
/// dladdr gives the library's load address from the address of `integrity`, a function in it, and dl_iterate_phdr then
/// gives the object with that load address: its path and the extent of its segments. Both are needed because dladdr
/// alone doesn't give the span of the image, and dl_iterate_phdr alone doesn't say which object is ours.
/// An object in this library, used only for its address: dladdr on it names librasp.so, with no function-pointer cast.
constexpr char kAnchor = 0;

[[nodiscard]] std::optional<LoadedLibrary> find_own_library() {
  Dl_info info{};
  if (dladdr(&kAnchor, &info) == 0 || info.dli_fbase == nullptr) {
    return std::nullopt;
  }
  LibrarySearch search{.load_bias = std::bit_cast<std::uintptr_t>(info.dli_fbase), .found = std::nullopt};
  dl_iterate_phdr(&visit_object, &search);
  return search.found;
}

}  // namespace

std::vector<Observation> integrity() {
  const std::optional<LoadedLibrary> library = find_own_library();
  if (!library || library->path.empty()) {
    return {failed(kTextHashSignal, kFileSource), failed(kTextHashSignal, kMemorySource)};
  }
  const std::span<const std::uint8_t> image(std::bit_cast<const std::uint8_t*>(library->load_bias),
                                            static_cast<std::size_t>(library->image_size));
  return observe_text_hashes(library->path, image);
}

#else

std::vector<Observation> integrity() {
  return {unsupported(kTextHashSignal, kFileSource), unsupported(kTextHashSignal, kMemorySource)};
}

#endif

}  // namespace rasp::android::checks

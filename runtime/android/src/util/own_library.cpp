#include "util/own_library.h"

#include <optional>

#ifdef __ANDROID__
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <link.h>
#include <span>
#endif

namespace rasp::android::util {

#ifdef __ANDROID__

namespace {

/// What dl_iterate_phdr looks for and fills in while it visits each loaded object.
struct LibrarySearch {
  /// The load address of the runtime's library, found through an object in it.
  std::uintptr_t load_bias = 0;
  /// The library, set when the visitor finds the object whose load address matches.
  std::optional<LoadedLibrary> found;
};

/// Records the path and extent of the visited object when its load address is the one looked for.
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

/// An object in this library, used only for its address.
constexpr char kAnchor = 0;

}  // namespace

std::optional<LoadedLibrary> find_own_library() {
  Dl_info info{};
  if (dladdr(&kAnchor, &info) == 0 || info.dli_fbase == nullptr) {
    return std::nullopt;
  }
  LibrarySearch search{.load_bias = std::bit_cast<std::uintptr_t>(info.dli_fbase), .found = std::nullopt};
  dl_iterate_phdr(&visit_object, &search);
  return search.found;
}

#else

std::optional<LoadedLibrary> find_own_library() { return std::nullopt; }

#endif

}  // namespace rasp::android::util

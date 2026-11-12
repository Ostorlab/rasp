/// Darwin search-only handles on known supported releases, with readable-directory fallback for the iOS 12 floor.
#include <fcntl.h>
#include <sys/types.h>

#include "rasp/posix/private_storage.h"

namespace rasp::posix {
int directory_search_flags() {
  if (__builtin_available(iOS 18.0, macOS 15.0, *)) {
    return O_SEARCH;
  }
  return O_RDONLY;
}
bool platform_alias_owner(uid_t owner) { return owner == 0; }
}  // namespace rasp::posix

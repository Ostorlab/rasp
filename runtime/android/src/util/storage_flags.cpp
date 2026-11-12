/// Android/Linux directory search handles traverse execute-only platform ancestors without requiring listing access.

#include "rasp/posix/private_storage.h"
#include "util/posix_file.h"

namespace rasp::posix {
int directory_search_flags() { return O_PATH; }
bool platform_alias_owner(uid_t owner) { return owner == 0 || owner == 1000; }
}  // namespace rasp::posix

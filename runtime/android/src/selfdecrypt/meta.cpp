/// The self-decrypt metadata storage. It lives alone in the plaintext .packmeta section, which the packer never
/// encrypts: the packer fills it in post-build and the load-time bootstrap reads the region table and the
/// key-derivation material from it. Freshly built every field is zero and packed is 0, so the bootstrap does nothing
/// until the packer activates it; there is deliberately no magic value and no key here.

#include "selfdecrypt/meta.h"

namespace rasp::android::selfdecrypt {

[[gnu::section(".packmeta"), gnu::used, gnu::aligned(16)]] volatile Meta g_meta = {};

}  // namespace rasp::android::selfdecrypt

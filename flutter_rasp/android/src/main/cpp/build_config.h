#ifndef RASP_BUILD_CONFIG_H
#define RASP_BUILD_CONFIG_H

/* Public per-build identity. The report key lives in the encrypted BUILD_KEY_HEX
 * registry slot, decoded at use. Without generated headers literals.def provides
 * the non-secret development key; production must register its generated key. */
#if defined(__has_include)
#if __has_include("build_generated.h")
#include "build_generated.h"
#endif
#endif

#ifndef RASP_BUILD_ID
#define RASP_BUILD_ID "test-build"
#endif


#endif

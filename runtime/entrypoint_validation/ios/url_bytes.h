/// Apple-only host source boundary for bounded delivered URL representation.
#pragma once
#include <CoreFoundation/CoreFoundation.h>

#include "rasp/entrypoint_validation.h"
#ifdef __cplusplus
extern "C" {
#endif
/// Classify delivered CF URL bytes without decoding or retaining them.
/// @param rules Borrowed compiled table. @param count At most16. @param delivery IOS_CUSTOM4/WEB5.
/// @param url Actual delivered URL. @param out Owned finite diagnostics. @return Classification only.
__attribute__((visibility("hidden"))) int32_t rasp_entry_classify_url_v1(const struct RaspEntryRuleV1* rules,
                                                                         uint32_t count, uint32_t delivery,
                                                                         CFURLRef url, struct RaspEntryCheckV1* out);
#ifdef __cplusplus
}
#endif

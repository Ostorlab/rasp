/// Actual primitive public C consumer, usable from C/ObjC/C++/ObjC++ hosts.
#pragma once
#include <stdint.h>

#include "rasp/entrypoint_validation.h"
#ifdef __cplusplus
extern "C" {
#endif
/// Classify, call the actual native gate and append one immediate harmless receipt.
/// @param rule Compiled public rule1. @param url Borrowed bytes. @param length Bounded size.
/// @param receipts Non-shared counter. @return1 only if this call performed its effect.
__attribute__((visibility("hidden"))) int32_t entry_demo_open(const struct RaspEntryRuleV1* rule, const uint8_t* url,
                                                              uint32_t length, uint32_t* receipts);
#ifdef __cplusplus
}
#endif

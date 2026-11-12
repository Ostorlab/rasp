/// Public CoreFoundation byte boundary; no URLComponents repair, heap or content export.
#include "url_bytes.h"

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <stddef.h>
#include <stdint.h>

#include "rasp/entrypoint_validation.h"

int32_t rasp_entry_classify_url_v1(const struct RaspEntryRuleV1* rules, uint32_t count, uint32_t delivery, CFURLRef url,
                                   struct RaspEntryCheckV1* out) {
  if (out == NULL) {
    return kRaspEntryRejected;
  }
  *out = (struct RaspEntryCheckV1){
      .version = 1, .struct_size = sizeof(*out), .status = kRaspEntryRejected, .reason = kRaspEntryBadArgument};
  if (delivery != 4 && delivery != 5) {
    out->status = kRaspEntryUnsupported;
    return kRaspEntryUnsupported;
  }
  if (url == NULL || CFURLGetBaseURL(url) != NULL) {
    return kRaspEntryRejected;
  }
  CFStringRef text = CFURLGetString(url);
  if (text == NULL) {
    return kRaspEntryRejected;
  }
  const CFIndex length = CFStringGetLength(text);
  if (length < 1 || length > 1024) {
    out->reason = kRaspEntryTooLong;
    return kRaspEntryRejected;
  }
  UniChar units[1024];
  uint8_t bytes[1024];
  CFStringGetCharacters(text, CFRangeMake(0, length), units);
  for (CFIndex index = 0; index < length; ++index) {
    if (units[index] <= 32 || units[index] >= 127) {
      out->reason = kRaspEntryBadEncoding;
      return kRaspEntryRejected;
    }
    bytes[index] = (uint8_t)units[index];
  }
  return rasp_entry_classify_v1(rules, count, sizeof(*rules), delivery, 1, bytes, (uint32_t)length, out, sizeof(*out));
}

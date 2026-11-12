/// Independent public C consumer; validates canonical matching and hostile tuple refusal.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rasp/entrypoint_validation.h"

/// Construct only the app-compiled harmless literal route.
static struct RaspEntryRuleV1 rule(void) {
  struct RaspEntryRuleV1 value = {0};
  value.version = 1;
  value.struct_size = sizeof(value);
  value.route_id = 1;
  value.delivery = 1;
  value.method = 1;
  value.dispatch_class = 1;
  memcpy(value.scheme, "https", 5);
  memcpy(value.authority, "links.example.invalid", 21);
  memcpy(value.path, "/open/help", 10);
  memcpy(value.operation, "append_demo_receipt", 19);
  memset(value.expected_policy_sha256, 'a', 64);
  return value;
}
/// This canonical positive case must fail before implementing the classifier.
static int canonical(void) {
  const struct RaspEntryRuleV1 binding = rule();
  struct RaspEntryCheckV1 out = {0};
  const char* url = "https://links.example.invalid/open/help";
  const int32_t status = rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)url,
                                                (uint32_t)strlen(url), &out, sizeof(out));
  if (status != kRaspEntryMatch || out.route_id != 1 || out.caller_state != 0) {
    fputs("FAIL canonical route must match without caller authority\n", stderr);
    return 1;
  }
  puts("PASS canonical public C classifier consumer");
  return 0;
}

/// Reject malformed shapes without modifying the immutable table or borrowed URL.
static int framing(void) {
  struct RaspEntryRuleV1 binding = rule();
  struct RaspEntryCheckV1 out = {0};
  out.status = 0;
  out.route_id = 16;
  if (rasp_entry_classify_v1(NULL, 0, sizeof(binding), 1, 1, NULL, 0, &out, sizeof(out)) != 1 || out.route_id != 0) {
    fputs("FAIL invalid input framing retained a preceding MATCH route\n", stderr);
    return 1;
  }
  const uint8_t url[] = "https://links.example.invalid/open/help";
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)&binding, sizeof(binding), &out,
                             sizeof(out)) != 1 ||
      out.reason != kRaspEntryBadArgument) {
    fputs("FAIL overlapping table/input was not rejected as invalid framing\n", stderr);
    return 1;
  }
  binding.reserved = 1;
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 1 ||
      out.route_id != 0)
    return 1;
  binding = rule();
  binding.path[200] = 'x';
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 1)
    return 1;
  struct RaspEntryRuleV1 duplicate[2] = {rule(), rule()};
  if (rasp_entry_classify_v1(duplicate, 2, sizeof(binding), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 1)
    return 1;
  binding = rule();
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, url, sizeof(url) - 1,
                             (struct RaspEntryCheckV1*)&binding, sizeof(out)) != 1)
    return 1;
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, url, sizeof(url) - 1, &out, sizeof(out) - 1) != 1)
    return 1;
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, NULL, 0, &out, sizeof(out)) != 1) return 1;
  return 0;
}
/// Convert one independently authored vector without using the parser under test.
static int vector_line(const char* line) {
  unsigned delivery = 0, method = 0, status = 0, route_id = 0;
  char hex[2301] = {0};
  uint8_t bytes[1150] = {0};
  if (sscanf(line, "%u%u%u%u%2300s", &delivery, &method, &status, &route_id, hex) != 5) return 1;
  size_t length = strlen(hex) / 2;
  if (hex[0] == '-' || hex[0] == '_') length = 0;
  for (size_t index = 0; index < length; ++index) {
    unsigned byte = 0;
    if (sscanf(hex + 2 * index, "%2x", &byte) != 1) return 1;
    bytes[index] = (uint8_t)byte;
  }
  const struct RaspEntryRuleV1 binding = rule();
  struct RaspEntryCheckV1 out = {0};
  const int32_t result = rasp_entry_classify_v1(&binding, 1, sizeof(binding), delivery, method,
                                                hex[0] == '-' ? NULL : bytes, (uint32_t)length, &out, sizeof(out));
  if (result != (int32_t)status || out.route_id != route_id || out.caller_state != 0) {
    fputs("FAIL independent shared tuple vector\n", stderr);
    return 1;
  }
  return 0;
}
/// Replay the same shared corpus as the Java consumer.
static int vectors(const char* path) {
  FILE* input = fopen(path, "r");
  if (input == NULL) return 1;
  char line[2400];
  int failures = 0, count = 0;
  while (fgets(line, sizeof(line), input) != NULL) {
    if (line[0] == '#') continue;
    failures += vector_line(line);
    ++count;
  }
  if (fclose(input) != 0 || count < 40) return 1;
  return failures;
}
/// Deterministic bounded mutation property: a MATCH must still equal the one full literal.
static int properties(void) {
  const struct RaspEntryRuleV1 binding = rule();
  const char* literal = "https://links.example.invalid/open/help";
  uint8_t bytes[1025];
  uint32_t seed = 0x21U;
  for (uint32_t iteration = 0; iteration < 20000; ++iteration) {
    seed = seed * 1664525U + 1013904223U;
    const uint32_t length = (seed >> 16) % 1026U;
    for (uint32_t index = 0; index < length; ++index) {
      seed = seed * 1664525U + 1013904223U;
      bytes[index] = (uint8_t)(seed >> 24);
    }
    struct RaspEntryCheckV1 out = {0}, again = {0};
    const int32_t result = rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, bytes, length, &out, sizeof(out));
    if (result != rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, bytes, length, &again, sizeof(again)) ||
        memcmp(&out, &again, sizeof(out)) != 0)
      return 1;
    if (result == 0 && (length != strlen(literal) || memcmp(bytes, literal, length) != 0)) return 1;
    if (result != 0 && out.route_id != 0) return 1;
  }
  return 0;
}
/// Exact accepted/rejected component bounds, independent of random mutation coverage.
static int bounds(void) {
  struct RaspEntryRuleV1 binding = rule();
  struct RaspEntryCheckV1 out = {0};
  char url[1025] = {0};
  memset(binding.authority, 0, sizeof(binding.authority));
  size_t offset = 0;
  for (int label = 0; label < 4; ++label) {
    const size_t length = label == 3 ? 61U : 63U;
    memset(binding.authority + offset, 'a', length);
    offset += length;
    if (label != 3) binding.authority[offset++] = '.';
  }
  memset(binding.path, 0, sizeof(binding.path));
  offset = 0;
  for (int segment = 0; segment < 4; ++segment) {
    binding.path[offset++] = '/';
    memset(binding.path + offset, 'a', 63);
    offset += 63;
  }
  memset(binding.scheme, 0, sizeof(binding.scheme));
  memcpy(binding.scheme, "app.", 4);
  memset(binding.scheme + 4, 'a', 28);
  int length = snprintf(url, sizeof(url), "%s://%s%s", binding.scheme, binding.authority, binding.path);
  if (length != 544 || rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)url, (uint32_t)length,
                                              &out, sizeof(out)) != 0)
    return 1;
  binding = rule();
  memset(binding.path, 0, sizeof(binding.path));
  for (int segment = 0; segment < 16; ++segment) {
    binding.path[segment * 2] = '/';
    binding.path[segment * 2 + 1] = 'a';
  }
  length = snprintf(url, sizeof(url), "https://links.example.invalid%s", binding.path);
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)url, (uint32_t)length, &out,
                             sizeof(out)) != 0)
    return 1;
  binding.path[32] = '/';
  binding.path[33] = 'a';
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)url, (uint32_t)length, &out,
                             sizeof(out)) != 1 ||
      out.reason != 2)
    return 1;
  binding = rule();
  memset(binding.path, 0, sizeof(binding.path));
  binding.path[0] = '/';
  length = snprintf(url, sizeof(url), "https://links.example.invalid/");
  if (rasp_entry_classify_v1(&binding, 1, sizeof(binding), 1, 1, (const uint8_t*)url, (uint32_t)length, &out,
                             sizeof(out)) != 0)
    return 1;
  return 0;
}
/// At most16 immutable distinct rules; bad later entries cannot permit an earlier match.
static int table_bounds(void) {
  struct RaspEntryRuleV1* rules = calloc(16, sizeof(*rules));
  if (rules == NULL) return 1;
  for (uint32_t index = 0; index < 16; ++index) {
    rules[index] = rule();
    rules[index].route_id = index + 1;
    memset(rules[index].path, 0, sizeof(rules[index].path));
    if (snprintf(rules[index].path, sizeof(rules[index].path), "/route%u", index + 1) < 0) {
      free(rules);
      return 1;
    }
  }
  const uint8_t url[] = "https://links.example.invalid/route16";
  struct RaspEntryCheckV1 out = {0};
  int failed = rasp_entry_classify_v1(rules, 16, sizeof(*rules), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 0 ||
               out.route_id != 16;
  rules[15].expected_policy_sha256[0] = 'A';
  failed |= rasp_entry_classify_v1(rules, 16, sizeof(*rules), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 1 ||
            out.route_id != 0;
  failed |= rasp_entry_classify_v1(rules, 17, sizeof(*rules), 1, 1, url, sizeof(url) - 1, &out, sizeof(out)) != 1 ||
            out.route_id != 0;
  free(rules);
  return failed;
}
/// Execute real host-only classifier consumers, never an authorization mock.
int main(int argc, char** argv) {
  int failures = canonical() + framing() + bounds() + table_bounds() + properties();
  if (argc == 2) failures += vectors(argv[1]);
  printf("C classifier failures: %d\n", failures);
  return failures == 0 ? 0 : 1;
}

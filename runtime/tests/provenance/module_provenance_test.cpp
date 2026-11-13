/// Real collector reductions with only native file/enumeration boundaries replaced.
#include "checks/module_provenance.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"
#include "rasp/posix/provenance.h"

namespace {
using rasp::android::checks::ExecutableImage;
using rasp::android::checks::MapRead;
using rasp::android::checks::ModuleCalls;
/// Complete fixture snapshots and file-descriptor ownership counters.
struct Source {
  std::string first = "1000-2000 r--p 0 00:01 1 /data/app/rwx-frida-x.so\n";
  std::string second;
  std::size_t offset = 0;
  int opens = 0;
  int closes = 0;
  bool deny = false;
  int open_error = 0;
  bool fail_close = false;
  bool second_read_error = false;
  int interrupted = 0;
  bool impossible_count = false;
  rasp::provenance::Error native_error = rasp::provenance::Error::kNone;
  std::vector<ExecutableImage> images;
};
/// Opens one independent snapshot without replacing the production read loop.
int open_maps(void* context) {
  auto& source = *static_cast<Source*>(context);
  source.offset = 0;
  ++source.opens;
  if (source.open_error != 0) {
    return source.open_error;
  }
  return source.deny ? -EACCES : 7;
}
/// Models kernel bytes with complete EOF and an independently changing second read.
MapRead read_maps(void* context, int /*descriptor*/, std::span<char> into) {
  auto& source = *static_cast<Source*>(context);
  if (source.interrupted > 0) {
    --source.interrupted;
    return {.size = -1, .error = EINTR};
  }
  if (source.impossible_count) {
    return {.size = static_cast<std::int64_t>(into.size()) + 1};
  }
  if (source.second_read_error && source.opens > 1) {
    return {.size = -1, .error = EACCES};
  }
  const auto& text = source.opens > 1 && !source.second.empty() ? source.second : source.first;
  const auto size = std::min(into.size(), text.size() - source.offset);
  std::copy_n(text.begin() + static_cast<std::ptrdiff_t>(source.offset), size, into.begin());
  source.offset += size;
  return {.size = static_cast<std::int64_t>(size)};
}
/// Counts exactly-once cleanup, with an injectable close error.
int close_maps(void* context, int /*descriptor*/) {
  auto& source = *static_cast<Source*>(context);
  ++source.closes;
  return source.fail_close ? -1 : 0;
}
/// Returns owned native metadata; actual interval validation remains in the collector.
rasp::provenance::Result<std::vector<ExecutableImage>> images(void* context, rasp::provenance::Budget& /*budget*/) {
  const auto& source = *static_cast<Source*>(context);
  if (source.native_error != rasp::provenance::Error::kNone) {
    return std::unexpected(source.native_error);
  }
  return source.images;
}
/// Supplies only native boundaries, never preclassified observations.
ModuleCalls calls(Source& source) {
  return {
      .maps = {.context = &source, .open = open_maps, .read = read_maps, .close = close_maps},
      .context = &source,
      .images = images,
  };
}
/// A fixed monotonic clock avoids scheduling-dependent fixture deadlines.
std::int64_t clock() { return 100; }
/// Runs the real inactive collector with public app-root evidence.
std::vector<rasp::Observation> collect(Source& source) {
  return rasp::android::checks::collect_module_provenance(
      {
          .apk_paths = {"/data/app/base.apk"},
          .native_directory = "/data/app/lib",
          .bundle_directory = {},
          .available = true,
      },
      calls(source), clock);
}
TEST(ModuleProvenance, collect_whenOnlyPathContainsExecutableCharacters_reportsNoExecutableMappings) {
  Source source;
  const auto rows = collect(source);
  ASSERT_EQ(rows.size(), 4U);
  EXPECT_EQ(rows[0].status, rasp::Status::kOk);
  EXPECT_EQ(rows[0].value, rasp::Value(std::vector<std::string>{}));
  EXPECT_EQ(source.closes, 2);
}
TEST(ModuleProvenance, collect_whenRawPermissionsAreExecutable_correlatesWithoutLeakingPaths) {
  Source source;
  source.first = "1000-2000 r-xp 0 00:01 1 /data/app/lib/libsecret.so\n";
  source.images = {{.name = "/data/app/lib/libsecret.so", .intervals = {{.start = 0x1000, .end = 0x2000, .flags = 5}}}};
  const auto rows = collect(source);
  ASSERT_EQ(rows[0].status, rasp::Status::kOk);
  const auto& values = std::get<std::vector<std::string>>(rows[0].value);
  ASSERT_EQ(values.size(), 1U);
  EXPECT_NE(values[0].find("scope=app_location"), std::string::npos);
  EXPECT_NE(values[0].find("perms=r-xp;loader=covered"), std::string::npos);
  for (const auto& row : rows) {
    EXPECT_EQ(rasp::describe(row).find("secret"), std::string::npos);
  }
}
TEST(ModuleProvenance, collect_whenMalformedRecordFollowsOutputCap_errorsInsteadOfPartialSuccess) {
  Source source;
  source.first.clear();
  for (unsigned index = 0; index < 33; ++index) {
    source.first += std::to_string(10000 + (index * 100)) + "-" + std::to_string(10050 + (index * 100)) +
                    " r-xp 0 00:01 1 /system/lib.so\n";
  }
  source.first += "broken\n";
  EXPECT_EQ(collect(source)[0].status, rasp::Status::kError);
}
TEST(ModuleProvenance, collect_whenSnapshotChanges_preservesEvidenceWithUnknownCorrelation) {
  Source source;
  source.first = "1000-2000 r-xp 0 00:01 1 /memfd:jit-cache (deleted)\n";
  source.second = "2000-3000 r-xp 0 00:01 1 /memfd:jit-cache (deleted)\n";
  const auto rows = collect(source);
  ASSERT_EQ(rows[0].status, rasp::Status::kOk);
  EXPECT_NE(rasp::describe(rows[0]).find("loader=unknown"), std::string::npos);
  EXPECT_NE(rasp::describe(rows[0]).find("backing=memfd_label"), std::string::npos);
  EXPECT_NE(rasp::describe(rows[1]).find("correlation=unstable"), std::string::npos);
}
TEST(ModuleProvenance, collect_whenCloseFails_reportsErrorAndClosesExactlyOncePerOpen) {
  Source source;
  source.fail_close = true;
  const auto rows = collect(source);
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(rows[0].value));
  EXPECT_EQ(source.closes, source.opens);
}
TEST(ModuleProvenance, collect_whenDenied_doesNotCloseAnUnownedDescriptorOrInventZero) {
  Source source;
  source.deny = true;
  const auto rows = collect(source);
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(rows[1]).find("reason=denied"), std::string::npos);
  EXPECT_EQ(source.closes, 0);
  EXPECT_EQ(rows[2].status, rasp::Status::kOk);
}
TEST(ModuleProvenance, collect_whenInterruptedOrImpossibleCounts_stopsWithinBoundsAndCleansUp) {
  Source source;
  source.interrupted = 8;
  EXPECT_EQ(collect(source)[0].status, rasp::Status::kOk);
  source.interrupted = 9;
  EXPECT_EQ(collect(source)[0].status, rasp::Status::kError);
  source.impossible_count = true;
  EXPECT_EQ(collect(source)[0].status, rasp::Status::kError);
  EXPECT_EQ(source.opens, source.closes);
}
TEST(ModuleProvenance, collect_whenSecondReadDenied_keepsFirstEvidenceButNoCorrelation) {
  Source source;
  source.first = "1000-2000 rwxp 0 00:01 1 [anon:legitimate-jit]\n";
  source.second_read_error = true;
  const auto rows = collect(source);
  EXPECT_EQ(rows[0].status, rasp::Status::kOk);
  EXPECT_NE(rasp::describe(rows[0]).find("backing=named_anon;perms=rwxp;loader=unknown"), std::string::npos);
  EXPECT_NE(rasp::describe(rows[1]).find("correlation=unavailable"), std::string::npos);
}
TEST(ModuleProvenance, collect_whenNativeIntervalOverlapsOnlyPart_reportsPartialNotInjection) {
  Source source;
  source.first = "1000-3000 r-xp 0 00:01 1 /system/lib.so\n";
  source.images = {{.name = "/system/lib.so", .intervals = {{.start = 0x1000, .end = 0x2000, .flags = 5}}}};
  const auto rows = collect(source);
  EXPECT_NE(rasp::describe(rows[0]).find("loader=partial"), std::string::npos);
}
TEST(ModuleProvenance, collect_whenNativeMetadataFails_preservesMapsWithUnknownRelation) {
  Source source;
  source.first = "1000-3000 r-xp 0 00:01 1 /data/app/lib/test.so\n";
  source.native_error = rasp::provenance::Error::kDenied;
  auto rows = collect(source);
  EXPECT_EQ(rows[0].status, rasp::Status::kOk);
  EXPECT_EQ(rows[2].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(rows[0]).find("loader=unknown"), std::string::npos);
  source.native_error = rasp::provenance::Error::kUnrecognized;
  rows = collect(source);
  EXPECT_EQ(rows[2].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(rows[3]).find("reason=io"), std::string::npos);
}
TEST(ModuleProvenance, collect_whenThirtyThreeValidEligibleRecords_samplesWithExplicitLossOnly) {
  Source source;
  source.first.clear();
  for (unsigned index = 0; index < 33; ++index) {
    source.first += std::to_string(10000 + (index * 100)) + "-" + std::to_string(10050 + (index * 100)) +
                    " r-xp 0 00:01 1 /system/lib.so\n";
  }
  const auto rows = collect(source);
  ASSERT_EQ(rows[0].status, rasp::Status::kOk);
  EXPECT_EQ(std::get<std::vector<std::string>>(rows[0].value).size(), 32U);
  EXPECT_NE(rasp::describe(rows[1]).find("eligible=33;emitted=32;sample_truncated=1"), std::string::npos);
}
TEST(ModuleProvenance, collect_whenMapRecordsAreMalformed_neverReturnsPartialSuccess) {
  const std::vector<std::string> invalid{
      "",
      "\n",
      "1000-2000 r-xp 0 00:01 1 /system/a",
      "1000-2000 rxxp 0 00:01 1 /system/a\n",
      "-1-2000 r-xp 0 00:01 1 /system/a\n",
      "fffffffffffffffff-fffffffffffffffffff r-xp 0 00:01 1 /system/a\n",
      "2000-1000 r-xp 0 00:01 1 /system/a\n",
      "1000-1000 r-xp 0 00:01 1 /system/a\n",
      "1000-2000 r-xp 0 00:01 -1 /system/a\n",
      "1000-2000 r-xp 0 00:01 1 /system/a\n1500-3000 r-xp 0 00:01 2 /system/b\n",
      std::string(8193, 'a') + "\n",
      std::string((4U * 1024U * 1024U) + 1U, 'a'),
  };
  for (const auto& input : invalid) {
    Source source;
    source.first = input;
    const auto rows = collect(source);
    EXPECT_EQ(rows[0].status, rasp::Status::kError);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(rows[0].value));
  }
}
TEST(ModuleProvenance, scope_whenRootsOrComponentPrefixesAreAmbiguous_doesNotClaimOwnership) {
  const rasp::provenance::Locations roots{
      .apk_paths = {"/data/app/base.apk"},
      .native_directory = "/data/app/lib",
      .bundle_directory = {},
      .available = true,
  };
  EXPECT_EQ(rasp::provenance::scope("/data/app/libevil/test.so", roots), "other_location");
  EXPECT_EQ(rasp::provenance::scope("/data/app/lib/../other/test.so", roots), "unresolved");
  EXPECT_EQ(rasp::provenance::scope("/data/app/base.apk!/lib/arm64-v8a/a.so", roots), "app_location");
  EXPECT_EQ(rasp::provenance::scope("/data/app/base.apk!/lib/../a.so", roots), "unresolved");
  EXPECT_EQ(rasp::provenance::scope("/system-other/lib.so", roots), "other_location");
}
#ifdef __linux__
TEST(ModuleProvenance, native_whenRealOwnProcessQueried_producesBoundedNativeImageEvidence) {
  const auto rows = rasp::android::checks::collect_module_provenance({});
  ASSERT_EQ(rows.size(), 4U);
  EXPECT_EQ(rows[2].status, rasp::Status::kOk) << rasp::describe(rows[3]);
  if (rows[2].status == rasp::Status::kOk) {
    EXPECT_LE(std::get<std::vector<std::string>>(rows[2].value).size(), 32U);
  }
}
#endif
TEST(ModuleProvenance, nativeOpen_whenForeignBoundaryReturnsMinimumInteger_reportsUnknownWithoutOverflow) {
  Source source;
  source.open_error = std::numeric_limits<int>::min();
  const auto result = collect(source);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(result[1]).find("reason=io"), std::string::npos);
  EXPECT_EQ(source.closes, 0);
}
TEST(ModuleProvenance, nativeMetadata_whenCountNameIntervalOrFlagBoundsFail_keepsMapsAndErrorsWholeNativeSource) {
  for (const auto mode : {0, 1, 2, 3, 4}) {
    Source source;
    source.first = "1000-3000 r-xp 0 00:01 1 /system/lib.so\n";
    source.images = {{.name = "/system/lib.so", .intervals = {{.start = 0x1000, .end = 0x2000, .flags = 5}}}};
    if (mode == 0) {
      source.images.resize(4097, source.images[0]);
    }
    if (mode == 1) {
      source.images[0].intervals.resize(16385, source.images[0].intervals[0]);
    }
    if (mode == 2) {
      source.images[0].name.assign(4096, 'a');
    }
    if (mode == 3) {
      source.images[0].intervals[0].end = 0;
    }
    if (mode == 4) {
      source.images[0].intervals[0].flags = 8;
    }
    const auto result = collect(source);
    EXPECT_EQ(result[0].status, rasp::Status::kOk) << mode;
    EXPECT_EQ(result[2].status, rasp::Status::kError) << mode;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result[2].value));
    EXPECT_NE(rasp::describe(result[0]).find("loader=unknown"), std::string::npos);
  }
}
TEST(ModuleProvenance, producerBoundary_whenRowsExceedWireBounds_rejectsWholeValueWithoutTruncation) {
  for (const auto mode : {0, 1, 2, 3}) {
    std::vector<std::string> rows{"v=1"};
    if (mode == 0) {
      rows[0].assign(193, 'a');
    }
    if (mode == 1) {
      rows.resize(33, "v=1");
    }
    if (mode == 2) {
      rows[0] = "v=1\nprivate";
    }
    if (mode == 3) {
      rows[0] = std::string(1, static_cast<char>(255));
    }
    const auto result = rasp::provenance::pair("hook.exec_modules", "proc_maps_v1", std::move(rows));
    EXPECT_EQ(result[0].status, rasp::Status::kError) << mode;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result[0].value));
    EXPECT_LE(std::get<std::string>(result[1].value).size(), 256U);
  }
  const auto chain =
      rasp::provenance::pair("hook.loader_chain", "application_classloader_v1", std::vector<std::string>(17, "v=1"));
  EXPECT_EQ(chain[0].status, rasp::Status::kError);
}
}  // namespace

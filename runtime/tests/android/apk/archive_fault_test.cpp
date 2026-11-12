/// Subprocess tests against production descriptor readers, with faults only at libc filesystem boundaries.

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "apk/archive.h"
#include "rasp/util/read_file.h"
#include "support/files.h"
#include "support/zip.h"

namespace {

enum class Fault : std::uint8_t {
  kNone,
  kTruncate,
  kMutate,
  kReplace,
  kShort,
  kInterrupted,
  kReadError,
  kBeforeStat,
  kAfterStat,
  kPathStat,
  kNanoseconds,
  kClose,
};

struct Injection {
  Fault fault = Fault::kNone;
  const char* path = nullptr;
  const char* replacement = nullptr;
  int descriptor = -1;
  std::size_t reads = 0;
  std::size_t stats = 0;
  std::size_t trigger_read = 1;
  bool fired = false;
};

Injection& injection() {
  static Injection state;
  return state;
}

}  // namespace

using ReadSize = decltype(pread(0, nullptr, 0, 0));
using FileOffset = decltype(lseek(0, 0, SEEK_SET));

extern "C" {
ReadSize real_pread(int descriptor, void* bytes, std::size_t count, FileOffset offset) asm("__real_pread");
int real_fstat(int descriptor, struct stat* status) asm("__real_fstat");
int real_stat(const char* path, struct stat* status) asm("__real_stat");
int real_close(int descriptor) asm("__real_close");
void* real_mmap(void* address, std::size_t length, int protection, int flags, int descriptor,
                FileOffset offset) asm("__real_mmap");

ReadSize wrap_pread(int descriptor, void* bytes, std::size_t count, FileOffset offset) asm("__wrap_pread");

ReadSize wrap_pread(int descriptor, void* bytes, std::size_t count, FileOffset offset) {
  if (descriptor != injection().descriptor || ++injection().reads != injection().trigger_read) {
    return real_pread(descriptor, bytes, count, offset);
  }
  switch (injection().fault) {
    case Fault::kTruncate:
      injection().fired = truncate(injection().path, 0) == 0;
      break;
    case Fault::kMutate: {
      std::fstream writer(injection().path, std::ios::in | std::ios::out | std::ios::binary);
      writer.put('X');
      writer.close();
      struct stat status = {};
      injection().fired = writer.good() && real_stat(injection().path, &status) == 0;
      if (injection().fired) {
        const std::array times = {
            timespec{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
            timespec{.tv_sec = status.st_mtim.tv_sec + 1, .tv_nsec = status.st_mtim.tv_nsec},
        };
        injection().fired = utimensat(AT_FDCWD, injection().path, times.data(), 0) == 0;
      }
      break;
    }
    case Fault::kReplace:
      injection().fired = rename(injection().replacement, injection().path) == 0;
      break;
    case Fault::kShort:
      injection().fired = true;
      return real_pread(descriptor, bytes, count == 0 ? 0 : count - 1, offset);
    case Fault::kInterrupted:
    case Fault::kReadError:
      injection().fired = true;
      errno = injection().fault == Fault::kInterrupted ? EINTR : EIO;
      return -1;
    default:
      break;
  }
  return real_pread(descriptor, bytes, count, offset);
}

int wrap_fstat(int descriptor, struct stat* status) asm("__wrap_fstat");

int wrap_fstat(int descriptor, struct stat* status) {
  const int result = real_fstat(descriptor, status);
  if (injection().path == nullptr) {
    return result;
  }
  injection().descriptor = descriptor;
  ++injection().stats;
  if ((injection().fault == Fault::kBeforeStat && injection().stats == 1) ||
      (injection().fault == Fault::kAfterStat && injection().stats == 2)) {
    injection().fired = true;
    errno = EIO;
    return -1;
  }
  if (injection().fault == Fault::kNanoseconds && injection().stats == 2 && result == 0) {
    status->st_mtim.tv_nsec = (status->st_mtim.tv_nsec + 1) % 1000000000;
    injection().fired = true;
  }
  return result;
}

int wrap_stat(const char* path, struct stat* status) asm("__wrap_stat");

int wrap_stat(const char* path, struct stat* status) {
  if (injection().fault == Fault::kPathStat && injection().reads > 0) {
    injection().fired = true;
    errno = EIO;
    return -1;
  }
  return real_stat(path, status);
}

int wrap_close(int descriptor) asm("__wrap_close");

int wrap_close(int descriptor) {
  const int result = real_close(descriptor);
  if (descriptor == injection().descriptor && injection().fault == Fault::kClose) {
    injection().fired = true;
    errno = EIO;
    return -1;
  }
  return result;
}

void* wrap_mmap(void* address, std::size_t length, int protection, int flags, int descriptor,
                FileOffset offset) asm("__wrap_mmap");

void* wrap_mmap(void* address, std::size_t length, int protection, int flags, int descriptor, FileOffset offset) {
  void* const result = real_mmap(address, length, protection, flags, descriptor, offset);
  if (descriptor == injection().descriptor && injection().fault == Fault::kTruncate && result != MAP_FAILED) {
    injection().fired = truncate(injection().path, 0) == 0;
  }
  return result;
}
}

namespace rasp::android::apk {
namespace {

using test_support::zip_detail::append_le;

/// A structurally valid v2 signer, used to reach success before injected cleanup/metadata failures.
[[nodiscard]] std::string prefix(std::string_view bytes) {
  std::string result;
  append_le(result, {.value = bytes.size(), .width = 4});
  return result + std::string(bytes);
}

[[nodiscard]] std::string signed_archive() {
  const auto certificate = rasp::util::read_file(std::string(RASP_TEST_CERTIFICATE_DIR) + "/signer_a.der", 65536);
  if (!certificate.has_value()) {
    return "";
  }
  std::string algorithm;
  append_le(algorithm, {.value = 0x0101, .width = 4});
  algorithm += prefix("signature bytes");
  const auto data = prefix(prefix(algorithm)) + prefix(prefix(*certificate)) + prefix("");
  const auto signer = prefix(prefix(prefix(data) + prefix(prefix(algorithm)) + prefix("public key")));
  std::string pairs;
  append_le(pairs, {.value = signer.size() + 4, .width = 8});
  append_le(pairs, {.value = 0x7109871a, .width = 4});
  pairs += signer;
  std::string block;
  append_le(block, {.value = pairs.size() + 24, .width = 8});
  block += pairs;
  append_le(block, {.value = pairs.size() + 24, .width = 8});
  block += "APK Sig Block 42";
  auto archive = test_support::zip_with_stored_entry("classes.dex", "dex");
  constexpr std::size_t kDirectoryOffset = 44;
  archive.insert(kDirectoryOffset, block);
  std::string offset;
  append_le(offset, {.value = kDirectoryOffset + block.size(), .width = 4});
  archive.replace(archive.size() - 6, 4, offset);
  return archive;
}

/// Fork keeps crash detection independent of test-framework signal handling and application process state.
[[nodiscard]] int child_read(const std::string& path, const std::string& replacement, int reader, Fault fault,
                             std::size_t trigger_read = 1) {
  const auto child = fork();
  if (child < 0) {
    return -1;
  }
  if (child == 0) {
    injection() = {
        .fault = fault,
        .path = path.c_str(),
        .replacement = replacement.c_str(),
        .trigger_read = trigger_read,
    };
    bool success = false;
    if (reader == 0) {
      success = read_stored_entry(path, "classes.dex", 32).has_value();
    } else if (reader == 1) {
      success = read_signing_certificate(path, 34).has_value();
    } else {
      success = read_signing_certificates(path, 34).has_value();
    }
    const bool expected = fault == Fault::kNone ? success : !success && injection().fired;
    _exit(expected ? 0 : 1);
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

class ArchiveFault : public ::testing::TestWithParam<int> {};

TEST_P(ArchiveFault, read_whenBoundariesFailOrArchiveChanges_returnsNoPartialSuccessWithoutSignals) {
  const test_support::TemporaryDirectory directory;
  const auto path = directory.path() + "/base.apk";
  const auto replacement = directory.path() + "/replacement.apk";
  const auto archive = signed_archive();
  ASSERT_FALSE(archive.empty());
  const std::array faults = {
      Fault::kNone,      Fault::kTruncate,    Fault::kMutate,      Fault::kReplace,
      Fault::kShort,     Fault::kInterrupted, Fault::kReadError,   Fault::kBeforeStat,
      Fault::kAfterStat, Fault::kPathStat,    Fault::kNanoseconds, Fault::kClose,
  };
  const int reader = GetParam();
  for (const Fault fault : faults) {
    SCOPED_TRACE(::testing::Message() << "reader=" << reader << " fault=" << static_cast<int>(fault));
    ASSERT_TRUE(test_support::write_file(path, archive));
    ASSERT_TRUE(test_support::write_file(replacement, archive));
    EXPECT_EQ(child_read(path, replacement, reader, fault), 0);
  }
}

TEST_P(ArchiveFault, read_whenTruncatedBeforeEachProductionRegion_failsCleanly) {
  const test_support::TemporaryDirectory directory;
  const auto path = directory.path() + "/base.apk";
  const auto archive = signed_archive();
  const int reader = GetParam();
  const std::size_t regions = reader == 0 ? 5 : 3;
  for (std::size_t region = 1; region <= regions; ++region) {
    SCOPED_TRACE(::testing::Message() << "reader=" << reader << " region=" << region);
    ASSERT_TRUE(test_support::write_file(path, archive));
    EXPECT_EQ(child_read(path, "", reader, Fault::kTruncate, region), 0);
  }
}

INSTANTIATE_TEST_SUITE_P(Readers, ArchiveFault, ::testing::Range(0, 3));

}  // namespace
}  // namespace rasp::android::apk

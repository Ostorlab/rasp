/// Isolated Apple executable replacing only the public Security entropy boundary with a failure.
#include <Security/SecRandom.h>
#include <cstddef>
#include <gtest/gtest.h>
#include <unistd.h>

#include "rasp/posix/private_storage.h"
#include "support/files.h"

/// Darwin's explicit assembly alias matches the real Security framework C symbol.
extern "C" int refuse_random(SecRandomRef random, std::size_t count, void* bytes) __asm__("_SecRandomCopyBytes");
extern "C" int refuse_random(SecRandomRef random, std::size_t count, void* bytes) {
  static_cast<void>(random);
  static_cast<void>(count);
  static_cast<void>(bytes);
  return -1;
}

namespace rasp::posix {
namespace {
TEST(ApplePrivateStorageEntropy, acquire_whenSecurityRandomFails_doesNotPublishAnIdentity) {
  const test_support::TemporaryDirectory directory;
  const auto storage = acquire_private_storage_at(directory.path());
  ASSERT_FALSE(storage.has_value());
  EXPECT_EQ(storage.error(), StorageError::kRandomUnavailable);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id.private.tmp").c_str(), F_OK), -1);
}
}  // namespace
}  // namespace rasp::posix

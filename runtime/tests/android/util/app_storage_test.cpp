/// Tests for the app's own storage on Android: the package name in the process's command line, and the path of the
/// `no_backup` folder.

#include "util/app_storage.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rasp::android::util {
namespace {

TEST(AppStorage, packageName_whenTheCommandLineHasArguments_givesTheFirstOne) {
  const std::string cmdline("com.example.bank\0--flag\0", 24);

  EXPECT_EQ(package_name(cmdline), "com.example.bank");
}

TEST(AppStorage, packageName_whenTheProcessIsPrivate_dropsItsSuffix) {
  EXPECT_EQ(package_name("com.example.bank:remote"), "com.example.bank");
}

TEST(AppStorage, packageName_whenTheCommandLineIsEmpty_givesNothing) { EXPECT_EQ(package_name(""), ""); }

TEST(AppStorage, noBackupDirectory_whenTheAppRunsForTheFirstUser_isInUserZero) {
  EXPECT_EQ(no_backup_directory("com.example.bank", 10123), "/data/user/0/com.example.bank/no_backup");
}

TEST(AppStorage, noBackupDirectory_whenTheAppRunsForAnotherUser_isInThatUser) {
  EXPECT_EQ(no_backup_directory("com.example.bank", 1010123), "/data/user/10/com.example.bank/no_backup");
}

}  // namespace
}  // namespace rasp::android::util

/// Tests for end_process, in a child process, since it ends the process that calls it.

#include "panic/end_process.h"

#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rasp::android {
namespace {

TEST(EndProcess, endProcess_whenCalled_endsTheProcessWithStatusZero) {
  const auto child = fork();
  ASSERT_NE(child, -1);
  if (child == 0) {
    end_process();
  }
  int status = 0;

  ASSERT_EQ(waitpid(child, &status, 0), child);

  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

}  // namespace
}  // namespace rasp::android

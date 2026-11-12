/// Public POSIX APIs and explicit Bionic/UAPI re-exports for the pinned Android NDK's forwarded declarations.
#pragma once

#include <fcntl.h>      // IWYU pragma: export
#include <sys/file.h>   // IWYU pragma: export
#include <sys/stat.h>   // IWYU pragma: export
#include <sys/types.h>  // IWYU pragma: export
#include <unistd.h>     // IWYU pragma: export

#ifdef __ANDROID__
#include <asm-generic/fcntl.h>  // IWYU pragma: export
#include <asm/fcntl.h>          // IWYU pragma: export
#include <bits/getentropy.h>    // IWYU pragma: export
#include <linux/fcntl.h>        // IWYU pragma: export
#include <linux/stat.h>         // IWYU pragma: export
#endif

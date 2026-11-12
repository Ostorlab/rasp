/// Host-only loaded fixture for the Android dispatch test. Each exported ABI name has a stock function body;
/// no fixture function is executed. The real dispatcher resolves these names through libc.so/libdl.so handles.

#include <unistd.h>

#define RASP_WATCHED_FUNCTION(name)                                                  \
  extern "C" __attribute__((visibility("default"))) int fixture_##name() asm(#name); \
  int fixture_##name() { return 7; }

RASP_WATCHED_FUNCTION(open)
RASP_WATCHED_FUNCTION(openat)
RASP_WATCHED_FUNCTION(fopen)
RASP_WATCHED_FUNCTION(fread)
RASP_WATCHED_FUNCTION(access)
RASP_WATCHED_FUNCTION(faccessat)
RASP_WATCHED_FUNCTION(stat)
RASP_WATCHED_FUNCTION(lstat)
RASP_WATCHED_FUNCTION(fstat)
RASP_WATCHED_FUNCTION(fstatat)
RASP_WATCHED_FUNCTION(readlink)
RASP_WATCHED_FUNCTION(opendir)
RASP_WATCHED_FUNCTION(readdir)
RASP_WATCHED_FUNCTION(syscall)
RASP_WATCHED_FUNCTION(ptrace)
RASP_WATCHED_FUNCTION(fork)
RASP_WATCHED_FUNCTION(kill)
RASP_WATCHED_FUNCTION(exit)
RASP_WATCHED_FUNCTION(_exit)
RASP_WATCHED_FUNCTION(abort)
RASP_WATCHED_FUNCTION(pthread_create)
RASP_WATCHED_FUNCTION(mmap)
RASP_WATCHED_FUNCTION(connect)
RASP_WATCHED_FUNCTION(__system_property_get)
RASP_WATCHED_FUNCTION(__system_property_find)
RASP_WATCHED_FUNCTION(__system_property_read_callback)
RASP_WATCHED_FUNCTION(dlopen)
RASP_WATCHED_FUNCTION(android_dlopen_ext)
RASP_WATCHED_FUNCTION(dlsym)
RASP_WATCHED_FUNCTION(dladdr)
RASP_WATCHED_FUNCTION(dl_iterate_phdr)

/// The read fixture has a genuine PLT/GOT relocation that the native loader applies before collection.
extern "C" __attribute__((visibility("default"))) int fixture_read() asm("read");
/// Calls an imported function so the stock control also covers relocated data beside immutable entry code.
int fixture_read() { return getpid(); }

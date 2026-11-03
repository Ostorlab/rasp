/// The source of the ELF fixtures the inline-hook and ELF reader tests read: libprologue-arm64.so, built for arm64-v8a,
/// and libprologue-armv7.so, built for armeabi-v7a as Thumb code. Each exports two functions, an IFUNC, and imports
/// getpid. Rebuild them with the Android NDK's clang, from this folder:
///
///   clang --target=aarch64-linux-android31 -O2 -fPIC -shared -nostdlib -Wl,-s -Wl,--build-id=none \
///     -o libprologue-arm64.so prologue.c
///   clang --target=armv7a-linux-androideabi31 -mthumb -O2 -fPIC -shared -nostdlib -Wl,-s -Wl,--build-id=none \
///     -o libprologue-armv7.so prologue.c

extern int getpid(void);

int rasp_fixture_first(int value) { return (value * 3) + getpid(); }

int rasp_fixture_second(int value) { return value ^ 0x5A; }

static int rasp_fixture_chosen(void) { return 7; }

static void* rasp_fixture_resolve(void) { return (void*)rasp_fixture_chosen; }

int rasp_fixture_indirect(void) __attribute__((ifunc("rasp_fixture_resolve")));

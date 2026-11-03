/// The load-time self-decrypt bootstrap of librasp.so. When the packer has encrypted the library, this runs as the
/// library's DT_INIT, before entry.cpp's rasp_start and before any DT_INIT_ARRAY constructor, and decrypts the
/// library's own .text/.rodata/.eh_frame in place. Everything it needs lives in the clear, page-isolated .stubcode /
/// .stubrodata / .packmeta sections, which the packer never encrypts, so it never touches an encrypted byte of its own.
///
/// It runs an anti-emulation gate (debugger, implausible load base, timing anomaly) first, then derives the ChaCha20
/// content key through a run-time-built "code-as-data" blob (the HKDF/SHA-256 logic is not present as .text; see
/// kdf_blob.c and gen_kdf_shovel.py), stages memory with raw svc/syscall mmap/mprotect, and decrypts each region. It is
/// reached only through a computed-branch trampoline, so a static disassembler cannot trace .init_array to the
/// decryptor.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kdf_shovel.h"
#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/meta.h"

#pragma clang section text = ".stubcode" rodata = ".stubrodata"

namespace rasp::android::selfdecrypt {

namespace {

#if defined(__aarch64__)
/// An aarch64 syscall: number in x8, arguments in x0..x5, result in x0.
long raw_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
  return x0;
}

/// Reads the aarch64 virtual counter for the timing anomaly check.
[[nodiscard]] std::uint64_t read_counter() {
  std::uint64_t v = 0;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
  return v;
}
#elif defined(__x86_64__)
/// An x86_64 syscall: number in rax, arguments in rdi/rsi/rdx/r10/r8/r9, result in rax.
long raw_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
  long ret = 0;
  register long r10 __asm__("r10") = a3;
  register long r8 __asm__("r8") = a4;
  register long r9 __asm__("r9") = a5;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

/// Reads the x86_64 timestamp counter for the timing anomaly check.
[[nodiscard]] std::uint64_t read_counter() {
  std::uint32_t lo = 0;
  std::uint32_t hi = 0;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return (static_cast<std::uint64_t>(hi) << 32) | lo;
}
#else
#error "the self-decrypt bootstrap supports only aarch64 and x86_64"
#endif

/// A raw mmap; returns MAP_FAILED on the kernel's -errno range, as libc does.
[[nodiscard]] void* raw_mmap(void* addr, std::size_t len, int prot, int flags, int fd, long offset) {
  long r = raw_syscall(__NR_mmap, reinterpret_cast<long>(addr), static_cast<long>(len), prot, flags, fd, offset);
  if (r < 0 && r >= -4095) {
    return MAP_FAILED;
  }
  return reinterpret_cast<void*>(r);
}

/// A raw mprotect; returns 0 on success, negative -errno on failure.
int raw_mprotect(void* addr, std::size_t len, int prot) {
  return static_cast<int>(
      raw_syscall(__NR_mprotect, reinterpret_cast<long>(addr), static_cast<long>(len), prot, 0, 0, 0));
}

/// A raw munmap; returns 0 on success, negative -errno on failure.
int raw_munmap(void* addr, std::size_t len) {
  return static_cast<int>(raw_syscall(__NR_munmap, reinterpret_cast<long>(addr), static_cast<long>(len), 0, 0, 0, 0));
}

/// Terminates the whole process at once; never returns.
[[noreturn]] void raw_exit_group(int code) {
  raw_syscall(__NR_exit_group, code, 0, 0, 0, 0, 0);
  __builtin_unreachable();
}

/// Rounds `v` down to a multiple of `a` (a must be a power of two).
[[nodiscard]] std::uintptr_t align_down(std::uintptr_t v, std::uintptr_t a) { return v & ~(a - 1); }

/// Rounds `v` up to a multiple of `a` (a must be a power of two).
[[nodiscard]] std::uintptr_t align_up(std::uintptr_t v, std::uintptr_t a) { return (v + a - 1) & ~(a - 1); }

/// Flushes the instruction cache over `[start, start + len)`. This is the standard aarch64 cache-maintenance sequence
/// (the one __builtin___clear_cache stands for), inlined here so the bootstrap does not call an external __clear_cache
/// that lives in the encrypted .text. On x86_64 the instruction cache is coherent, so nothing is needed.
void flush_icache(void* start, std::size_t len) {
#if defined(__aarch64__)
  std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(start);
  std::uintptr_t end = begin + len;
  std::uint64_t ctr = 0;
  __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
  std::uintptr_t dcache_line = std::uintptr_t{4} << ((ctr >> 16) & 0xf);
  std::uintptr_t icache_line = std::uintptr_t{4} << (ctr & 0xf);
  for (std::uintptr_t a = begin & ~(dcache_line - 1); a < end; a += dcache_line) {
    __asm__ volatile("dc cvau, %0" : : "r"(a) : "memory");
  }
  __asm__ volatile("dsb ish" : : : "memory");
  for (std::uintptr_t a = begin & ~(icache_line - 1); a < end; a += icache_line) {
    __asm__ volatile("ic ivau, %0" : : "r"(a) : "memory");
  }
  __asm__ volatile("dsb ish" : : : "memory");
  __asm__ volatile("isb" : : : "memory");
#else
  static_cast<void>(start);
  static_cast<void>(len);
#endif
}

/// Writes `v` as four little-endian bytes at `p`.
void store32_le(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}

/// The index of the first occurrence of `needle` in `hay`, or -1.
[[nodiscard]] long find_bytes(const std::uint8_t* hay, long hay_len, const std::uint8_t* needle, long needle_len) {
  for (long i = 0; i + needle_len <= hay_len; i++) {
    long j = 0;
    while (j < needle_len && hay[i + j] == needle[j]) {
      j++;
    }
    if (j == needle_len) {
      return i;
    }
  }
  return -1;
}

/// Aborts if a debugger is attached (TracerPid in /proc/self/status is non-zero). The path and field name are built on
/// the stack so they are not greppable; the file is read with raw syscalls, so no libc read is hooked.
void check_debugger() {
  char path[18];
  path[0] = '/';
  path[1] = 'p';
  path[2] = 'r';
  path[3] = 'o';
  path[4] = 'c';
  path[5] = '/';
  path[6] = 's';
  path[7] = 'e';
  path[8] = 'l';
  path[9] = 'f';
  path[10] = '/';
  path[11] = 's';
  path[12] = 't';
  path[13] = 'a';
  path[14] = 't';
  path[15] = 'u';
  path[16] = 's';
  path[17] = '\0';

  std::uint8_t needle[10];
  needle[0] = 'T';
  needle[1] = 'r';
  needle[2] = 'a';
  needle[3] = 'c';
  needle[4] = 'e';
  needle[5] = 'r';
  needle[6] = 'P';
  needle[7] = 'i';
  needle[8] = 'd';
  needle[9] = ':';

  long fd = raw_syscall(__NR_openat, static_cast<long>(AT_FDCWD), reinterpret_cast<long>(path), O_RDONLY, 0, 0, 0);
  if (fd < 0) {
    return;
  }
  std::uint8_t buf[512];
  long n = raw_syscall(__NR_read, fd, reinterpret_cast<long>(buf), static_cast<long>(sizeof(buf)), 0, 0, 0);
  raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
  if (n <= 0) {
    return;
  }

  long pos = find_bytes(buf, n, needle, 10);
  if (pos < 0) {
    return;
  }
  long k = pos + 10;
  while (k < n && (buf[k] == ' ' || buf[k] == '\t')) {
    k++;
  }
  if (k < n && buf[k] != '0') {
    raw_exit_group(1);
  }
}

/// Aborts if the library's own load base looks implausible. The base is the load bias (link base is 0 for a PIE), so
/// it is `&g_meta - meta_vaddr`, and the ELF header sits there in the first LOAD segment, which is always mapped
/// readable. A base of 0 (what a bare Unicorn run leaves) or no ELF magic at the base means the image was not mapped
/// normally. It reads only the base page, never the unreadable gaps the loader leaves between segments, so it is safe
/// on 4 KB- and 16 KB-page devices alike. Reached only once g_meta.packed == 1, so meta_vaddr holds the link address.
void check_elf_base() {
  std::uintptr_t base = reinterpret_cast<std::uintptr_t>(&g_meta) - static_cast<std::uintptr_t>(g_meta.meta_vaddr);
  if (base == 0) {
    raw_exit_group(2);
  }
  const unsigned char* m = reinterpret_cast<const unsigned char*>(base);
  if (!(m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F')) {
    raw_exit_group(2);
  }
}

/// Aborts on a gross timing anomaly. A short fixed loop takes a handful of counter ticks natively; under
/// single-stepping or a slow emulator it takes orders of magnitude longer. The threshold is deliberately loose so
/// ordinary scheduling jitter does not trip it.
void check_timing() {
  volatile std::uint32_t acc = 0;
  std::uint64_t t0 = read_counter();
  for (int i = 0; i < 1024; i++) {
    acc = acc + static_cast<std::uint32_t>(i * 3 + 1);
  }
  std::uint64_t t1 = read_counter();
  if (t1 - t0 > 0x02000000ULL) {
    raw_exit_group(3);
  }
}

/// Runs the tamper and emulation gate before any decryption; aborts the process on any trip.
void tamper_gate() {
  check_debugger();
  check_elf_base();
  check_timing();
}

/// Builds and runs the key-derivation in an RWX page and writes the 32-byte key to `key`. The derivation is not present
/// as .text: kdf_shovel_emit writes its machine code into a fresh anonymous page as immediate stores, the page is made
/// executable (RW then RX, so SELinux W^X holds), and the code is branched into. On any mapping failure the key is left
/// as-is and decryption fails safely.
void run_kdf(const std::uint8_t ikm[32], const std::uint8_t* stub, std::size_t stublen, std::uint8_t key[32]) {
  std::uintptr_t page = static_cast<std::uintptr_t>(sysconf(_SC_PAGESIZE));
  std::size_t span = static_cast<std::size_t>(align_up(static_cast<std::uintptr_t>(kKdfBlobLen), page));

  void* mem = raw_mmap(nullptr, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    return;
  }
  kdf_shovel_emit(reinterpret_cast<unsigned char*>(mem));
  if (raw_mprotect(mem, span, PROT_READ | PROT_EXEC) != 0) {
    raw_munmap(mem, span);
    return;
  }
  flush_icache(mem, span);

  using kdf_fn = void (*)(const std::uint8_t*, const std::uint8_t*, unsigned long, std::uint8_t*);
  kdf_fn run = reinterpret_cast<kdf_fn>(reinterpret_cast<unsigned char*>(mem) + kKdfBlobEntry);
  run(ikm, stub, static_cast<unsigned long>(stublen), key);

  raw_munmap(mem, span);
}

/// Derives the 32-byte ChaCha20 content key the packer used. Reassembles the eight scattered IKM words from .packmeta
/// (little-endian) and hands them, with the clear .stubcode location, to the run-time-built derivation blob, which
/// salts HKDF with SHA-256 over .stubcode. The packer reproduces this exactly.
void derive_key(std::uintptr_t bias, std::uint8_t key[32]) {
  std::uint8_t ikm[32];
  store32_le(ikm + 0, g_meta.ikm0);
  store32_le(ikm + 4, g_meta.ikm1);
  store32_le(ikm + 8, g_meta.ikm2);
  store32_le(ikm + 12, g_meta.ikm3);
  store32_le(ikm + 16, g_meta.ikm4);
  store32_le(ikm + 20, g_meta.ikm5);
  store32_le(ikm + 24, g_meta.ikm6);
  store32_le(ikm + 28, g_meta.ikm7);

  const std::uint8_t* stubcode =
      reinterpret_cast<const std::uint8_t*>(bias + static_cast<std::uintptr_t>(g_meta.stubcode_vaddr));
  run_kdf(ikm, stubcode, static_cast<std::size_t>(g_meta.stubcode_size), key);

  std::memset(ikm, 0, sizeof(ikm));
}

/// Decrypts one code region. In-place decryption cannot work for code on Android: the segment is file-backed, and once
/// the app writes to a file-backed executable page, restoring PROT_EXEC needs SELinux execmod, which untrusted_app is
/// denied. So this replaces the file-backed pages with an anonymous mapping at the same address (MAP_FIXED keeps every
/// PC-relative reference valid), decrypts there, and makes it executable via execmem (the permission the ART JIT uses).
/// A shipped runtime logs nothing, so a failed step bails silently.
void decrypt_code(void* addr, std::uint32_t size, std::uintptr_t start, std::size_t span, const std::uint8_t* key,
                  const std::uint8_t* nonce) {
  void* saved = raw_mmap(nullptr, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (saved == MAP_FAILED) {
    return;
  }
  std::memcpy(saved, reinterpret_cast<void*>(start), span);

  void* remap = raw_mmap(reinterpret_cast<void*>(start), span, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (remap == MAP_FAILED) {
    raw_munmap(saved, span);
    return;
  }
  std::memcpy(reinterpret_cast<void*>(start), saved, span);
  raw_munmap(saved, span);

  chacha20_xor(reinterpret_cast<std::uint8_t*>(addr), size, key, nonce);

  raw_mprotect(reinterpret_cast<void*>(start), span, PROT_READ | PROT_EXEC);
  flush_icache(reinterpret_cast<void*>(start), span);
}

/// Decrypts one read-only data region in place. Data restores to PROT_READ, which needs no execute permission, so the
/// file-backed mapping can be written via copy-on-write and restored read-only without tripping SELinux.
void decrypt_data(void* addr, std::uint32_t size, std::uintptr_t start, std::size_t span, const std::uint8_t* key,
                  const std::uint8_t* nonce) {
  if (raw_mprotect(reinterpret_cast<void*>(start), span, PROT_READ | PROT_WRITE) != 0) {
    return;
  }
  chacha20_xor(reinterpret_cast<std::uint8_t*>(addr), size, key, nonce);
  raw_mprotect(reinterpret_cast<void*>(start), span, PROT_READ);
}

/// Runs the gate, derives the key, and decrypts every region the packer recorded: code via the anonymous-remap path,
/// read-only data in place. It touches only the clear bootstrap (g_meta, the crypto in .stubcode, the run-time-built
/// derivation page) and libc; it never calls the library's own encrypted code. Reached only through the computed-branch
/// trampoline rasp_self_decrypt_init (the DT_INIT entry), never called directly.
[[gnu::noinline, gnu::used]] void self_decrypt() {
  if (g_meta.packed != 1) {
    return;
  }

  tamper_gate();

  std::uintptr_t bias = reinterpret_cast<std::uintptr_t>(&g_meta) - static_cast<std::uintptr_t>(g_meta.meta_vaddr);
  std::uintptr_t page = static_cast<std::uintptr_t>(sysconf(_SC_PAGESIZE));
  std::uint32_t count = g_meta.region_count;
  if (count > kMaxRegions) {
    count = kMaxRegions;
  }

  std::uint8_t key[32];
  derive_key(bias, key);

  for (std::uint32_t r = 0; r < count; r++) {
    std::uint32_t size = g_meta.regions[r].size;
    std::uint32_t is_code = g_meta.regions[r].is_code;
    void* addr = reinterpret_cast<void*>(bias + static_cast<std::uintptr_t>(g_meta.regions[r].vaddr));

    std::uint8_t nonce[16];
    for (int i = 0; i < 16; i++) {
      nonce[i] = g_meta.regions[r].nonce[i];
    }

    std::uintptr_t start = align_down(reinterpret_cast<std::uintptr_t>(addr), page);
    std::uintptr_t end = align_up(reinterpret_cast<std::uintptr_t>(addr) + size, page);
    std::size_t span = static_cast<std::size_t>(end - start);

    if (is_code == 1) {
      decrypt_code(addr, size, start, span, key, nonce);
    } else {
      decrypt_data(addr, size, start, span, key, nonce);
    }
  }

  std::memset(key, 0, sizeof(key));
}

}  // namespace

/// The library's DT_INIT entry (wired by -Wl,-init in android/CMakeLists.txt). The dynamic linker calls DT_INIT before
/// every DT_INIT_ARRAY constructor, so the library is decrypted before any of its own code runs. A plain constructor is
/// not enough: the O-MVLL obfuscator emits its own constructors at a priority that sorts ahead of a constructor(1) (a
/// priority-0 constructor beats priority 1), so those obfuscator constructors -- which live in the encrypted .text --
/// would run, and crash on ciphertext, before a constructor-based bootstrap got its turn. DT_INIT runs before all of
/// them regardless of priority. The bootstrap uses no atomics, so running this early is safe. It does not call the
/// decryptor directly: it folds self_decrypt's address through the live frame pointer and return address (which a static
/// disassembler cannot know) and reaches it with a computed indirect branch, so the trace from DT_INIT to the decryptor
/// is broken. The two XORs by the same volatile runtime value cancel, so at run time the call lands on self_decrypt.
extern "C" [[gnu::used]] void rasp_self_decrypt_init() {
  volatile std::uintptr_t mask = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0)) ^
                                 reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));
  std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&self_decrypt);
  target ^= mask;
  target ^= mask;
  using entry_fn = void (*)();
  entry_fn go = reinterpret_cast<entry_fn>(target);
  go();
}

}  // namespace rasp::android::selfdecrypt

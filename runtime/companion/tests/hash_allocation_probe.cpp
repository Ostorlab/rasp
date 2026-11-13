/// Enforce zero hidden digest copies/heap state in the actual dependency path; test interposition only.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <print>

#include "encoding.h"

namespace {
struct Counters {
  std::atomic<bool> measuring{false};
  std::atomic<std::size_t> allocations{0};
  std::atomic<std::size_t> bytes{0};
};
Counters& counters() {
  static constinit Counters value{};
  return value;
}

}  // namespace
extern "C" void* real_calloc(std::size_t count, std::size_t size) asm("__real_calloc");
extern "C" void* real_malloc(std::size_t size) asm("__real_malloc");
extern "C" void* real_realloc(void* pointer, std::size_t size) asm("__real_realloc");
extern "C" void* wrap_calloc(std::size_t count, std::size_t size) asm("__wrap_calloc");
extern "C" void* wrap_malloc(std::size_t size) asm("__wrap_malloc");
extern "C" void* wrap_realloc(void* pointer, std::size_t size) asm("__wrap_realloc");
extern "C" void* wrap_calloc(std::size_t count, std::size_t size) {
  if (counters().measuring.load()) {
    counters().allocations.fetch_add(1);
    counters().bytes.fetch_add(count * size);
  }
  return real_calloc(count, size);
}
extern "C" void* wrap_malloc(std::size_t size) {
  if (counters().measuring.load()) {
    counters().allocations.fetch_add(1);
    counters().bytes.fetch_add(size);
  }
  return real_malloc(size);
}
extern "C" void* wrap_realloc(void* pointer, std::size_t size) {
  if (counters().measuring.load()) {
    counters().allocations.fetch_add(1);
    counters().bytes.fetch_add(size);
  }
  return real_realloc(pointer, size);
}
int main() {
  auto input = std::make_unique<std::array<std::uint8_t, 4958>>();
  std::array<std::uint8_t, 32> output{};
  counters().measuring.store(true);
  const bool computed = rasp::keys::digest(*input, output);
  counters().measuring.store(false);
  std::println("digest allocations={} requested_bytes={}", counters().allocations.load(), counters().bytes.load());
  return computed && counters().allocations.load() == 0 ? 0 : 1;
}

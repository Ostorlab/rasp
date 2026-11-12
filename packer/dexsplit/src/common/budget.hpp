#pragma once

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/// Finite, cumulative request accounting; releasing memory never replenishes a budget.
namespace dexsplit::budget {
inline constexpr std::size_t kDexBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kTotalBytes = 256U * 1024U * 1024U;
inline constexpr std::size_t kWork = 16U * 1024U * 1024U;
inline constexpr std::size_t kClasses = 100000;
inline constexpr std::size_t kStrings = 1048576;
inline constexpr std::size_t kFiles = 256;
/// Amortize upstream pool metadata; logical charges still apply to every allocation.
inline constexpr std::size_t kPoolChunkBlocks = 64;

/// Exhaustion is distinct from a format pool overflow and must never trigger subdivision.
class Exhausted : public std::runtime_error {
 public:
  explicit Exhausted(const char* message) : std::runtime_error(message) {}
};

class OutputLimit : public std::runtime_error {
 public:
  OutputLimit() : std::runtime_error("rewritten DEX exceeds 64 MiB") {}
};

/// Logical allocations and retained backing capacity are separately cumulative; neither is refunded.
struct State {
  std::size_t work = 0;
  std::size_t storage = 0;
  // Conservative fixed allowance for State/control block/pool object and native request bookkeeping.
  std::size_t backing = 4096;
  std::size_t max_work = kWork;
  std::size_t max_storage = kTotalBytes;
  std::size_t max_backing = kTotalBytes;
  std::mutex accounting_mutex;
  std::mutex pool_mutex;
  struct Upstream : std::pmr::memory_resource {
    State* state;
    explicit Upstream(State* owner) : state(owner) {}
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
      {
        std::lock_guard lock(state->accounting_mutex);
        if (alignment == 0 || bytes > std::numeric_limits<std::size_t>::max() - (alignment - 1)) {
          throw Exhausted("DEX backing alignment overflow");
        }
        std::size_t charged = bytes + alignment - 1;
        if (state->backing > state->max_backing || charged > state->max_backing - state->backing) {
          throw Exhausted("DEX retained backing budget exhausted");
        }
        state->backing += charged;
      }
      return std::pmr::new_delete_resource()->allocate(bytes, alignment);
    }
    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
      std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
  } upstream{this};
  std::unique_ptr<std::pmr::unsynchronized_pool_resource> pool;
  void charge(std::size_t visits, std::size_t bytes) {
    std::lock_guard lock(accounting_mutex);
    if (work > max_work || storage > max_storage || visits > max_work - work || bytes > max_storage - storage) {
      throw Exhausted("DEX request work/storage budget exhausted");
    }
    work += visits;
    storage += bytes;
  }
  void* allocate(std::size_t bytes, std::size_t alignment) {
    std::lock_guard lock(pool_mutex);
    if (pool == nullptr) {
      charge(0, sizeof(std::pmr::unsynchronized_pool_resource));
      pool = std::make_unique<std::pmr::unsynchronized_pool_resource>(
          std::pmr::pool_options{kPoolChunkBlocks, kDexBytes}, &upstream);
    }
    return pool->allocate(bytes, alignment);
  }
  void release(void* pointer, std::size_t bytes, std::size_t alignment) {
    std::lock_guard lock(pool_mutex);
    pool->deallocate(pointer, bytes, alignment);
  }
};

static_assert(sizeof(State) + sizeof(std::pmr::unsynchronized_pool_resource) + 128 <= 4096);

inline thread_local std::shared_ptr<State> active;

/// Nested native calls share the outer request; they cannot reset its allowance.
class Scope {
 public:
  explicit Scope(std::shared_ptr<State> state = {}) : previous_(active) {
    if (active == nullptr) {
      active = state == nullptr ? std::make_shared<State>() : std::move(state);
    } else if (state != nullptr && state != active) {
      throw Exhausted("cannot replace an active DEX request budget");
    }
  }
  ~Scope() { active = previous_; }
  Scope(const Scope&) = delete;
  Scope& operator=(const Scope&) = delete;

 private:
  std::shared_ptr<State> previous_;
};

inline void visit(std::size_t count = 1) {
  if (active != nullptr) {
    active->charge(count, 0);
  }
}

/// Every native container allocation uses this allocator, including copies/reallocations.
template <class T>
class Allocator {
 public:
  using value_type = T;
  using propagate_on_container_move_assignment = std::true_type;
  Allocator() = default;
  template <class U>
  Allocator(const Allocator<U>&) noexcept {}
  struct alignas(alignof(T) > alignof(std::shared_ptr<State>) ? alignof(T) : alignof(std::shared_ptr<State>)) Header {
    std::shared_ptr<State> owner;
    std::size_t bytes;
  };
  [[nodiscard]] T* allocate(std::size_t count) {
    if (count > (std::numeric_limits<std::size_t>::max() - sizeof(Header)) / sizeof(T)) {
      throw Exhausted("DEX allocation size overflow");
    }
    auto state = active == nullptr ? std::make_shared<State>() : active;
    std::size_t bytes = sizeof(Header) + count * sizeof(T);
    state->charge(1, bytes);
    auto* header = static_cast<Header*>(state->allocate(bytes, alignof(Header)));
    std::construct_at(header, Header{state, bytes});
    return reinterpret_cast<T*>(header + 1);
  }
  void deallocate(T* pointer, std::size_t) noexcept {
    auto* header = reinterpret_cast<Header*>(pointer) - 1;
    auto state = header->owner;
    auto bytes = header->bytes;
    std::destroy_at(header);
    state->release(header, bytes, alignof(Header));
  }
  template <class U>
  bool operator==(const Allocator<U>&) const noexcept {
    return true;
  }
};

using String = std::basic_string<char, std::char_traits<char>, Allocator<char>>;
template <class T>
using Vector = std::vector<T, Allocator<T>>;
template <class K, class V, class C = std::less<K>>
using Map = std::map<K, V, C, Allocator<std::pair<const K, V>>>;
template <class K, class C = std::less<K>>
using Set = std::set<K, C, Allocator<K>>;
template <class T>
struct Hash {
  std::size_t operator()(const T& value) const {
    if constexpr (std::is_convertible_v<const T&, std::string_view>) {
      visit(std::string_view(value).size() / 64 + 1);
    }
    return std::hash<T>{}(value);
  }
};
template <class K, class V, class H = Hash<K>, class E = std::equal_to<K>>
using UnorderedMap = std::unordered_map<K, V, H, E, Allocator<std::pair<const K, V>>>;
template <class K, class H = Hash<K>, class E = std::equal_to<K>>
using UnorderedSet = std::unordered_set<K, H, E, Allocator<K>>;

template <class T, class... A>
auto make_shared(A&&... arguments) {
  return std::allocate_shared<T>(Allocator<T>{}, std::forward<A>(arguments)...);
}

template <class... A>
String format(std::format_string<A...> pattern, A&&... arguments) {
  String result;
  std::format_to(std::back_inserter(result), pattern, std::forward<A>(arguments)...);
  return result;
}
template <class Iterator, class Compare = std::less<>>
void sort(Iterator first, Iterator last, Compare compare = {}) {
  auto count = static_cast<std::size_t>(last - first);
  auto passes = std::bit_width(count);
  if (passes != 0 && count > kWork / passes) {
    throw Exhausted("DEX sorting work budget exceeded");
  }
  visit(count * passes);
  std::sort(first, last, compare);
}
template <class T>
String to_string(T value) {
  return format("{}", value);
}
}  // namespace dexsplit::budget

template <>
struct std::hash<dexsplit::budget::String> {
  std::size_t operator()(const dexsplit::budget::String& value) const noexcept {
    return std::hash<std::string_view>{}(value);
  }
};

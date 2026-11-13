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
inline constexpr std::size_t kDexBytes = std::size_t{64} * 1024U * 1024U;
/// Aggregate input/output bytes stay separate from cumulative allocation and backing limits.
inline constexpr std::size_t kTotalBytes = std::size_t{256} * 1024U * 1024U;
inline constexpr std::size_t kAllocationBytes = std::size_t{1536} * 1024U * 1024U;
inline constexpr std::size_t kBackingBytes = std::size_t{512} * 1024U * 1024U;
inline constexpr std::size_t kWork = 64000000;
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
  std::size_t max_storage = kAllocationBytes;
  std::size_t max_backing = kBackingBytes;
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
  /// Large vectors need fewer blocks per chunk; small-container pools keep their amortized metadata.
  std::unique_ptr<std::pmr::unsynchronized_pool_resource> large_pool;
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
    auto& selected = bytes > std::size_t{64} * 1024U ? large_pool : pool;
    if (selected == nullptr) {
      charge(0, sizeof(std::pmr::unsynchronized_pool_resource));
      selected = std::make_unique<std::pmr::unsynchronized_pool_resource>(
          std::pmr::pool_options{bytes > std::size_t{64} * 1024U ? 8 : kPoolChunkBlocks, kDexBytes}, &upstream);
    }
    return selected->allocate(bytes, alignment);
  }
  void release(void* pointer, std::size_t bytes, std::size_t alignment) {
    std::lock_guard lock(pool_mutex);
    auto& selected = bytes > std::size_t{64} * 1024U ? large_pool : pool;
    selected->deallocate(pointer, bytes, alignment);
  }
};

static_assert(sizeof(State) + 2 * sizeof(std::pmr::unsynchronized_pool_resource) + 128 <= 4096);

inline thread_local std::shared_ptr<State> active;
inline thread_local std::weak_ptr<State> last_request;

/// Unscoped native construction shares a retained request without keeping an expired pool alive.
inline std::shared_ptr<State> retained_request() {
  if (active != nullptr) {
    return active;
  }
  if (auto retained = last_request.lock()) {
    return retained;
  }
  auto state = std::make_shared<State>();
  last_request = state;
  return state;
}

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
  ~Scope() {
    if (previous_ == nullptr) {
      last_request = active;
    }
    active = previous_;
  }
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

/// Containers retain their owner across copies, moves, scope exit and nested element construction.
template <class T>
class Allocator {
 public:
  using value_type = T;
  using propagate_on_container_copy_assignment = std::true_type;
  using propagate_on_container_move_assignment = std::true_type;
  using propagate_on_container_swap = std::true_type;
  Allocator() : owner_(retained_request()) {}
  explicit Allocator(std::shared_ptr<State> owner) : owner_(std::move(owner)) {}
  Allocator(const Allocator&) noexcept = default;
  Allocator& operator=(const Allocator&) noexcept = default;
  template <class U>
  Allocator(const Allocator<U>& other) noexcept : owner_(other.owner()) {}
  const std::shared_ptr<State>& owner() const noexcept { return owner_; }
  Allocator select_on_container_copy_construction() const {
    if (owner_ == nullptr) {
      return Allocator{};
    }
    Scope scope(owner_);
    return *this;
  }
  [[nodiscard]] T* allocate(std::size_t count) {
    if (owner_ == nullptr) {
      throw Exhausted("immutable empty allocator cannot grow");
    }
    Scope scope(owner_);
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
      throw Exhausted("DEX allocation size overflow");
    }
    std::size_t bytes = count * sizeof(T);
    owner_->charge(count / 64 + 1, bytes);
    return static_cast<T*>(owner_->allocate(bytes, alignof(T)));
  }
  void deallocate(T* pointer, std::size_t count) noexcept {
    owner_->release(static_cast<void*>(pointer), count * sizeof(T), alignof(T));
  }
  template <class U, class... A>
    requires(!std::is_trivially_copyable_v<U>)
  void construct(U* pointer, A&&... arguments) {
    Scope scope(owner_);
    visit();
    std::construct_at(pointer, std::forward<A>(arguments)...);
  }
  template <class U>
  bool operator==(const Allocator<U>& other) const noexcept {
    return owner_ == other.owner();
  }

 private:
  std::shared_ptr<State> owner_;
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
// NOLINTNEXTLINE(bugprone-std-namespace-modification) -- [namespace.std]/2: depends on program-defined Allocator<char>.
struct std::hash<dexsplit::budget::String> {
  std::size_t operator()(const dexsplit::budget::String& value) const noexcept {
    return std::hash<std::string_view>{}(value);
  }
};

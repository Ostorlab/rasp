#include "model/types.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "common/budget.hpp"
#include "model/copy.hpp"

namespace dexsplit::model {

// ===== RegList =====

RegList::RegList(std::initializer_list<Reg> regs) : RegList(std::span<const Reg>(regs)) {}

RegList::RegList(std::span<const Reg> regs) {
  for (Reg r : regs) {
    push_back(r);
  }
}

RegList RegList::range(Reg first, uint16_t count) {
  RegList out;
  for (uint32_t i = 0; i < count; ++i) {
    out.push_back(static_cast<Reg>(first + i));
  }
  return out;
}

Reg* RegList::heap() const noexcept {
  Reg* p;
  std::memcpy(static_cast<void*>(&p), storage_, sizeof p);
  return p;
}

void RegList::set_heap(Reg* p) noexcept {
  static_assert(sizeof(Reg*) <= sizeof(storage_));
  std::memcpy(storage_, static_cast<const void*>(&p), sizeof p);
}

void RegList::release() noexcept {
  if (on_heap()) {
    allocator_.deallocate(heap(), capacity_);
  }
  size_ = 0;
  capacity_ = kInline;
}

RegList::RegList(const RegList& other) : allocator_(other.allocator_) {
  budget::Scope scope(allocator_.owner());
  for (Reg reg : other) {
    push_back(reg);
  }
}

RegList::RegList(RegList&& other) noexcept
    : allocator_(other.allocator_), size_(other.size_), capacity_(other.capacity_) {
  std::memcpy(storage_, other.storage_, sizeof storage_);
  other.size_ = 0;
  other.capacity_ = kInline;
}

RegList& RegList::operator=(const RegList& other) {
  if (this != &other) {
    RegList copy(other);
    *this = std::move(copy);
  }
  return *this;
}

RegList& RegList::operator=(RegList&& other) noexcept {
  if (this != &other) {
    release();
    allocator_ = other.allocator_;
    size_ = other.size_;
    capacity_ = other.capacity_;
    std::memcpy(storage_, other.storage_, sizeof storage_);
    other.size_ = 0;
    other.capacity_ = kInline;
  }
  return *this;
}

RegList::~RegList() { release(); }

void RegList::push_back(Reg reg) {
  budget::Scope scope(allocator_.owner());
  budget::visit();
  if (size_ == capacity_) {
    uint32_t grown = std::min<uint32_t>(uint32_t{capacity_} * 2, 0xFFFF);
    if (grown <= size_) {
      throw std::length_error("RegList: more than 65535 registers");
    }
    if (budget::active != nullptr) {
      budget::active->charge(size_, 0);
    }
    Reg* bigger = allocator_.allocate(grown);
    std::copy(begin(), end(), bigger);
    uint16_t size = size_;
    release();
    size_ = size;
    capacity_ = static_cast<uint16_t>(grown);
    set_heap(bigger);
  }
  data()[size_++] = reg;
}

bool RegList::is_run() const noexcept {
  for (std::size_t i = 1; i < size_; ++i) {
    if (data()[i] != data()[0] + i) {
      return false;
    }
  }
  return true;
}

bool operator==(const RegList& a, const RegList& b) noexcept {
  return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

/// Copy under the source request before any container growth, including nested owned values.
Dex::Dex(const Dex& other)
    : version(other.version), request(other.request), classes(budget::Allocator<ClassDef>{request}) {
  budget::Scope scope(request);
  for (const auto& cls : other.classes) {
    detail::charge_class_copy(cls);
  }
  classes = other.classes;
  original = other.original;
}
Dex& Dex::operator=(const Dex& other) {
  if (this != &other) {
    Dex copy(other);
    *this = std::move(copy);
  }
  return *this;
}
Dex::Dex(Dex&& other) noexcept
    : version(other.version),
      request(std::move(other.request)),
      classes(std::move(other.classes)),
      original(std::move(other.original)) {
  other.request = request;
}
Dex& Dex::operator=(Dex&& other) noexcept {
  if (this != &other) {
    version = other.version;
    request = other.request;
    classes = std::move(other.classes);
    original = std::move(other.original);
  }
  return *this;
}

// ===== lookups =====

FieldDef* ClassDef::find_field(std::string_view name, std::string_view type) {
  for (FieldDef& f : fields) {
    if (f.name == name && f.type == type) {
      return &f;
    }
  }
  return nullptr;
}

const FieldDef* ClassDef::find_field(std::string_view name, std::string_view type) const {
  return const_cast<ClassDef*>(this)->find_field(name, type);
}

MethodDef* ClassDef::find_method(std::string_view name, std::string_view proto) {
  for (MethodDef& m : methods) {
    if (m.name == name && m.proto == proto) {
      return &m;
    }
  }
  return nullptr;
}

const MethodDef* ClassDef::find_method(std::string_view name, std::string_view proto) const {
  return const_cast<ClassDef*>(this)->find_method(name, proto);
}

ClassDef* Dex::find_class(std::string_view type) {
  for (ClassDef& c : classes) {
    if (c.type == type) {
      return &c;
    }
  }
  return nullptr;
}

const ClassDef* Dex::find_class(std::string_view type) const { return const_cast<Dex*>(this)->find_class(type); }

}  // namespace dexsplit::model

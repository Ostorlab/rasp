#include "common/budget.hpp"
#pragma once

#include <bit>
#include <compare>
#include <concepts>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/access_flags.hpp"
#include "common/annotation_visibility.hpp"
#include "common/ids.hpp"

/** An editable, in-memory model of one DEX file.
 *
 *  The model holds no pool indices and no byte offsets.  Every reference is
 *  written out in full — type descriptors, prototype descriptors, MethodId,
 *  FieldId — and branches point at labels.  write() collects the references,
 *  builds and sorts the pools, assigns indices, and picks each instruction's
 *  encoding.  So editing never involves index bookkeeping: splitting, merging,
 *  renaming and generating code are ordinary edits followed by write().
 *
 *  Everything is plain data with value semantics: copying a Dex copies it,
 *  and two models compare equal when they hold the same content.
 *
 *  Strings are WTF-8 (see raw/mutf8.hpp): UTF-8, except that an unpaired
 *  surrogate, which DEX string constants may contain, is kept as its 3-byte
 *  sequence.  Every DEX string survives a read and a write unchanged. */
namespace dexsplit::model {

/// Immutable empty sentinels must not retain the request that first accesses them.
template <class T>
T empty_shared_value();

// ===================================================================
// Building blocks
// ===================================================================

/** An immutable value held by a shared pointer.  Copies share one
 *  allocation, but a Shared compares by value and can never be changed in
 *  place — to change it, assign a new value — so the sharing is invisible
 *  except for memory use.  Instruction operands use it: a large method refers
 *  to the same few strings, types and members thousands of times.
 *
 *  A default-constructed (or moved-from) Shared holds T{}. */
template <class T>
class Shared {
 public:
  Shared() = default;

  /** Hold a T built from @p value: Shared<budget::String> s = "text". */
  template <class U = T>
    requires(!std::is_same_v<std::remove_cvref_t<U>, Shared> && std::is_constructible_v<T, U&&>)
  Shared(U&& value) : ptr_(budget::make_shared<const T>(std::forward<U>(value))) {}

  /** Build an aggregate T in place: Shared<MethodId>{"La;", "run", "()V"}. */
  template <class A, class B, class... Rest>
    requires std::is_aggregate_v<T>
  Shared(A&& a, B&& b, Rest&&... rest)
      : ptr_(budget::make_shared<const T>(T{std::forward<A>(a), std::forward<B>(b), std::forward<Rest>(rest)...})) {}

  const T& get() const noexcept { return ptr_ ? *ptr_ : fallback(); }
  const T& operator*() const noexcept { return get(); }
  const T* operator->() const noexcept { return &get(); }

  friend bool operator==(const Shared& a, const Shared& b) { return a.ptr_ == b.ptr_ || a.get() == b.get(); }

 private:
  static const T& fallback() {
    static const T value = empty_shared_value<T>();
    return value;
  }

  std::shared_ptr<const T> ptr_;
};

/** A virtual register number. */
using Reg = uint16_t;

/** A list of registers: the arguments of an invoke or filled-new-array.
 *  Holds up to six registers without allocating.  The DEX format can encode
 *  a list of up to five registers below v16, or a run of consecutive
 *  registers; write() rejects any other list. */
class RegList {
 public:
  RegList() = default;
  RegList(std::initializer_list<Reg> regs);
  explicit RegList(std::span<const Reg> regs);
  /** The run first, first + 1, ..., first + count - 1. */
  static RegList range(Reg first, uint16_t count);

  RegList(const RegList& other);
  RegList(RegList&& other) noexcept;
  RegList& operator=(const RegList& other);
  RegList& operator=(RegList&& other) noexcept;
  ~RegList();

  std::size_t size() const noexcept { return size_; }
  bool empty() const noexcept { return size_ == 0; }
  const Reg* begin() const noexcept { return data(); }
  const Reg* end() const noexcept { return data() + size_; }
  Reg* begin() noexcept { return data(); }
  Reg* end() noexcept { return data() + size_; }
  Reg operator[](std::size_t i) const noexcept { return data()[i]; }
  Reg& operator[](std::size_t i) noexcept { return data()[i]; }

  void push_back(Reg reg);
  void clear() noexcept { size_ = 0; }

  /** True if the registers are consecutive and increasing (or the list is empty). */
  bool is_run() const noexcept;

  friend bool operator==(const RegList& a, const RegList& b) noexcept;

 private:
  static constexpr uint16_t kInline = 6;

  bool on_heap() const noexcept { return capacity_ > kInline; }
  Reg* heap() const noexcept;
  void set_heap(Reg* p) noexcept;
  const Reg* data() const noexcept { return on_heap() ? heap() : storage_; }
  Reg* data() noexcept { return on_heap() ? heap() : storage_; }
  void release() noexcept;

  budget::Allocator<Reg> allocator_;
  uint16_t size_ = 0;
  uint16_t capacity_ = kInline;
  // Inline registers; when on the heap, the first bytes hold the pointer.
  Reg storage_[kInline] = {};
};

/** A position in a method's code.  Branches, switch cases and try ranges
 *  name labels; a Label item in Code::items marks where it is. */
struct Label {
  uint32_t id = 0;
  auto operator<=>(const Label&) const = default;
};

// ===================================================================
// Values: annotation elements, static field values, call-site arguments
// ===================================================================

enum class MethodHandleKind : uint8_t {
  StaticPut = 0x00,
  StaticGet = 0x01,
  InstancePut = 0x02,
  InstanceGet = 0x03,
  InvokeStatic = 0x04,
  InvokeInstance = 0x05,
  InvokeConstructor = 0x06,
  InvokeDirect = 0x07,
  InvokeInterface = 0x08,
};

/** A method handle (java.lang.invoke.MethodHandle constant).  The four field
 *  kinds take a FieldId, the five invoke kinds a MethodId. */
struct MethodHandle {
  MethodHandleKind kind = MethodHandleKind::InvokeStatic;
  std::variant<MethodId, FieldId> member;

  bool operator==(const MethodHandle&) const = default;
};

struct NamedValue;

/** An annotation's type and its explicitly set elements.  Elements left at
 *  their @interface defaults are absent. */
struct EncodedAnnotation {
  budget::String type;  ///< Class descriptor of the annotation type.
  budget::Vector<NamedValue> elements;

  bool operator==(const EncodedAnnotation&) const;
};

/** A constant value as the DEX format encodes it (encoded_value), with its
 *  exact type: a Java `char` stays a Char, a `byte` a Byte.  Build one from
 *  its alternative: `Value{Value::Int{42}}`, `Value{Value::String{"x"}}`.
 *  There is no implicit conversion from plain numbers, so a value can't get
 *  the wrong type by accident.  Float and Double compare by their bits, so
 *  -0.0 and 0.0 differ and a NaN equals itself. */
struct Value {
  struct Null {
    bool operator==(const Null&) const = default;
  };
  struct Boolean {
    bool value = false;
    bool operator==(const Boolean&) const = default;
  };
  struct Byte {
    int8_t value = 0;
    bool operator==(const Byte&) const = default;
  };
  struct Short {
    int16_t value = 0;
    bool operator==(const Short&) const = default;
  };
  struct Char {
    char16_t value = 0;
    bool operator==(const Char&) const = default;
  };
  struct Int {
    int32_t value = 0;
    bool operator==(const Int&) const = default;
  };
  struct Long {
    int64_t value = 0;
    bool operator==(const Long&) const = default;
  };
  struct Float {
    float value = 0;
    bool operator==(const Float& o) const { return std::bit_cast<uint32_t>(value) == std::bit_cast<uint32_t>(o.value); }
  };
  struct Double {
    double value = 0;
    bool operator==(const Double& o) const {
      return std::bit_cast<uint64_t>(value) == std::bit_cast<uint64_t>(o.value);
    }
  };
  struct String {
    budget::String value;
    bool operator==(const String&) const = default;
  };
  /** A class literal, e.g. `String.class`. */
  struct Type {
    budget::String descriptor;
    bool operator==(const Type&) const = default;
  };
  struct Field {
    FieldId field;
    bool operator==(const Field&) const = default;
  };
  struct Method {
    MethodId method;
    bool operator==(const Method&) const = default;
  };
  /** An enum constant, named by its static field. */
  struct Enum {
    FieldId field;
    bool operator==(const Enum&) const = default;
  };
  /** A method type (java.lang.invoke.MethodType), as a prototype descriptor. */
  struct MethodType {
    budget::String proto;
    bool operator==(const MethodType&) const = default;
  };
  struct Array {
    budget::Vector<Value> values;
    bool operator==(const Array&) const = default;
  };

  std::variant<Null, Boolean, Byte, Short, Char, Int, Long, Float, Double, String, Type, Field, Method, Enum,
               MethodType, MethodHandle, Array, Shared<EncodedAnnotation>>
      data;

  bool operator==(const Value&) const = default;
};

/** One `name = value` element of an annotation. */
struct NamedValue {
  budget::String name;
  Value value;

  bool operator==(const NamedValue&) const = default;
};

inline bool EncodedAnnotation::operator==(const EncodedAnnotation& o) const {
  return type == o.type && elements == o.elements;
}

/** An annotation attached to a class, field, method or parameter. */
struct AnnotationItem {
  AnnotationVisibility visibility = AnnotationVisibility::Runtime;
  EncodedAnnotation annotation;

  bool operator==(const AnnotationItem&) const = default;
};

/** An invoke-custom call site: the bootstrap method and the arguments it is
 *  linked with.
 *
 *  The runtime links each call site once.  So two invoke-custom instructions
 *  that share a call site share the linked result, and splitting or merging
 *  call sites changes how often the bootstrap method runs.  `share_key`
 *  keeps that sharing: call sites with the same non-zero key and the same
 *  contents are written as one call site; a key of 0 is never shared.
 *  read() sets the key from the call site's position in the file, so a read
 *  and a write keep the sharing; new code can leave it at 0. */
struct CallSite {
  MethodHandle bootstrap;            ///< The bootstrap method (an InvokeStatic handle).
  budget::String method_name;        ///< The name the call site is linked for.
  budget::String method_type;        ///< Its prototype descriptor.
  budget::Vector<Value> extra_args;  ///< Further static arguments to the bootstrap method.
  uint32_t share_key = 0;

  bool operator==(const CallSite&) const = default;
};

// ===================================================================
// Instructions
// ===================================================================
//
// An instruction says what to do; write() picks how to encode it — the
// smallest encoding that fits its registers, values and branch distance
// (e.g. `Const` becomes const/4, const/16, const/high16 or const).  The
// enumerators of each operation enum follow the opcode order.

/** Which variant of a move, return, array, field or result instruction: the
 *  kind of value it moves.  Normal is a 32-bit non-object value (int or
 *  float); Wide a register pair (long or double).  Move, MoveResult and
 *  Return take only Normal, Wide and Object. */
enum class ValueKind : uint8_t { Normal, Wide, Object, Boolean, Byte, Char, Short };

/** Comparison of an If (two registers) or IfZero (a register and zero). */
enum class Condition : uint8_t { Eq, Ne, Lt, Ge, Gt, Le };

enum class CompareOp : uint8_t { CmplFloat, CmpgFloat, CmplDouble, CmpgDouble, CmpLong };

enum class UnaryOp : uint8_t {
  NegInt,
  NotInt,
  NegLong,
  NotLong,
  NegFloat,
  NegDouble,
  IntToLong,
  IntToFloat,
  IntToDouble,
  LongToInt,
  LongToFloat,
  LongToDouble,
  FloatToInt,
  FloatToLong,
  FloatToDouble,
  DoubleToInt,
  DoubleToLong,
  DoubleToFloat,
  IntToByte,
  IntToChar,
  IntToShort,
};

enum class BinaryOp : uint8_t {
  AddInt,
  SubInt,
  MulInt,
  DivInt,
  RemInt,
  AndInt,
  OrInt,
  XorInt,
  ShlInt,
  ShrInt,
  UshrInt,
  AddLong,
  SubLong,
  MulLong,
  DivLong,
  RemLong,
  AndLong,
  OrLong,
  XorLong,
  ShlLong,
  ShrLong,
  UshrLong,
  AddFloat,
  SubFloat,
  MulFloat,
  DivFloat,
  RemFloat,
  AddDouble,
  SubDouble,
  MulDouble,
  DivDouble,
  RemDouble,
};

/** Operation of a BinaryLiteral (an int operation with a constant).  Rsub is
 *  literal - src.  Shl, Shr and Ushr only exist with an 8-bit literal. */
enum class LiteralOp : uint8_t { Add, Rsub, Mul, Div, Rem, And, Or, Xor, Shl, Shr, Ushr };

struct Nop {
  bool operator==(const Nop&) const = default;
};
struct Move {
  ValueKind kind = ValueKind::Normal;
  Reg dest = 0;
  Reg src = 0;
  bool operator==(const Move&) const = default;
};
/** move-result: must directly follow an invoke or filled-new-array. */
struct MoveResult {
  ValueKind kind = ValueKind::Normal;
  Reg dest = 0;
  bool operator==(const MoveResult&) const = default;
};
/** move-exception: must be the first instruction of a catch handler. */
struct MoveException {
  Reg dest = 0;
  bool operator==(const MoveException&) const = default;
};
struct ReturnVoid {
  bool operator==(const ReturnVoid&) const = default;
};
struct Return {
  ValueKind kind = ValueKind::Normal;
  Reg src = 0;
  bool operator==(const Return&) const = default;
};
/** A 32-bit constant (int, float bits, or 0 as null). */
struct Const {
  Reg dest = 0;
  int32_t value = 0;
  bool operator==(const Const&) const = default;
};
/** A 64-bit constant into a register pair. */
struct ConstWide {
  Reg dest = 0;
  int64_t value = 0;
  bool operator==(const ConstWide&) const = default;
};
struct ConstString {
  Reg dest = 0;
  Shared<budget::String> value;
  bool operator==(const ConstString&) const = default;
};
struct ConstClass {
  Reg dest = 0;
  Shared<budget::String> type;
  bool operator==(const ConstClass&) const = default;
};
struct ConstMethodHandle {
  Reg dest = 0;
  Shared<MethodHandle> handle;
  bool operator==(const ConstMethodHandle&) const = default;
};
struct ConstMethodType {
  Reg dest = 0;
  Shared<budget::String> proto;
  bool operator==(const ConstMethodType&) const = default;
};
struct MonitorEnter {
  Reg object = 0;
  bool operator==(const MonitorEnter&) const = default;
};
struct MonitorExit {
  Reg object = 0;
  bool operator==(const MonitorExit&) const = default;
};
struct CheckCast {
  Reg object = 0;
  Shared<budget::String> type;
  bool operator==(const CheckCast&) const = default;
};
struct InstanceOf {
  Reg dest = 0;
  Reg object = 0;
  Shared<budget::String> type;
  bool operator==(const InstanceOf&) const = default;
};
struct ArrayLength {
  Reg dest = 0;
  Reg array = 0;
  bool operator==(const ArrayLength&) const = default;
};
struct NewInstance {
  Reg dest = 0;
  Shared<budget::String> type;
  bool operator==(const NewInstance&) const = default;
};
/** new-array: `type` is the array type, e.g. "[I". */
struct NewArray {
  Reg dest = 0;
  Reg size = 0;
  Shared<budget::String> type;
  bool operator==(const NewArray&) const = default;
};
/** filled-new-array: `type` is the array type; the result is picked up by a
 *  following MoveResult. */
struct FilledNewArray {
  RegList args;
  Shared<budget::String> type;
  bool operator==(const FilledNewArray&) const = default;
};
/** fill-array-data: `data` holds the elements' little-endian bytes,
 *  `element_width` bytes each (1, 2, 4 or 8). */
struct FillArrayData {
  Reg array = 0;
  uint16_t element_width = 1;
  budget::Vector<uint8_t> data;
  bool operator==(const FillArrayData&) const = default;
};
struct Throw {
  Reg exception = 0;
  bool operator==(const Throw&) const = default;
};
struct Goto {
  Label target;
  bool operator==(const Goto&) const = default;
};
/** packed-switch or sparse-switch, chosen by write().  A value with no case
 *  falls through to the next instruction. */
struct Switch {
  struct Case {
    int32_t key = 0;
    Label target;
    bool operator==(const Case&) const = default;
  };
  Reg value = 0;
  budget::Vector<Case> cases;
  bool operator==(const Switch&) const = default;
};
struct Compare {
  CompareOp op = CompareOp::CmpLong;
  Reg dest = 0;
  Reg a = 0;
  Reg b = 0;
  bool operator==(const Compare&) const = default;
};
/** Branch to `target` if `a cond b`. */
struct If {
  Condition cond = Condition::Eq;
  Reg a = 0;
  Reg b = 0;
  Label target;
  bool operator==(const If&) const = default;
};
/** Branch to `target` if `value cond 0`. */
struct IfZero {
  Condition cond = Condition::Eq;
  Reg value = 0;
  Label target;
  bool operator==(const IfZero&) const = default;
};
struct ArrayGet {
  ValueKind kind = ValueKind::Normal;
  Reg dest = 0;
  Reg array = 0;
  Reg index = 0;
  bool operator==(const ArrayGet&) const = default;
};
struct ArrayPut {
  ValueKind kind = ValueKind::Normal;
  Reg value = 0;
  Reg array = 0;
  Reg index = 0;
  bool operator==(const ArrayPut&) const = default;
};
struct InstanceGet {
  ValueKind kind = ValueKind::Normal;
  Reg dest = 0;
  Reg object = 0;
  Shared<FieldId> field;
  bool operator==(const InstanceGet&) const = default;
};
struct InstancePut {
  ValueKind kind = ValueKind::Normal;
  Reg value = 0;
  Reg object = 0;
  Shared<FieldId> field;
  bool operator==(const InstancePut&) const = default;
};
struct StaticGet {
  ValueKind kind = ValueKind::Normal;
  Reg dest = 0;
  Shared<FieldId> field;
  bool operator==(const StaticGet&) const = default;
};
struct StaticPut {
  ValueKind kind = ValueKind::Normal;
  Reg value = 0;
  Shared<FieldId> field;
  bool operator==(const StaticPut&) const = default;
};
/** invoke-virtual, -super, -direct, -static or -interface.  `args` lists every
 *  argument register in order — the receiver first for non-static calls, and
 *  both registers of a long or double. */
struct Invoke {
  enum class Kind : uint8_t { Virtual, Super, Direct, Static, Interface };
  Kind kind = Kind::Virtual;
  RegList args;
  Shared<MethodId> method;
  bool operator==(const Invoke&) const = default;
};
/** invoke-polymorphic: a signature-polymorphic call (MethodHandle.invoke...).
 *  `proto` is the call site's prototype. */
struct InvokePolymorphic {
  RegList args;
  Shared<MethodId> method;
  Shared<budget::String> proto;
  bool operator==(const InvokePolymorphic&) const = default;
};
struct InvokeCustom {
  RegList args;
  Shared<CallSite> call_site;
  bool operator==(const InvokeCustom&) const = default;
};
struct Unary {
  UnaryOp op = UnaryOp::NegInt;
  Reg dest = 0;
  Reg src = 0;
  bool operator==(const Unary&) const = default;
};
/** dest = a op b.  Encoded as the 2-address form when dest == a fits it. */
struct Binary {
  BinaryOp op = BinaryOp::AddInt;
  Reg dest = 0;
  Reg a = 0;
  Reg b = 0;
  bool operator==(const Binary&) const = default;
};
/** dest = src op literal (for Rsub: literal - src). */
struct BinaryLiteral {
  LiteralOp op = LiteralOp::Add;
  Reg dest = 0;
  Reg src = 0;
  int16_t literal = 0;
  bool operator==(const BinaryLiteral&) const = default;
};

using Insn = std::variant<Nop, Move, MoveResult, MoveException, ReturnVoid, Return, Const, ConstWide, ConstString,
                          ConstClass, ConstMethodHandle, ConstMethodType, MonitorEnter, MonitorExit, CheckCast,
                          InstanceOf, ArrayLength, NewInstance, NewArray, FilledNewArray, FillArrayData, Throw, Goto,
                          Switch, Compare, If, IfZero, ArrayGet, ArrayPut, InstanceGet, InstancePut, StaticGet,
                          StaticPut, Invoke, InvokePolymorphic, InvokeCustom, Unary, Binary, BinaryLiteral>;

// ===================================================================
// Debug information: markers between instructions
// ===================================================================

/** The source line of the code that follows. */
struct LineNumber {
  uint32_t line = 0;
  bool operator==(const LineNumber&) const = default;
};
struct LocalVariable {
  std::optional<budget::String> name;
  std::optional<budget::String> type;       ///< Type descriptor.
  std::optional<budget::String> signature;  ///< Generic signature, if any.
  bool operator==(const LocalVariable&) const = default;
};
/** A local variable comes into scope in `reg`. */
struct LocalStart {
  Reg reg = 0;
  Shared<LocalVariable> local;
  bool operator==(const LocalStart&) const = default;
};
/** The local variable in `reg` goes out of scope. */
struct LocalEnd {
  Reg reg = 0;
  bool operator==(const LocalEnd&) const = default;
};
/** The local variable last in `reg` comes back into scope. */
struct LocalRestart {
  Reg reg = 0;
  bool operator==(const LocalRestart&) const = default;
};
/** The next LineNumber marks the end of the method prologue (a breakpoint spot). */
struct PrologueEnd {
  bool operator==(const PrologueEnd&) const = default;
};
/** The next LineNumber marks the start of the method epilogue. */
struct EpilogueBegin {
  bool operator==(const EpilogueBegin&) const = default;
};
/** Later line numbers refer to another source file (nullopt: unknown). */
struct SetSourceFile {
  std::optional<budget::String> name;
  bool operator==(const SetSourceFile&) const = default;
};

/** One entry of Code::items: an instruction, a label position, or a debug
 *  marker.  Labels and markers take no space: they belong to the position of
 *  the next instruction (or the end of the code). */
using Item = std::variant<Insn, Label, LineNumber, LocalStart, LocalEnd, LocalRestart, PrologueEnd, EpilogueBegin,
                          SetSourceFile>;

// ===================================================================
// Code, members, classes
// ===================================================================

struct Catch {
  budget::String type;  ///< Class descriptor of the exception type.
  Label handler;
  bool operator==(const Catch&) const = default;
};

/** The instructions between `start` and `end` are protected: an exception
 *  goes to the first matching `catches` entry, else to `catch_all`.  Ranges
 *  may nest or overlap; where they do, the range listed first wins, as in a
 *  Java exception table. */
struct TryRange {
  Label start;
  Label end;
  budget::Vector<Catch> catches;
  std::optional<Label> catch_all;
  bool operator==(const TryRange&) const = default;
};

/** A method body.  The incoming arguments occupy the last registers of the
 *  frame (`this` first for an instance method); write() derives the argument
 *  and outgoing-argument sizes. */
struct Code {
  Reg registers = 0;  ///< Frame size.
  budget::Vector<Item> items;
  budget::Vector<TryRange> tries{budget::Allocator<TryRange>{items.get_allocator().owner()}};
  /** Debug names of the parameters (not including `this`). */
  budget::Vector<std::optional<budget::String>> parameter_names{
      budget::Allocator<std::optional<budget::String>>{items.get_allocator().owner()}};

  /** A label not used yet in this code. */
  Label new_label() noexcept { return Label{next_label_++}; }

  /** Number of labels new_label() handed out. */
  uint32_t label_count() const noexcept { return next_label_; }

  /** Compares the content; which labels new_label() has handed out does not count. */
  bool operator==(const Code& o) const {
    return registers == o.registers && items == o.items && tries == o.tries && parameter_names == o.parameter_names;
  }

 private:
  uint32_t next_label_ = 0;
};

/// Optional code with value semantics: grouping shares immutable bodies; edits detach before mutation.
class CodeValue {
 public:
  CodeValue() = default;
  CodeValue(Code value) : value_(store(std::move(value))) {}
  CodeValue& operator=(Code value) {
    value_ = store(std::move(value));
    return *this;
  }
  bool has_value() const noexcept { return value_ != nullptr; }
  explicit operator bool() const noexcept { return has_value(); }
  const Code& operator*() const { return *value_; }
  const Code* operator->() const { return value_.get(); }
  Code& operator*() {
    detach();
    return *value_;
  }
  Code* operator->() {
    detach();
    return value_.get();
  }
  bool operator==(const CodeValue& other) const {
    return value_ == other.value_ || (value_ != nullptr && other.value_ != nullptr && *value_ == *other.value_);
  }

 private:
  static std::shared_ptr<Code> store(Code value) {
    budget::Scope scope(value.items.get_allocator().owner());
    return budget::make_shared<Code>(std::move(value));
  }
  void detach() {
    if (value_ != nullptr && value_.use_count() > 1) {
      budget::Scope scope(value_->items.get_allocator().owner());
      budget::visit(value_->items.size() + value_->tries.size() + value_->parameter_names.size());
      for (const auto& item : value_->items) {
        if (const auto* instruction = std::get_if<Insn>(&item)) {
          if (const auto* data = std::get_if<FillArrayData>(instruction)) {
            budget::visit(data->data.size() / 64 + 1);
          }
          if (const auto* cases = std::get_if<Switch>(instruction)) {
            budget::visit(cases->cases.size());
          }
        }
      }
      for (const auto& range : value_->tries) {
        budget::visit(range.catches.size());
        for (const auto& caught : range.catches) {
          budget::visit(caught.type.size() / 64 + 1);
        }
      }
      value_ = budget::make_shared<Code>(*value_);
    }
  }
  std::shared_ptr<Code> value_;
};

struct FieldDef {
  budget::String name;
  budget::String type;  ///< Field type descriptor.
  AccessFlags access{};
  /** A static field's initial value; nullopt means the type's default
   *  (zero, false or null). */
  std::optional<Value> initial_value;
  budget::Vector<AnnotationItem> annotations;

  bool operator==(const FieldDef&) const = default;
};

struct MethodDef {
  budget::String name;
  budget::String proto;  ///< Prototype descriptor, e.g. "(ILjava/lang/String;)V".
  AccessFlags access{};
  /** nullopt for abstract and native methods. */
  CodeValue code;
  budget::Vector<AnnotationItem> annotations;
  /** One annotation list per parameter, as the file declares them (the
   *  count may differ from the parameter count); empty for none. */
  budget::Vector<budget::Vector<AnnotationItem>> parameter_annotations;

  bool operator==(const MethodDef&) const = default;
};

struct ClassDef {
  budget::String type;  ///< Class descriptor, e.g. "Lcom/example/Foo;".
  AccessFlags access{};
  /** nullopt only for java.lang.Object. */
  std::optional<budget::String> superclass;
  budget::Vector<budget::String> interfaces;
  std::optional<budget::String> source_file;
  budget::Vector<AnnotationItem> annotations;
  /** Static and instance fields, in any order. */
  budget::Vector<FieldDef> fields;
  /** Direct and virtual methods, in any order. */
  budget::Vector<MethodDef> methods;

  FieldDef* find_field(std::string_view name, std::string_view type);
  const FieldDef* find_field(std::string_view name, std::string_view type) const;
  MethodDef* find_method(std::string_view name, std::string_view proto);
  const MethodDef* find_method(std::string_view name, std::string_view proto) const;

  bool operator==(const ClassDef&) const = default;
};

/** One DEX file. */
struct Dex {
  /** DEX format version: 35, 37, 38, 39 or 40 (written as "dex\n0NN\0"). */
  uint32_t version = 35;
  std::shared_ptr<budget::State> request = budget::retained_request();
  /** Classes in any order; write() puts supertypes first. */
  budget::Vector<ClassDef> classes{budget::Allocator<ClassDef>{request}};

  Dex() = default;
  Dex(const Dex& other);
  Dex& operator=(const Dex& other);
  Dex(Dex&& other) noexcept;
  Dex& operator=(Dex&& other) noexcept;

  ClassDef* find_class(std::string_view type);
  const ClassDef* find_class(std::string_view type) const;

  /// Immutable source exists only after a complete validated read.
  std::shared_ptr<const budget::Vector<uint8_t>> original;
  bool operator==(const Dex& other) const { return version == other.version && classes == other.classes; }
};

template <class T>
T empty_shared_value() {
  if constexpr (std::is_same_v<T, budget::String>) {
    return budget::String{budget::Allocator<char>{nullptr}};
  } else if constexpr (std::is_same_v<T, FieldId> || std::is_same_v<T, MethodId>) {
    return T{empty_shared_value<budget::String>(), empty_shared_value<budget::String>(),
             empty_shared_value<budget::String>()};
  } else if constexpr (std::is_same_v<T, MethodHandle>) {
    return MethodHandle{MethodHandleKind::InvokeStatic, empty_shared_value<MethodId>()};
  } else if constexpr (std::is_same_v<T, EncodedAnnotation>) {
    return EncodedAnnotation{empty_shared_value<budget::String>(),
                             budget::Vector<NamedValue>{budget::Allocator<NamedValue>{nullptr}}};
  } else if constexpr (std::is_same_v<T, CallSite>) {
    return CallSite{empty_shared_value<MethodHandle>(), empty_shared_value<budget::String>(),
                    empty_shared_value<budget::String>(), budget::Vector<Value>{budget::Allocator<Value>{nullptr}}, 0};
  } else {
    return T{};
  }
}

}  // namespace dexsplit::model

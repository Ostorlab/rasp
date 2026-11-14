#pragma once

// The encoder of values and annotations of the DEX writer.  Internal: not
// part of the API.

#include <cstdint>
#include <span>
#include <string_view>

#include "model/pools.hpp"
#include "raw/byte_writer.hpp"

namespace dexsplit::model::detail {

// Smallest number of bytes holding @p v sign-extended.
inline uint32_t signed_size(int64_t v)
{
    uint32_t n = 1;
    while (n < 8) {
        int64_t lo = -(int64_t{1} << (8 * n - 1));
        int64_t hi = (int64_t{1} << (8 * n - 1)) - 1;
        if (v >= lo && v <= hi)
            break;
        ++n;
    }
    return n;
}

// Smallest number of bytes holding @p v zero-extended.
inline uint32_t unsigned_size(uint64_t v)
{
    uint32_t n = 1;
    while (n < 8 && (v >> (8 * n)) != 0)
        ++n;
    return n;
}

class ValueEncoder
{
  public:
    explicit ValueEncoder(const Pools &pools) : pools_(pools) {}

    void value(raw::ByteWriter &out, const Value &v) const
    {
        std::visit([&](const auto &x) { encode(out, x); }, v.data);
    }

    void array(raw::ByteWriter &out, std::span<const Value> values) const
    {
        out.uleb128(static_cast<uint32_t>(values.size()));
        for (const Value &v : values)
            value(out, v);
    }

    void annotation(raw::ByteWriter &out, const EncodedAnnotation &a) const
    {
        out.uleb128(pools_.type(a.type));
        // Elements in increasing order of their name's string index.
        std::vector<std::pair<uint32_t, const Value *>> elements;
        for (const NamedValue &e : a.elements)
            elements.emplace_back(pools_.string(e.name), &e.value);
        std::sort(elements.begin(), elements.end(),
                  [](const auto &x, const auto &y) { return x.first < y.first; });
        out.uleb128(static_cast<uint32_t>(elements.size()));
        for (const auto &[name, v] : elements) {
            out.uleb128(name);
            value(out, *v);
        }
    }

  private:
    static void header(raw::ByteWriter &out, uint8_t type, uint32_t arg)
    {
        out.u8(static_cast<uint8_t>((arg << 5) | type));
    }
    static void bytes(raw::ByteWriter &out, uint64_t v, uint32_t n)
    {
        for (uint32_t i = 0; i < n; ++i)
            out.u8(static_cast<uint8_t>(v >> (8 * i)));
    }
    static void signed_value(raw::ByteWriter &out, uint8_t type, int64_t v)
    {
        uint32_t n = signed_size(v);
        header(out, type, n - 1);
        bytes(out, static_cast<uint64_t>(v), n);
    }
    static void unsigned_value(raw::ByteWriter &out, uint8_t type, uint64_t v)
    {
        uint32_t n = unsigned_size(v);
        header(out, type, n - 1);
        bytes(out, v, n);
    }
    // Floats are stored right-zero-extended: trailing zero bytes of the low
    // end are dropped.
    static void float_value(raw::ByteWriter &out, uint8_t type, uint64_t bits, uint32_t width)
    {
        uint32_t n = width;
        while (n > 1 && ((bits >> (8 * (width - n))) & 0xFF) == 0)
            --n;
        header(out, type, n - 1);
        bytes(out, bits >> (8 * (width - n)), n);
    }

    void encode(raw::ByteWriter &out, const Value::Null &) const { header(out, 0x1e, 0); }
    void encode(raw::ByteWriter &out, const Value::Boolean &x) const
    {
        header(out, 0x1f, x.value ? 1 : 0);
    }
    void encode(raw::ByteWriter &out, const Value::Byte &x) const
    {
        header(out, 0x00, 0);
        out.u8(static_cast<uint8_t>(x.value));
    }
    void encode(raw::ByteWriter &out, const Value::Short &x) const
    {
        signed_value(out, 0x02, x.value);
    }
    void encode(raw::ByteWriter &out, const Value::Char &x) const
    {
        unsigned_value(out, 0x03, static_cast<uint16_t>(x.value));
    }
    void encode(raw::ByteWriter &out, const Value::Int &x) const
    {
        signed_value(out, 0x04, x.value);
    }
    void encode(raw::ByteWriter &out, const Value::Long &x) const
    {
        signed_value(out, 0x06, x.value);
    }
    void encode(raw::ByteWriter &out, const Value::Float &x) const
    {
        float_value(out, 0x10, std::bit_cast<uint32_t>(x.value), 4);
    }
    void encode(raw::ByteWriter &out, const Value::Double &x) const
    {
        float_value(out, 0x11, std::bit_cast<uint64_t>(x.value), 8);
    }
    void encode(raw::ByteWriter &out, const Value::String &x) const
    {
        unsigned_value(out, 0x17, pools_.string(x.value));
    }
    void encode(raw::ByteWriter &out, const Value::Type &x) const
    {
        unsigned_value(out, 0x18, pools_.type(x.descriptor));
    }
    void encode(raw::ByteWriter &out, const Value::Field &x) const
    {
        unsigned_value(out, 0x19, pools_.field(x.field));
    }
    void encode(raw::ByteWriter &out, const Value::Method &x) const
    {
        unsigned_value(out, 0x1a, pools_.method(x.method));
    }
    void encode(raw::ByteWriter &out, const Value::Enum &x) const
    {
        unsigned_value(out, 0x1b, pools_.field(x.field));
    }
    void encode(raw::ByteWriter &out, const Value::MethodType &x) const
    {
        unsigned_value(out, 0x15, pools_.proto(x.proto));
    }
    void encode(raw::ByteWriter &out, const MethodHandle &x) const
    {
        unsigned_value(out, 0x16, pools_.method_handle(x));
    }
    void encode(raw::ByteWriter &out, const Value::Array &x) const
    {
        header(out, 0x1c, 0);
        array(out, x.values);
    }
    void encode(raw::ByteWriter &out, const Shared<EncodedAnnotation> &x) const
    {
        header(out, 0x1d, 0);
        annotation(out, x.get());
    }

    const Pools &pools_;
};

/** A field type's default value, for gaps in a static-values array. */
inline Value default_value(std::string_view type)
{
    switch (type.empty() ? 'L' : type.front()) {
    case 'Z':
        return Value{Value::Boolean{false}};
    case 'B':
        return Value{Value::Byte{0}};
    case 'S':
        return Value{Value::Short{0}};
    case 'C':
        return Value{Value::Char{0}};
    case 'I':
        return Value{Value::Int{0}};
    case 'J':
        return Value{Value::Long{0}};
    case 'F':
        return Value{Value::Float{0}};
    case 'D':
        return Value{Value::Double{0}};
    default:
        return Value{Value::Null{}};
    }
}

} // namespace dexsplit::model::detail

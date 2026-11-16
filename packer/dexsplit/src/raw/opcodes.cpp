#include "raw/opcodes.hpp"

namespace dexsplit::raw {

// clang-format off
constexpr std::array<OpcodeInfo, 256> detail::opcode_table = {{
    {"nop", Format::F10x, RefKind::None, 1}, // 0x00
    {"move", Format::F12x, RefKind::None, 1}, // 0x01
    {"move/from16", Format::F22x, RefKind::None, 2}, // 0x02
    {"move/16", Format::F32x, RefKind::None, 3}, // 0x03
    {"move-wide", Format::F12x, RefKind::None, 1}, // 0x04
    {"move-wide/from16", Format::F22x, RefKind::None, 2}, // 0x05
    {"move-wide/16", Format::F32x, RefKind::None, 3}, // 0x06
    {"move-object", Format::F12x, RefKind::None, 1}, // 0x07
    {"move-object/from16", Format::F22x, RefKind::None, 2}, // 0x08
    {"move-object/16", Format::F32x, RefKind::None, 3}, // 0x09
    {"move-result", Format::F11x, RefKind::None, 1}, // 0x0a
    {"move-result-wide", Format::F11x, RefKind::None, 1}, // 0x0b
    {"move-result-object", Format::F11x, RefKind::None, 1}, // 0x0c
    {"move-exception", Format::F11x, RefKind::None, 1}, // 0x0d
    {"return-void", Format::F10x, RefKind::None, 1}, // 0x0e
    {"return", Format::F11x, RefKind::None, 1}, // 0x0f
    {"return-wide", Format::F11x, RefKind::None, 1}, // 0x10
    {"return-object", Format::F11x, RefKind::None, 1}, // 0x11
    {"const/4", Format::F11n, RefKind::None, 1}, // 0x12
    {"const/16", Format::F21s, RefKind::None, 2}, // 0x13
    {"const", Format::F31i, RefKind::None, 3}, // 0x14
    {"const/high16", Format::F21h, RefKind::None, 2}, // 0x15
    {"const-wide/16", Format::F21s, RefKind::None, 2}, // 0x16
    {"const-wide/32", Format::F31i, RefKind::None, 3}, // 0x17
    {"const-wide", Format::F51l, RefKind::None, 5}, // 0x18
    {"const-wide/high16", Format::F21h, RefKind::None, 2}, // 0x19
    {"const-string", Format::F21c, RefKind::String, 2}, // 0x1a
    {"const-string/jumbo", Format::F31c, RefKind::String, 3}, // 0x1b
    {"const-class", Format::F21c, RefKind::Type, 2}, // 0x1c
    {"monitor-enter", Format::F11x, RefKind::None, 1}, // 0x1d
    {"monitor-exit", Format::F11x, RefKind::None, 1}, // 0x1e
    {"check-cast", Format::F21c, RefKind::Type, 2}, // 0x1f
    {"instance-of", Format::F22c, RefKind::Type, 2}, // 0x20
    {"array-length", Format::F12x, RefKind::None, 1}, // 0x21
    {"new-instance", Format::F21c, RefKind::Type, 2}, // 0x22
    {"new-array", Format::F22c, RefKind::Type, 2}, // 0x23
    {"filled-new-array", Format::F35c, RefKind::Type, 3}, // 0x24
    {"filled-new-array/range", Format::F3rc, RefKind::Type, 3}, // 0x25
    {"fill-array-data", Format::F31t, RefKind::None, 3}, // 0x26
    {"throw", Format::F11x, RefKind::None, 1}, // 0x27
    {"goto", Format::F10t, RefKind::None, 1}, // 0x28
    {"goto/16", Format::F20t, RefKind::None, 2}, // 0x29
    {"goto/32", Format::F30t, RefKind::None, 3}, // 0x2a
    {"packed-switch", Format::F31t, RefKind::None, 3}, // 0x2b
    {"sparse-switch", Format::F31t, RefKind::None, 3}, // 0x2c
    {"cmpl-float", Format::F23x, RefKind::None, 2}, // 0x2d
    {"cmpg-float", Format::F23x, RefKind::None, 2}, // 0x2e
    {"cmpl-double", Format::F23x, RefKind::None, 2}, // 0x2f
    {"cmpg-double", Format::F23x, RefKind::None, 2}, // 0x30
    {"cmp-long", Format::F23x, RefKind::None, 2}, // 0x31
    {"if-eq", Format::F22t, RefKind::None, 2}, // 0x32
    {"if-ne", Format::F22t, RefKind::None, 2}, // 0x33
    {"if-lt", Format::F22t, RefKind::None, 2}, // 0x34
    {"if-ge", Format::F22t, RefKind::None, 2}, // 0x35
    {"if-gt", Format::F22t, RefKind::None, 2}, // 0x36
    {"if-le", Format::F22t, RefKind::None, 2}, // 0x37
    {"if-eqz", Format::F21t, RefKind::None, 2}, // 0x38
    {"if-nez", Format::F21t, RefKind::None, 2}, // 0x39
    {"if-ltz", Format::F21t, RefKind::None, 2}, // 0x3a
    {"if-gez", Format::F21t, RefKind::None, 2}, // 0x3b
    {"if-gtz", Format::F21t, RefKind::None, 2}, // 0x3c
    {"if-lez", Format::F21t, RefKind::None, 2}, // 0x3d
    {"unused-3e", Format::Unused, RefKind::None, 1}, // 0x3e
    {"unused-3f", Format::Unused, RefKind::None, 1}, // 0x3f
    {"unused-40", Format::Unused, RefKind::None, 1}, // 0x40
    {"unused-41", Format::Unused, RefKind::None, 1}, // 0x41
    {"unused-42", Format::Unused, RefKind::None, 1}, // 0x42
    {"unused-43", Format::Unused, RefKind::None, 1}, // 0x43
    {"aget", Format::F23x, RefKind::None, 2}, // 0x44
    {"aget-wide", Format::F23x, RefKind::None, 2}, // 0x45
    {"aget-object", Format::F23x, RefKind::None, 2}, // 0x46
    {"aget-boolean", Format::F23x, RefKind::None, 2}, // 0x47
    {"aget-byte", Format::F23x, RefKind::None, 2}, // 0x48
    {"aget-char", Format::F23x, RefKind::None, 2}, // 0x49
    {"aget-short", Format::F23x, RefKind::None, 2}, // 0x4a
    {"aput", Format::F23x, RefKind::None, 2}, // 0x4b
    {"aput-wide", Format::F23x, RefKind::None, 2}, // 0x4c
    {"aput-object", Format::F23x, RefKind::None, 2}, // 0x4d
    {"aput-boolean", Format::F23x, RefKind::None, 2}, // 0x4e
    {"aput-byte", Format::F23x, RefKind::None, 2}, // 0x4f
    {"aput-char", Format::F23x, RefKind::None, 2}, // 0x50
    {"aput-short", Format::F23x, RefKind::None, 2}, // 0x51
    {"iget", Format::F22c, RefKind::Field, 2}, // 0x52
    {"iget-wide", Format::F22c, RefKind::Field, 2}, // 0x53
    {"iget-object", Format::F22c, RefKind::Field, 2}, // 0x54
    {"iget-boolean", Format::F22c, RefKind::Field, 2}, // 0x55
    {"iget-byte", Format::F22c, RefKind::Field, 2}, // 0x56
    {"iget-char", Format::F22c, RefKind::Field, 2}, // 0x57
    {"iget-short", Format::F22c, RefKind::Field, 2}, // 0x58
    {"iput", Format::F22c, RefKind::Field, 2}, // 0x59
    {"iput-wide", Format::F22c, RefKind::Field, 2}, // 0x5a
    {"iput-object", Format::F22c, RefKind::Field, 2}, // 0x5b
    {"iput-boolean", Format::F22c, RefKind::Field, 2}, // 0x5c
    {"iput-byte", Format::F22c, RefKind::Field, 2}, // 0x5d
    {"iput-char", Format::F22c, RefKind::Field, 2}, // 0x5e
    {"iput-short", Format::F22c, RefKind::Field, 2}, // 0x5f
    {"sget", Format::F21c, RefKind::Field, 2}, // 0x60
    {"sget-wide", Format::F21c, RefKind::Field, 2}, // 0x61
    {"sget-object", Format::F21c, RefKind::Field, 2}, // 0x62
    {"sget-boolean", Format::F21c, RefKind::Field, 2}, // 0x63
    {"sget-byte", Format::F21c, RefKind::Field, 2}, // 0x64
    {"sget-char", Format::F21c, RefKind::Field, 2}, // 0x65
    {"sget-short", Format::F21c, RefKind::Field, 2}, // 0x66
    {"sput", Format::F21c, RefKind::Field, 2}, // 0x67
    {"sput-wide", Format::F21c, RefKind::Field, 2}, // 0x68
    {"sput-object", Format::F21c, RefKind::Field, 2}, // 0x69
    {"sput-boolean", Format::F21c, RefKind::Field, 2}, // 0x6a
    {"sput-byte", Format::F21c, RefKind::Field, 2}, // 0x6b
    {"sput-char", Format::F21c, RefKind::Field, 2}, // 0x6c
    {"sput-short", Format::F21c, RefKind::Field, 2}, // 0x6d
    {"invoke-virtual", Format::F35c, RefKind::Method, 3}, // 0x6e
    {"invoke-super", Format::F35c, RefKind::Method, 3}, // 0x6f
    {"invoke-direct", Format::F35c, RefKind::Method, 3}, // 0x70
    {"invoke-static", Format::F35c, RefKind::Method, 3}, // 0x71
    {"invoke-interface", Format::F35c, RefKind::Method, 3}, // 0x72
    {"unused-73", Format::Unused, RefKind::None, 1}, // 0x73
    {"invoke-virtual/range", Format::F3rc, RefKind::Method, 3}, // 0x74
    {"invoke-super/range", Format::F3rc, RefKind::Method, 3}, // 0x75
    {"invoke-direct/range", Format::F3rc, RefKind::Method, 3}, // 0x76
    {"invoke-static/range", Format::F3rc, RefKind::Method, 3}, // 0x77
    {"invoke-interface/range", Format::F3rc, RefKind::Method, 3}, // 0x78
    {"unused-79", Format::Unused, RefKind::None, 1}, // 0x79
    {"unused-7a", Format::Unused, RefKind::None, 1}, // 0x7a
    {"neg-int", Format::F12x, RefKind::None, 1}, // 0x7b
    {"not-int", Format::F12x, RefKind::None, 1}, // 0x7c
    {"neg-long", Format::F12x, RefKind::None, 1}, // 0x7d
    {"not-long", Format::F12x, RefKind::None, 1}, // 0x7e
    {"neg-float", Format::F12x, RefKind::None, 1}, // 0x7f
    {"neg-double", Format::F12x, RefKind::None, 1}, // 0x80
    {"int-to-long", Format::F12x, RefKind::None, 1}, // 0x81
    {"int-to-float", Format::F12x, RefKind::None, 1}, // 0x82
    {"int-to-double", Format::F12x, RefKind::None, 1}, // 0x83
    {"long-to-int", Format::F12x, RefKind::None, 1}, // 0x84
    {"long-to-float", Format::F12x, RefKind::None, 1}, // 0x85
    {"long-to-double", Format::F12x, RefKind::None, 1}, // 0x86
    {"float-to-int", Format::F12x, RefKind::None, 1}, // 0x87
    {"float-to-long", Format::F12x, RefKind::None, 1}, // 0x88
    {"float-to-double", Format::F12x, RefKind::None, 1}, // 0x89
    {"double-to-int", Format::F12x, RefKind::None, 1}, // 0x8a
    {"double-to-long", Format::F12x, RefKind::None, 1}, // 0x8b
    {"double-to-float", Format::F12x, RefKind::None, 1}, // 0x8c
    {"int-to-byte", Format::F12x, RefKind::None, 1}, // 0x8d
    {"int-to-char", Format::F12x, RefKind::None, 1}, // 0x8e
    {"int-to-short", Format::F12x, RefKind::None, 1}, // 0x8f
    {"add-int", Format::F23x, RefKind::None, 2}, // 0x90
    {"sub-int", Format::F23x, RefKind::None, 2}, // 0x91
    {"mul-int", Format::F23x, RefKind::None, 2}, // 0x92
    {"div-int", Format::F23x, RefKind::None, 2}, // 0x93
    {"rem-int", Format::F23x, RefKind::None, 2}, // 0x94
    {"and-int", Format::F23x, RefKind::None, 2}, // 0x95
    {"or-int", Format::F23x, RefKind::None, 2}, // 0x96
    {"xor-int", Format::F23x, RefKind::None, 2}, // 0x97
    {"shl-int", Format::F23x, RefKind::None, 2}, // 0x98
    {"shr-int", Format::F23x, RefKind::None, 2}, // 0x99
    {"ushr-int", Format::F23x, RefKind::None, 2}, // 0x9a
    {"add-long", Format::F23x, RefKind::None, 2}, // 0x9b
    {"sub-long", Format::F23x, RefKind::None, 2}, // 0x9c
    {"mul-long", Format::F23x, RefKind::None, 2}, // 0x9d
    {"div-long", Format::F23x, RefKind::None, 2}, // 0x9e
    {"rem-long", Format::F23x, RefKind::None, 2}, // 0x9f
    {"and-long", Format::F23x, RefKind::None, 2}, // 0xa0
    {"or-long", Format::F23x, RefKind::None, 2}, // 0xa1
    {"xor-long", Format::F23x, RefKind::None, 2}, // 0xa2
    {"shl-long", Format::F23x, RefKind::None, 2}, // 0xa3
    {"shr-long", Format::F23x, RefKind::None, 2}, // 0xa4
    {"ushr-long", Format::F23x, RefKind::None, 2}, // 0xa5
    {"add-float", Format::F23x, RefKind::None, 2}, // 0xa6
    {"sub-float", Format::F23x, RefKind::None, 2}, // 0xa7
    {"mul-float", Format::F23x, RefKind::None, 2}, // 0xa8
    {"div-float", Format::F23x, RefKind::None, 2}, // 0xa9
    {"rem-float", Format::F23x, RefKind::None, 2}, // 0xaa
    {"add-double", Format::F23x, RefKind::None, 2}, // 0xab
    {"sub-double", Format::F23x, RefKind::None, 2}, // 0xac
    {"mul-double", Format::F23x, RefKind::None, 2}, // 0xad
    {"div-double", Format::F23x, RefKind::None, 2}, // 0xae
    {"rem-double", Format::F23x, RefKind::None, 2}, // 0xaf
    {"add-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb0
    {"sub-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb1
    {"mul-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb2
    {"div-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb3
    {"rem-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb4
    {"and-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb5
    {"or-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb6
    {"xor-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb7
    {"shl-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb8
    {"shr-int/2addr", Format::F12x, RefKind::None, 1}, // 0xb9
    {"ushr-int/2addr", Format::F12x, RefKind::None, 1}, // 0xba
    {"add-long/2addr", Format::F12x, RefKind::None, 1}, // 0xbb
    {"sub-long/2addr", Format::F12x, RefKind::None, 1}, // 0xbc
    {"mul-long/2addr", Format::F12x, RefKind::None, 1}, // 0xbd
    {"div-long/2addr", Format::F12x, RefKind::None, 1}, // 0xbe
    {"rem-long/2addr", Format::F12x, RefKind::None, 1}, // 0xbf
    {"and-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc0
    {"or-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc1
    {"xor-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc2
    {"shl-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc3
    {"shr-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc4
    {"ushr-long/2addr", Format::F12x, RefKind::None, 1}, // 0xc5
    {"add-float/2addr", Format::F12x, RefKind::None, 1}, // 0xc6
    {"sub-float/2addr", Format::F12x, RefKind::None, 1}, // 0xc7
    {"mul-float/2addr", Format::F12x, RefKind::None, 1}, // 0xc8
    {"div-float/2addr", Format::F12x, RefKind::None, 1}, // 0xc9
    {"rem-float/2addr", Format::F12x, RefKind::None, 1}, // 0xca
    {"add-double/2addr", Format::F12x, RefKind::None, 1}, // 0xcb
    {"sub-double/2addr", Format::F12x, RefKind::None, 1}, // 0xcc
    {"mul-double/2addr", Format::F12x, RefKind::None, 1}, // 0xcd
    {"div-double/2addr", Format::F12x, RefKind::None, 1}, // 0xce
    {"rem-double/2addr", Format::F12x, RefKind::None, 1}, // 0xcf
    {"add-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd0
    {"rsub-int", Format::F22s, RefKind::None, 2}, // 0xd1
    {"mul-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd2
    {"div-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd3
    {"rem-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd4
    {"and-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd5
    {"or-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd6
    {"xor-int/lit16", Format::F22s, RefKind::None, 2}, // 0xd7
    {"add-int/lit8", Format::F22b, RefKind::None, 2}, // 0xd8
    {"rsub-int/lit8", Format::F22b, RefKind::None, 2}, // 0xd9
    {"mul-int/lit8", Format::F22b, RefKind::None, 2}, // 0xda
    {"div-int/lit8", Format::F22b, RefKind::None, 2}, // 0xdb
    {"rem-int/lit8", Format::F22b, RefKind::None, 2}, // 0xdc
    {"and-int/lit8", Format::F22b, RefKind::None, 2}, // 0xdd
    {"or-int/lit8", Format::F22b, RefKind::None, 2}, // 0xde
    {"xor-int/lit8", Format::F22b, RefKind::None, 2}, // 0xdf
    {"shl-int/lit8", Format::F22b, RefKind::None, 2}, // 0xe0
    {"shr-int/lit8", Format::F22b, RefKind::None, 2}, // 0xe1
    {"ushr-int/lit8", Format::F22b, RefKind::None, 2}, // 0xe2
    {"unused-e3", Format::Unused, RefKind::None, 1}, // 0xe3
    {"unused-e4", Format::Unused, RefKind::None, 1}, // 0xe4
    {"unused-e5", Format::Unused, RefKind::None, 1}, // 0xe5
    {"unused-e6", Format::Unused, RefKind::None, 1}, // 0xe6
    {"unused-e7", Format::Unused, RefKind::None, 1}, // 0xe7
    {"unused-e8", Format::Unused, RefKind::None, 1}, // 0xe8
    {"unused-e9", Format::Unused, RefKind::None, 1}, // 0xe9
    {"unused-ea", Format::Unused, RefKind::None, 1}, // 0xea
    {"unused-eb", Format::Unused, RefKind::None, 1}, // 0xeb
    {"unused-ec", Format::Unused, RefKind::None, 1}, // 0xec
    {"unused-ed", Format::Unused, RefKind::None, 1}, // 0xed
    {"unused-ee", Format::Unused, RefKind::None, 1}, // 0xee
    {"unused-ef", Format::Unused, RefKind::None, 1}, // 0xef
    {"unused-f0", Format::Unused, RefKind::None, 1}, // 0xf0
    {"unused-f1", Format::Unused, RefKind::None, 1}, // 0xf1
    {"unused-f2", Format::Unused, RefKind::None, 1}, // 0xf2
    {"unused-f3", Format::Unused, RefKind::None, 1}, // 0xf3
    {"unused-f4", Format::Unused, RefKind::None, 1}, // 0xf4
    {"unused-f5", Format::Unused, RefKind::None, 1}, // 0xf5
    {"unused-f6", Format::Unused, RefKind::None, 1}, // 0xf6
    {"unused-f7", Format::Unused, RefKind::None, 1}, // 0xf7
    {"unused-f8", Format::Unused, RefKind::None, 1}, // 0xf8
    {"unused-f9", Format::Unused, RefKind::None, 1}, // 0xf9
    {"invoke-polymorphic", Format::F45cc, RefKind::Method, 4}, // 0xfa
    {"invoke-polymorphic/range", Format::F4rcc, RefKind::Method, 4}, // 0xfb
    {"invoke-custom", Format::F35c, RefKind::CallSite, 3}, // 0xfc
    {"invoke-custom/range", Format::F3rc, RefKind::CallSite, 3}, // 0xfd
    {"const-method-handle", Format::F21c, RefKind::MethodHandle, 2}, // 0xfe
    {"const-method-type", Format::F21c, RefKind::Proto, 2}, // 0xff
}};
// clang-format on

namespace {

int32_t sext4(uint32_t v)
{
    return (v & 0x8) ? static_cast<int32_t>(v | 0xFFFFFFF0u) : static_cast<int32_t>(v);
}

ParseError bad_insn(uint32_t pos, const char *what)
{
    return ParseError{ParseError::Code::InvalidOpcode, what, pos};
}

} // namespace

uint32_t format_units(Format format)
{
    switch (format) {
    case Format::F10x:
    case Format::F12x:
    case Format::F11n:
    case Format::F11x:
    case Format::F10t:
    case Format::Unused:
        return 1;
    case Format::F20t:
    case Format::F22x:
    case Format::F21t:
    case Format::F21s:
    case Format::F21h:
    case Format::F21c:
    case Format::F23x:
    case Format::F22b:
    case Format::F22t:
    case Format::F22s:
    case Format::F22c:
        return 2;
    case Format::F32x:
    case Format::F30t:
    case Format::F31t:
    case Format::F31i:
    case Format::F31c:
    case Format::F35c:
    case Format::F3rc:
        return 3;
    case Format::F45cc:
    case Format::F4rcc:
        return 4;
    case Format::F51l:
        return 5;
    }
    return 1;
}

std::optional<uint64_t> payload_units(std::span<const uint16_t> insns, uint32_t pos)
{
    if (pos >= insns.size())
        return std::nullopt;
    switch (insns[pos]) {
    case PACKED_SWITCH_PAYLOAD: // ident, size, first_key (2 units), targets (2 units each)
        if (insns.size() - pos < 2)
            return std::nullopt;
        return 4 + uint64_t{insns[pos + 1]} * 2;
    case SPARSE_SWITCH_PAYLOAD: // ident, size, keys and targets (2 units each)
        if (insns.size() - pos < 2)
            return std::nullopt;
        return 2 + uint64_t{insns[pos + 1]} * 4;
    case FILL_ARRAY_DATA_PAYLOAD: { // ident, element_width, size (2 units), data
        if (insns.size() - pos < 4)
            return std::nullopt;
        uint64_t width = insns[pos + 1];
        uint64_t count = insns[pos + 2] | (uint64_t{insns[pos + 3]} << 16);
        return 4 + (width * count + 1) / 2;
    }
    default:
        return std::nullopt;
    }
}

std::expected<InsnFields, ParseError> decode_insn(std::span<const uint16_t> insns, uint32_t pos)
{
    if (pos >= insns.size())
        return std::unexpected(bad_insn(pos, "instruction starts past the end of the code"));
    const uint16_t u0 = insns[pos];
    InsnFields f;
    f.opcode = static_cast<uint8_t>(u0 & 0xFF);
    const OpcodeInfo &info = opcode_info(f.opcode);
    if (info.format == Format::Unused)
        return std::unexpected(bad_insn(pos, "unused opcode"));
    if (f.opcode == 0x00 && (u0 >> 8) != 0)
        return std::unexpected(bad_insn(pos, "payload where an instruction was expected"));
    const uint32_t units = format_units(info.format);
    if (insns.size() - pos < units)
        return std::unexpected(bad_insn(pos, "instruction runs past the end of the code"));

    auto u = [&](uint32_t i) -> uint32_t { return insns[pos + i]; };
    const uint32_t aa = u0 >> 8;
    const uint32_t a4 = (u0 >> 8) & 0xF;
    const uint32_t b4 = u0 >> 12;
    switch (info.format) {
    case Format::F10x:
    case Format::Unused:
        break;
    case Format::F12x:
        f.a = a4;
        f.b = b4;
        break;
    case Format::F11n:
        f.a = a4;
        f.literal = sext4(b4);
        break;
    case Format::F11x:
        f.a = aa;
        break;
    case Format::F10t:
        f.offset = static_cast<int8_t>(aa);
        break;
    case Format::F20t:
        f.offset = static_cast<int16_t>(u(1));
        break;
    case Format::F22x:
        f.a = aa;
        f.b = u(1);
        break;
    case Format::F21t:
        f.a = aa;
        f.offset = static_cast<int16_t>(u(1));
        break;
    case Format::F21s:
    case Format::F21h:
        f.a = aa;
        f.literal = static_cast<int16_t>(u(1));
        break;
    case Format::F21c:
        f.a = aa;
        f.index = u(1);
        break;
    case Format::F23x:
        f.a = aa;
        f.b = u(1) & 0xFF;
        f.c = u(1) >> 8;
        break;
    case Format::F22b:
        f.a = aa;
        f.b = u(1) & 0xFF;
        f.literal = static_cast<int8_t>(u(1) >> 8);
        break;
    case Format::F22t:
        f.a = a4;
        f.b = b4;
        f.offset = static_cast<int16_t>(u(1));
        break;
    case Format::F22s:
        f.a = a4;
        f.b = b4;
        f.literal = static_cast<int16_t>(u(1));
        break;
    case Format::F22c:
        f.a = a4;
        f.b = b4;
        f.index = u(1);
        break;
    case Format::F32x:
        f.a = u(1);
        f.b = u(2);
        break;
    case Format::F30t:
        f.offset = static_cast<int32_t>(u(1) | (u(2) << 16));
        break;
    case Format::F31t:
        f.a = aa;
        f.offset = static_cast<int32_t>(u(1) | (u(2) << 16));
        break;
    case Format::F31i:
        f.a = aa;
        f.literal = static_cast<int32_t>(u(1) | (u(2) << 16));
        break;
    case Format::F31c:
        f.a = aa;
        f.index = u(1) | (u(2) << 16);
        break;
    case Format::F35c:
    case Format::F45cc: {
        f.a = b4; // argument count
        if (f.a > 5)
            return std::unexpected(bad_insn(pos, "more than 5 arguments"));
        f.index = u(1);
        const uint16_t regs[5] = {
            static_cast<uint16_t>(u(2) & 0xF),
            static_cast<uint16_t>((u(2) >> 4) & 0xF),
            static_cast<uint16_t>((u(2) >> 8) & 0xF),
            static_cast<uint16_t>(u(2) >> 12),
            static_cast<uint16_t>(a4),
        };
        for (uint32_t i = 0; i < f.a; ++i)
            f.args[i] = regs[i];
        if (info.format == Format::F45cc)
            f.proto = u(3);
        break;
    }
    case Format::F3rc:
    case Format::F4rcc:
        f.a = aa; // argument count
        f.index = u(1);
        f.c = u(2); // first register
        if (info.format == Format::F4rcc)
            f.proto = u(3);
        break;
    case Format::F51l:
        f.a = aa;
        f.literal = static_cast<int64_t>(uint64_t{u(1)} | (uint64_t{u(2)} << 16) |
                                         (uint64_t{u(3)} << 32) | (uint64_t{u(4)} << 48));
        break;
    }
    return f;
}

bool encode_insn(const InsnFields &f, std::vector<uint16_t> &out)
{
    const OpcodeInfo &info = opcode_info(f.opcode);
    auto fits_signed = [](int64_t v, int bits) {
        int64_t lo = -(int64_t{1} << (bits - 1));
        int64_t hi = (int64_t{1} << (bits - 1)) - 1;
        return v >= lo && v <= hi;
    };
    auto unit0 = [&](uint32_t high) { return static_cast<uint16_t>(f.opcode | (high << 8)); };
    auto lo16 = [](uint32_t v) { return static_cast<uint16_t>(v & 0xFFFF); };
    auto hi16 = [](uint32_t v) { return static_cast<uint16_t>(v >> 16); };

    uint16_t w[5] = {};
    switch (info.format) {
    case Format::Unused:
        return false;
    case Format::F10x:
        w[0] = unit0(0);
        break;
    case Format::F12x:
        if (f.a > 0xF || f.b > 0xF)
            return false;
        w[0] = unit0(f.a | (f.b << 4));
        break;
    case Format::F11n:
        if (f.a > 0xF || !fits_signed(f.literal, 4))
            return false;
        w[0] = unit0(f.a | ((static_cast<uint32_t>(f.literal) & 0xF) << 4));
        break;
    case Format::F11x:
        if (f.a > 0xFF)
            return false;
        w[0] = unit0(f.a);
        break;
    case Format::F10t:
        if (!fits_signed(f.offset, 8))
            return false;
        w[0] = unit0(static_cast<uint32_t>(f.offset) & 0xFF);
        break;
    case Format::F20t:
        if (!fits_signed(f.offset, 16))
            return false;
        w[0] = unit0(0);
        w[1] = lo16(static_cast<uint32_t>(f.offset));
        break;
    case Format::F22x:
        if (f.a > 0xFF || f.b > 0xFFFF)
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(f.b);
        break;
    case Format::F21t:
        if (f.a > 0xFF || !fits_signed(f.offset, 16))
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(static_cast<uint32_t>(f.offset));
        break;
    case Format::F21s:
    case Format::F21h:
        if (f.a > 0xFF || !fits_signed(f.literal, 16))
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(static_cast<uint32_t>(f.literal));
        break;
    case Format::F21c:
        if (f.a > 0xFF || f.index > 0xFFFF)
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(f.index);
        break;
    case Format::F23x:
        if (f.a > 0xFF || f.b > 0xFF || f.c > 0xFF)
            return false;
        w[0] = unit0(f.a);
        w[1] = static_cast<uint16_t>(f.b | (f.c << 8));
        break;
    case Format::F22b:
        if (f.a > 0xFF || f.b > 0xFF || !fits_signed(f.literal, 8))
            return false;
        w[0] = unit0(f.a);
        w[1] = static_cast<uint16_t>(f.b | ((static_cast<uint32_t>(f.literal) & 0xFF) << 8));
        break;
    case Format::F22t:
        if (f.a > 0xF || f.b > 0xF || !fits_signed(f.offset, 16))
            return false;
        w[0] = unit0(f.a | (f.b << 4));
        w[1] = lo16(static_cast<uint32_t>(f.offset));
        break;
    case Format::F22s:
        if (f.a > 0xF || f.b > 0xF || !fits_signed(f.literal, 16))
            return false;
        w[0] = unit0(f.a | (f.b << 4));
        w[1] = lo16(static_cast<uint32_t>(f.literal));
        break;
    case Format::F22c:
        if (f.a > 0xF || f.b > 0xF || f.index > 0xFFFF)
            return false;
        w[0] = unit0(f.a | (f.b << 4));
        w[1] = lo16(f.index);
        break;
    case Format::F32x:
        if (f.a > 0xFFFF || f.b > 0xFFFF)
            return false;
        w[0] = unit0(0);
        w[1] = lo16(f.a);
        w[2] = lo16(f.b);
        break;
    case Format::F30t:
        w[0] = unit0(0);
        w[1] = lo16(static_cast<uint32_t>(f.offset));
        w[2] = hi16(static_cast<uint32_t>(f.offset));
        break;
    case Format::F31t:
        if (f.a > 0xFF)
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(static_cast<uint32_t>(f.offset));
        w[2] = hi16(static_cast<uint32_t>(f.offset));
        break;
    case Format::F31i:
        if (f.a > 0xFF || !fits_signed(f.literal, 32))
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(static_cast<uint32_t>(f.literal));
        w[2] = hi16(static_cast<uint32_t>(f.literal));
        break;
    case Format::F31c:
        if (f.a > 0xFF)
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(f.index);
        w[2] = hi16(f.index);
        break;
    case Format::F35c:
    case Format::F45cc: {
        if (f.a > 5 || f.index > 0xFFFF || f.proto > 0xFFFF)
            return false;
        uint16_t regs[5] = {};
        for (uint32_t i = 0; i < f.a; ++i) {
            if (f.args[i] > 0xF)
                return false;
            regs[i] = f.args[i];
        }
        w[0] = unit0(regs[4] | (f.a << 4));
        w[1] = lo16(f.index);
        w[2] = static_cast<uint16_t>(regs[0] | (regs[1] << 4) | (regs[2] << 8) | (regs[3] << 12));
        w[3] = lo16(f.proto);
        break;
    }
    case Format::F3rc:
    case Format::F4rcc:
        if (f.a > 0xFF || f.index > 0xFFFF || f.proto > 0xFFFF || f.c > 0xFFFF ||
            f.c + f.a > 0x10000)
            return false;
        w[0] = unit0(f.a);
        w[1] = lo16(f.index);
        w[2] = lo16(f.c);
        w[3] = lo16(f.proto);
        break;
    case Format::F51l: {
        if (f.a > 0xFF)
            return false;
        uint64_t v = static_cast<uint64_t>(f.literal);
        w[0] = unit0(f.a);
        for (int i = 0; i < 4; ++i)
            w[1 + i] = static_cast<uint16_t>(v >> (16 * i));
        break;
    }
    }
    if (f.opcode == 0x00 && w[0] != 0)
        return false;
    out.insert(out.end(), w, w + format_units(info.format));
    return true;
}

} // namespace dexsplit::raw

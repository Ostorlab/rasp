#include "raw/code_validation.hpp"

#include <algorithm>

#include "raw/opcodes.hpp"

namespace dexsplit::raw {
namespace {
/// Widths of explicit register operands, independent of inferred ART register types.
std::array<bool, 3> wide_registers(uint8_t op) {
  bool a = (op >= 0x04 && op <= 0x06) || op == 0x0b || op == 0x10 || (op >= 0x16 && op <= 0x19) || op == 0x45 ||
           op == 0x4c || op == 0x53 || op == 0x5a || op == 0x61 || op == 0x68 || op == 0x7d || op == 0x7e ||
           op == 0x80 || op == 0x81 || op == 0x83 || op == 0x86 || op == 0x88 || op == 0x89 || op == 0x8b ||
           (op >= 0x9b && op <= 0xa5) || (op >= 0xab && op <= 0xaf) || (op >= 0xbb && op <= 0xc5) ||
           (op >= 0xcb && op <= 0xcf);
  bool b = (op >= 0x04 && op <= 0x06) || (op >= 0x2f && op <= 0x31) || op == 0x7d || op == 0x7e || op == 0x80 ||
           (op >= 0x84 && op <= 0x86) || (op >= 0x8a && op <= 0x8c) || (op >= 0x9b && op <= 0xa5) ||
           (op >= 0xab && op <= 0xaf) || (op >= 0xbb && op <= 0xc2) || (op >= 0xcb && op <= 0xcf);
  bool c = (op >= 0x2f && op <= 0x31) || (op >= 0x9b && op <= 0xa2) || (op >= 0xab && op <= 0xaf);
  return {a, b, c};
}
bool registers_fit(const InsnFields& insn, uint16_t frame) {
  const auto widths = wide_registers(insn.opcode);
  auto reg = [&](uint32_t value, std::size_t operand) { return value + (widths[operand] ? 1U : 0U) < frame; };
  switch (opcode_info(insn.opcode).format) {
    case Format::F12x:
    case Format::F22x:
    case Format::F22b:
    case Format::F22t:
    case Format::F22s:
    case Format::F22c:
    case Format::F32x:
      return reg(insn.a, 0) && reg(insn.b, 1);
    case Format::F23x:
      return reg(insn.a, 0) && reg(insn.b, 1) && reg(insn.c, 2);
    case Format::F11n:
    case Format::F11x:
    case Format::F21t:
    case Format::F21s:
    case Format::F21h:
    case Format::F21c:
    case Format::F31t:
    case Format::F31i:
    case Format::F31c:
    case Format::F51l:
      return reg(insn.a, 0);
    case Format::F35c:
    case Format::F45cc:
      for (uint32_t i = 0; i < insn.a; ++i) {
        budget::visit();
        if (insn.args[i] >= frame) {
          return false;
        }
      }
      return true;
    case Format::F3rc:
    case Format::F4rcc:
      return insn.a == 0 || (insn.c < frame && insn.a <= frame - insn.c);
    default:
      return true;
  }
}
}  // namespace
std::expected<CodeStructure, ParseError> validate_code_structure(const CodeItem& code) {
  budget::Scope scope(code.insns.get_allocator().owner());
  CodeStructure result;
  auto fail = [](const char* message, uint32_t at) -> std::expected<CodeStructure, ParseError> {
    return std::unexpected(ParseError{ParseError::Code::MalformedData, message, at});
  };
  if (code.ins_size > code.registers_size) {
    return fail("incoming arguments exceed code register frame", 0);
  }
  const auto& words = code.insns;
  const auto size = static_cast<uint32_t>(words.size());
  budget::Vector<uint8_t> boundary(words.size() + 1, 0);
  for (uint32_t at = 0; at < size;) {
    budget::visit();
    if ((words[at] & 255) == 0 && words[at] != 0) {
      auto length = payload_units(words, at);
      if (!length || *length > size - at || at % 2 != 0) {
        return fail("invalid code payload boundary", at);
      }
      if (words[at] == FILL_ARRAY_DATA_PAYLOAD && words[at + 1] != 1 && words[at + 1] != 2 && words[at + 1] != 4 &&
          words[at + 1] != 8) {
        return fail("invalid code fill-array payload width", at);
      }
      if (words[at] == SPARSE_SWITCH_PAYLOAD) {
        int64_t previous = INT64_MIN;
        for (uint32_t i = 0; i < words[at + 1]; ++i) {
          budget::visit();
          uint32_t pos = at + 2 + 2 * i;
          int32_t key = static_cast<int32_t>(words[pos] | (uint32_t{words[pos + 1]} << 16));
          if (key <= previous) {
            return fail("unsorted sparse-switch payload keys", at);
          }
          previous = key;
        }
      }
      if (words[at] == PACKED_SWITCH_PAYLOAD && words[at + 1] != 0) {
        int32_t first = static_cast<int32_t>(words[at + 2] | (uint32_t{words[at + 3]} << 16));
        if (int64_t{first} + words[at + 1] - 1 > INT32_MAX) {
          return fail("packed-switch payload keys overflow", at);
        }
      }
      result.payloads.emplace(at, static_cast<uint32_t>(*length));
      boundary[at] = 2;
      at += static_cast<uint32_t>(*length);
    } else {
      auto decoded = decode_insn(words, at);
      if (!decoded) {
        return std::unexpected(decoded.error());
      }
      if (!registers_fit(*decoded, code.registers_size)) {
        return fail("code instruction register outside frame", at);
      }
      if (((decoded->opcode >= 0x6e && decoded->opcode <= 0x78) ||
           (decoded->opcode >= 0xfa && decoded->opcode <= 0xfd)) &&
          decoded->a > code.outs_size) {
        return fail("invoke arguments exceed outgoing code registers", at);
      }
      result.starts.push_back(at);
      boundary[at] = 1;
      at += opcode_info(decoded->opcode).units;
    }
  }
  if (size == 0 || boundary.front() != 1) {
    return fail("code has no entry instruction", 0);
  }
  auto target = [&](uint32_t from, int64_t offset) {
    int64_t at = int64_t{from} + offset;
    return at >= 0 && at < size && boundary[static_cast<std::size_t>(at)] == 1;
  };
  for (std::size_t i = 0; i < result.starts.size(); ++i) {
    budget::visit();
    const auto at = result.starts[i];
    const auto insn = *decode_insn(words, at);
    const auto format = opcode_info(insn.opcode).format;
    if ((format == Format::F10t || format == Format::F20t || format == Format::F30t || format == Format::F21t ||
         format == Format::F22t) &&
        !target(at, insn.offset)) {
      return fail("code branch target is not an instruction boundary", at);
    }
    if (format == Format::F10t || format == Format::F20t || format == Format::F30t || format == Format::F21t ||
        format == Format::F22t) {
      result.targets.push_back(static_cast<uint32_t>(int64_t{at} + insn.offset));
    }
    if (format == Format::F31t) {
      int64_t pos = int64_t{at} + insn.offset;
      uint16_t ident = insn.opcode == 0x26   ? FILL_ARRAY_DATA_PAYLOAD
                       : insn.opcode == 0x2b ? PACKED_SWITCH_PAYLOAD
                                             : SPARSE_SWITCH_PAYLOAD;
      if (pos < 0 || pos >= size || boundary[static_cast<std::size_t>(pos)] != 2 ||
          words[static_cast<std::size_t>(pos)] != ident) {
        return fail("code instruction has no matching payload boundary", at);
      }
      auto payload = static_cast<uint32_t>(pos);
      if (ident != FILL_ARRAY_DATA_PAYLOAD) {
        uint32_t count = words[payload + 1];
        uint32_t first = payload + (ident == PACKED_SWITCH_PAYLOAD ? 4 : 2 + 2 * count);
        for (uint32_t i = 0; i < count; ++i) {
          budget::visit();
          int32_t offset = static_cast<int32_t>(words[first + 2 * i] | (uint32_t{words[first + 2 * i + 1]} << 16));
          if (!target(at, offset)) {
            return fail("switch case target is not an instruction boundary", at);
          }
          if (offset != 3) {
            result.targets.push_back(static_cast<uint32_t>(int64_t{at} + offset));
          }
        }
      }
    }
  }
  for (const auto& handler : code.handlers) {
    budget::visit();
    for (const auto& caught : handler.handlers) {
      budget::visit();
      if (!target(0, caught.addr)) {
        return fail("catch target is not an instruction boundary", caught.addr);
      }
      result.targets.push_back(caught.addr);
    }
    if (handler.catch_all_addr && !target(0, *handler.catch_all_addr)) {
      return fail("catch-all target is not an instruction boundary", *handler.catch_all_addr);
    }
    if (handler.catch_all_addr) {
      result.targets.push_back(*handler.catch_all_addr);
    }
  }
  uint32_t previous_end = 0;
  for (const auto& range : code.tries) {
    budget::visit();
    if (range.insn_count == 0 || !target(0, range.start_addr) || range.start_addr < previous_end ||
        range.insn_count > size - range.start_addr) {
      return fail("invalid/overlapping code try range", range.start_addr);
    }
    uint32_t end = range.start_addr + range.insn_count;
    if (end != size && boundary[end] == 0) {
      return fail("code try end is not an instruction/payload boundary", end);
    }
    if (!std::binary_search(code.handler_byte_offsets.begin(), code.handler_byte_offsets.end(), range.handler_off)) {
      return fail("code try handler offset is not a handler boundary", range.start_addr);
    }
    result.targets.push_back(range.start_addr);
    result.targets.push_back(end);
    previous_end = end;
  }
  budget::sort(result.targets.begin(), result.targets.end());
  result.targets.erase(std::unique(result.targets.begin(), result.targets.end()), result.targets.end());
  return result;
}
}  // namespace dexsplit::raw

#pragma once

// The encoder of method code of the DEX writer.  Internal: not part of the
// API.

#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "model/pools.hpp"
#include "raw/opcodes.hpp"

namespace dexsplit::model::detail {

/** A method's code_item contents, before layout. */
struct CodeOut
{
    uint16_t registers = 0;
    uint16_t ins = 0;
    uint16_t outs = 0;
    std::vector<uint16_t> insns;
    struct Try
    {
        uint32_t start;
        uint16_t count;
        uint16_t handler_off;
    };
    std::vector<Try> tries;
    std::vector<uint8_t> handlers; ///< encoded_catch_handler_list
    std::vector<uint8_t> debug;    ///< debug_info_item; empty for none
};

class CodeEncoder
{
  public:
    CodeEncoder(const Pools &pools, CallSites &sites, std::string where)
        : pools_(pools), sites_(sites), where_(std::move(where))
    {
    }

    CodeOut encode(const MethodDef &method, const Code &code, bool debug_info);

  private:
    // How a branch is encoded; the forms of one branch only ever grow.
    enum class Form : uint8_t {
        Fixed,
        Goto8,  // goto +AA
        Goto16, // goto/16 +AAAA
        Goto32, // goto/32 +AAAAAAAA (the only one that may branch to itself)
        IfNear, // if-* +CCCC
        IfNop,  // nop; if-* (a branch to itself goes back to the nop)
        IfFar,  // if-!cond +5; goto/32 target (out of 16-bit range)
    };

    struct Slot
    {
        uint32_t item = 0;      // index in Code::items
        raw::InsnFields fields; // the instruction, for every form but the branches
        Form form = Form::Fixed;
        uint32_t units = 0;
        Label target;         // branches
        bool payload = false; // switch or fill-array-data: has a payload
    };

    [[noreturn]] void fail_at(uint32_t item, std::string_view message) const
    {
        fail(Error::Kind::Invalid, std::format("{}, item {}: {}", where_, item, message));
    }

    raw::InsnFields fields_of(const Insn &insn, uint32_t item);
    static uint32_t form_units(Form form);
    static bool fits(Form form, int64_t offset);

    const Pools &pools_;
    CallSites &sites_;
    std::string where_;
};

} // namespace dexsplit::model::detail

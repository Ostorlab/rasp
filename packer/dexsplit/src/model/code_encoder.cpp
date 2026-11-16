#include "model/code_encoder.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <unordered_map>

#include "model/rules.hpp"
#include "raw/byte_writer.hpp"
#include "raw/constants.hpp"

namespace dexsplit::model::detail {

uint32_t CodeEncoder::form_units(Form form)
{
    switch (form) {
    case Form::Goto8:
        return 1;
    case Form::Goto16:
    case Form::IfNear:
        return 2;
    case Form::Goto32:
    case Form::IfNop:
        return 3;
    case Form::IfFar:
        return 5;
    case Form::Fixed:
        break;
    }
    return 0;
}

bool CodeEncoder::fits(Form form, int64_t offset)
{
    switch (form) {
    case Form::Goto8:
        return offset != 0 && offset >= -128 && offset <= 127;
    case Form::Goto16:
    case Form::IfNear:
    case Form::IfNop:
        return offset != 0 && offset >= -32768 && offset <= 32767;
    case Form::Goto32:
    case Form::IfFar:
        return true;
    case Form::Fixed:
        break;
    }
    return true;
}

raw::InsnFields CodeEncoder::fields_of(const Insn &insn, uint32_t item)
{
    raw::InsnFields f;
    auto set_args = [&](const RegList &args, uint8_t op_35c, uint8_t op_3rc) {
        if (detail::args_fit_35c(args)) {
            f.opcode = op_35c;
            f.a = static_cast<uint32_t>(args.size());
            for (std::size_t i = 0; i < args.size(); ++i)
                f.args[i] = args[i];
        }
        else if (detail::args_encodable(args)) {
            f.opcode = op_3rc;
            f.a = static_cast<uint32_t>(args.size());
            f.c = args.empty() ? 0 : args[0];
        }
        else {
            fail_at(item, "argument registers are neither five below v16 nor a run");
        }
    };
    auto kind = [](ValueKind k) { return static_cast<uint8_t>(k); };

    std::visit(
        [&](const auto &x) {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, Nop>) {
                f.opcode = 0x00;
            }
            else if constexpr (std::is_same_v<T, Move>) {
                uint8_t base = static_cast<uint8_t>(0x01 + 3 * kind(x.kind));
                f.a = x.dest;
                f.b = x.src;
                f.opcode = (x.dest < 16 && x.src < 16) ? base
                           : x.dest < 256              ? static_cast<uint8_t>(base + 1)
                                                       : static_cast<uint8_t>(base + 2);
            }
            else if constexpr (std::is_same_v<T, MoveResult>) {
                f.opcode = static_cast<uint8_t>(0x0a + kind(x.kind));
                f.a = x.dest;
            }
            else if constexpr (std::is_same_v<T, MoveException>) {
                f.opcode = 0x0d;
                f.a = x.dest;
            }
            else if constexpr (std::is_same_v<T, ReturnVoid>) {
                f.opcode = 0x0e;
            }
            else if constexpr (std::is_same_v<T, Return>) {
                f.opcode = static_cast<uint8_t>(0x0f + kind(x.kind));
                f.a = x.src;
            }
            else if constexpr (std::is_same_v<T, Const>) {
                f.a = x.dest;
                if (x.dest < 16 && x.value >= -8 && x.value <= 7) {
                    f.opcode = 0x12;
                    f.literal = x.value;
                }
                else if (x.value >= -32768 && x.value <= 32767) {
                    f.opcode = 0x13;
                    f.literal = x.value;
                }
                else if ((x.value & 0xFFFF) == 0) {
                    f.opcode = 0x15;
                    f.literal = static_cast<int16_t>(x.value >> 16);
                }
                else {
                    f.opcode = 0x14;
                    f.literal = x.value;
                }
            }
            else if constexpr (std::is_same_v<T, ConstWide>) {
                f.a = x.dest;
                if (x.value >= -32768 && x.value <= 32767) {
                    f.opcode = 0x16;
                    f.literal = x.value;
                }
                else if ((x.value & 0xFFFFFFFFFFFFLL) == 0) {
                    f.opcode = 0x19;
                    f.literal = static_cast<int16_t>(x.value >> 48);
                }
                else if (x.value >= INT32_MIN && x.value <= INT32_MAX) {
                    f.opcode = 0x17;
                    f.literal = x.value;
                }
                else {
                    f.opcode = 0x18;
                    f.literal = x.value;
                }
            }
            else if constexpr (std::is_same_v<T, ConstString>) {
                f.a = x.dest;
                f.index = pools_.memo(Pools::kString, x.value,
                                      [&](const std::string &s) { return pools_.string(s); });
                f.opcode = f.index <= 0xFFFF ? 0x1a : 0x1b;
            }
            else if constexpr (std::is_same_v<T, ConstClass>) {
                f.opcode = 0x1c;
                f.a = x.dest;
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, MonitorEnter>) {
                f.opcode = 0x1d;
                f.a = x.object;
            }
            else if constexpr (std::is_same_v<T, MonitorExit>) {
                f.opcode = 0x1e;
                f.a = x.object;
            }
            else if constexpr (std::is_same_v<T, CheckCast>) {
                f.opcode = 0x1f;
                f.a = x.object;
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, InstanceOf>) {
                f.opcode = 0x20;
                f.a = x.dest;
                f.b = x.object;
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, ArrayLength>) {
                f.opcode = 0x21;
                f.a = x.dest;
                f.b = x.array;
            }
            else if constexpr (std::is_same_v<T, NewInstance>) {
                f.opcode = 0x22;
                f.a = x.dest;
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, NewArray>) {
                f.opcode = 0x23;
                f.a = x.dest;
                f.b = x.size;
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, FilledNewArray>) {
                set_args(x.args, 0x24, 0x25);
                f.index = pools_.memo(Pools::kType, x.type,
                                      [&](const std::string &s) { return pools_.type(s); });
            }
            else if constexpr (std::is_same_v<T, FillArrayData>) {
                f.opcode = 0x26;
                f.a = x.array;
            }
            else if constexpr (std::is_same_v<T, Throw>) {
                f.opcode = 0x27;
                f.a = x.exception;
            }
            else if constexpr (std::is_same_v<T, Switch>) {
                f.a = x.value; // opcode chosen with the payload
            }
            else if constexpr (std::is_same_v<T, Compare>) {
                f.opcode = static_cast<uint8_t>(0x2d + static_cast<uint8_t>(x.op));
                f.a = x.dest;
                f.b = x.a;
                f.c = x.b;
            }
            else if constexpr (std::is_same_v<T, If>) {
                f.opcode = static_cast<uint8_t>(0x32 + static_cast<uint8_t>(x.cond));
                f.a = x.a;
                f.b = x.b;
            }
            else if constexpr (std::is_same_v<T, IfZero>) {
                f.opcode = static_cast<uint8_t>(0x38 + static_cast<uint8_t>(x.cond));
                f.a = x.value;
            }
            else if constexpr (std::is_same_v<T, ArrayGet>) {
                f.opcode = static_cast<uint8_t>(0x44 + kind(x.kind));
                f.a = x.dest;
                f.b = x.array;
                f.c = x.index;
            }
            else if constexpr (std::is_same_v<T, ArrayPut>) {
                f.opcode = static_cast<uint8_t>(0x4b + kind(x.kind));
                f.a = x.value;
                f.b = x.array;
                f.c = x.index;
            }
            else if constexpr (std::is_same_v<T, InstanceGet> || std::is_same_v<T, InstancePut>) {
                f.opcode = static_cast<uint8_t>((std::is_same_v<T, InstanceGet> ? 0x52 : 0x59) +
                                                kind(x.kind));
                if constexpr (std::is_same_v<T, InstanceGet>)
                    f.a = x.dest;
                else
                    f.a = x.value;
                f.b = x.object;
                f.index = pools_.memo(Pools::kField, x.field,
                                      [&](const FieldId &id) { return pools_.field(id); });
            }
            else if constexpr (std::is_same_v<T, StaticGet> || std::is_same_v<T, StaticPut>) {
                f.opcode = static_cast<uint8_t>((std::is_same_v<T, StaticGet> ? 0x60 : 0x67) +
                                                kind(x.kind));
                if constexpr (std::is_same_v<T, StaticGet>)
                    f.a = x.dest;
                else
                    f.a = x.value;
                f.index = pools_.memo(Pools::kField, x.field,
                                      [&](const FieldId &id) { return pools_.field(id); });
            }
            else if constexpr (std::is_same_v<T, Invoke>) {
                uint8_t k = static_cast<uint8_t>(x.kind);
                set_args(x.args, static_cast<uint8_t>(0x6e + k), static_cast<uint8_t>(0x74 + k));
                f.index = pools_.memo(Pools::kMethod, x.method,
                                      [&](const MethodId &id) { return pools_.method(id); });
            }
            else if constexpr (std::is_same_v<T, InvokePolymorphic>) {
                set_args(x.args, 0xfa, 0xfb);
                f.index = pools_.memo(Pools::kMethod, x.method,
                                      [&](const MethodId &id) { return pools_.method(id); });
                f.proto = pools_.memo(Pools::kProto, x.proto,
                                      [&](const std::string &s) { return pools_.proto(s); });
            }
            else if constexpr (std::is_same_v<T, InvokeCustom>) {
                set_args(x.args, 0xfc, 0xfd);
                f.index = sites_.id(x.call_site.get());
                if (f.index > 0xFFFF)
                    fail(Error::Kind::TooLarge,
                         std::format("{} call sites; a DEX file holds at most 65536",
                                     sites_.list().size()));
            }
            else if constexpr (std::is_same_v<T, ConstMethodHandle>) {
                f.opcode = 0xfe;
                f.a = x.dest;
                f.index = pools_.memo(Pools::kHandle, x.handle, [&](const MethodHandle &h) {
                    return pools_.method_handle(h);
                });
            }
            else if constexpr (std::is_same_v<T, ConstMethodType>) {
                f.opcode = 0xff;
                f.a = x.dest;
                f.index = pools_.memo(Pools::kProto, x.proto,
                                      [&](const std::string &s) { return pools_.proto(s); });
            }
            else if constexpr (std::is_same_v<T, Unary>) {
                f.opcode = static_cast<uint8_t>(0x7b + static_cast<uint8_t>(x.op));
                f.a = x.dest;
                f.b = x.src;
            }
            else if constexpr (std::is_same_v<T, Binary>) {
                uint8_t op = static_cast<uint8_t>(x.op);
                if (x.dest == x.a && x.a < 16 && x.b < 16) {
                    f.opcode = static_cast<uint8_t>(0xb0 + op);
                    f.a = x.dest;
                    f.b = x.b;
                }
                else {
                    f.opcode = static_cast<uint8_t>(0x90 + op);
                    f.a = x.dest;
                    f.b = x.a;
                    f.c = x.b;
                }
            }
            else if constexpr (std::is_same_v<T, BinaryLiteral>) {
                uint8_t op = static_cast<uint8_t>(x.op);
                f.a = x.dest;
                f.b = x.src;
                f.literal = x.literal;
                bool lit8 = x.literal >= -128 && x.literal <= 127 && x.dest < 256 && x.src < 256;
                f.opcode = lit8 ? static_cast<uint8_t>(0xd8 + op) : static_cast<uint8_t>(0xd0 + op);
            }
            else if constexpr (std::is_same_v<T, Goto>) {
                f.opcode = 0x28;
            }
        },
        insn);
    return f;
}

CodeOut CodeEncoder::encode(const MethodDef &method, const Code &code, bool debug_info)
{
    const std::vector<Item> &items = code.items;
    CodeOut out;
    out.registers = code.registers;
    out.ins = static_cast<uint16_t>(detail::ins_words(method));

    // Where each label is.
    std::unordered_map<uint32_t, uint32_t> label_item;
    for (uint32_t i = 0; i < items.size(); ++i)
        if (const Label *l = std::get_if<Label>(&items[i]))
            label_item.emplace(l->id, i);

    // One slot per instruction, starting each branch at its smallest form.
    std::vector<Slot> slots;
    std::vector<uint32_t> slot_of(items.size(), UINT32_MAX);
    uint32_t outs = 0;
    for (uint32_t i = 0; i < items.size(); ++i) {
        const Insn *insn = std::get_if<Insn>(&items[i]);
        if (!insn)
            continue;
        Slot s;
        s.item = i;
        s.fields = fields_of(*insn, i);
        if (const Goto *g = std::get_if<Goto>(insn)) {
            s.form = Form::Goto8;
            s.target = g->target;
        }
        else if (const If *x = std::get_if<If>(insn)) {
            s.form = Form::IfNear;
            s.target = x->target;
        }
        else if (const IfZero *x = std::get_if<IfZero>(insn)) {
            s.form = Form::IfNear;
            s.target = x->target;
        }
        else if (std::holds_alternative<Switch>(*insn) ||
                 std::holds_alternative<FillArrayData>(*insn)) {
            s.payload = true;
            s.units = 3;
        }
        s.units = s.form == Form::Fixed ? (s.payload ? 3 : raw::opcode_info(s.fields.opcode).units)
                                        : form_units(s.form);
        if (const Invoke *x = std::get_if<Invoke>(insn))
            outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
        else if (const InvokePolymorphic *x = std::get_if<InvokePolymorphic>(insn))
            outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
        else if (const InvokeCustom *x = std::get_if<InvokeCustom>(insn))
            outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
        slot_of[i] = static_cast<uint32_t>(slots.size());
        slots.push_back(s);
    }
    out.outs = static_cast<uint16_t>(outs);

    // Addresses of every item (labels and markers take the address of the
    // next instruction); widen branches that don't reach until nothing
    // changes.  Forms only grow, so this ends.
    std::vector<uint32_t> addr(items.size() + 1, 0);
    auto layout = [&] {
        uint64_t at = 0;
        for (uint32_t i = 0; i < items.size(); ++i) {
            addr[i] = static_cast<uint32_t>(at);
            if (slot_of[i] != UINT32_MAX)
                at += slots[slot_of[i]].units;
        }
        if (at > UINT32_MAX / 2)
            fail(Error::Kind::TooLarge, std::format("{}: the code is too long", where_));
        addr[items.size()] = static_cast<uint32_t>(at);
    };
    auto label_addr = [&](Label l) { return addr[label_item.at(l.id)]; };
    auto branch_offset = [&](const Slot &s) {
        int64_t origin =
            addr[s.item] + (s.form == Form::IfNop ? 1 : 0) + (s.form == Form::IfFar ? 2 : 0);
        return int64_t{label_addr(s.target)} - origin;
    };
    for (bool changed = true; changed;) {
        layout();
        changed = false;
        for (Slot &s : slots) {
            if (s.form == Form::Fixed || fits(s.form, branch_offset(s)))
                continue;
            int64_t offset = branch_offset(s);
            switch (s.form) {
            case Form::Goto8:
                s.form = fits(Form::Goto16, offset) ? Form::Goto16 : Form::Goto32;
                break;
            case Form::Goto16:
                s.form = Form::Goto32;
                break;
            case Form::IfNear:
                s.form = offset == 0 ? Form::IfNop : Form::IfFar;
                break;
            case Form::IfNop:
                s.form = Form::IfFar;
                break;
            default:
                break;
            }
            s.units = form_units(s.form);
            changed = true;
        }
    }

    // Payloads go after the last instruction, each at an even address.
    const uint32_t main_size = addr[items.size()];
    std::vector<uint32_t> payload_addr(slots.size(), 0);
    std::vector<uint16_t> payloads;
    for (uint32_t k = 0; k < slots.size(); ++k) {
        const Slot &s = slots[k];
        if (!s.payload)
            continue;
        if ((main_size + payloads.size()) % 2 != 0)
            payloads.push_back(0); // nop
        payload_addr[k] = main_size + static_cast<uint32_t>(payloads.size());
        const Insn &insn = std::get<Insn>(items[s.item]);
        if (const FillArrayData *fill = std::get_if<FillArrayData>(&insn)) {
            uint32_t count = static_cast<uint32_t>(fill->data.size() / fill->element_width);
            payloads.push_back(raw::FILL_ARRAY_DATA_PAYLOAD);
            payloads.push_back(fill->element_width);
            payloads.push_back(static_cast<uint16_t>(count));
            payloads.push_back(static_cast<uint16_t>(count >> 16));
            for (std::size_t b = 0; b < fill->data.size(); b += 2) {
                uint16_t lo = fill->data[b];
                uint16_t hi = b + 1 < fill->data.size() ? fill->data[b + 1] : 0;
                payloads.push_back(static_cast<uint16_t>(lo | (hi << 8)));
            }
            slots[k].fields.offset = static_cast<int32_t>(payload_addr[k] - addr[s.item]);
            continue;
        }
        // A switch: packed when the keys are dense enough, else sparse.
        const Switch &sw = std::get<Switch>(insn);
        std::vector<Switch::Case> cases = sw.cases;
        std::sort(cases.begin(), cases.end(),
                  [](const Switch::Case &a, const Switch::Case &b) { return a.key < b.key; });
        const int64_t here = addr[s.item];
        auto rel = [&](Label l) { return static_cast<uint32_t>(int64_t{label_addr(l)} - here); };
        auto put32 = [&](uint32_t v) {
            payloads.push_back(static_cast<uint16_t>(v));
            payloads.push_back(static_cast<uint16_t>(v >> 16));
        };
        const uint64_t n = cases.size();
        const uint64_t range =
            n == 0 ? 0 : uint64_t(int64_t{cases.back().key} - cases.front().key) + 1;
        const bool packed = n > 0 && range <= 0xFFFF && 4 + 2 * range <= 2 + 4 * n;
        if (packed) {
            slots[k].fields.opcode = 0x2b;
            payloads.push_back(raw::PACKED_SWITCH_PAYLOAD);
            payloads.push_back(static_cast<uint16_t>(range));
            put32(static_cast<uint32_t>(cases.front().key));
            const uint32_t fallthrough = 3; // the next instruction, relative to the switch
            std::size_t next = 0;
            for (uint64_t key = 0; key < range; ++key) {
                int64_t value = int64_t{cases.front().key} + static_cast<int64_t>(key);
                if (next < cases.size() && cases[next].key == value)
                    put32(rel(cases[next++].target));
                else
                    put32(fallthrough);
            }
        }
        else {
            slots[k].fields.opcode = 0x2c;
            payloads.push_back(raw::SPARSE_SWITCH_PAYLOAD);
            payloads.push_back(static_cast<uint16_t>(n));
            for (const Switch::Case &c : cases)
                put32(static_cast<uint32_t>(c.key));
            for (const Switch::Case &c : cases)
                put32(rel(c.target));
        }
        slots[k].fields.offset = static_cast<int32_t>(payload_addr[k] - addr[s.item]);
    }

    // Emit.
    out.insns.reserve(main_size + payloads.size());
    for (const Slot &s : slots) {
        raw::InsnFields f = s.fields;
        bool ok = true;
        const int64_t offset = s.form == Form::Fixed ? 0 : branch_offset(s);
        switch (s.form) {
        case Form::Fixed:
            ok = raw::encode_insn(f, out.insns);
            break;
        case Form::Goto8:
        case Form::Goto16:
        case Form::Goto32:
            f.opcode = s.form == Form::Goto8 ? 0x28 : s.form == Form::Goto16 ? 0x29 : 0x2a;
            f.offset = static_cast<int32_t>(offset);
            ok = raw::encode_insn(f, out.insns);
            break;
        case Form::IfNear:
            f.offset = static_cast<int32_t>(offset);
            ok = raw::encode_insn(f, out.insns);
            break;
        case Form::IfNop:
            out.insns.push_back(0); // nop
            f.offset = static_cast<int32_t>(offset);
            ok = raw::encode_insn(f, out.insns);
            break;
        case Form::IfFar: {
            // Branch over a goto/32 on the opposite condition.
            const Insn &insn = std::get<Insn>(items[s.item]);
            uint8_t base = std::holds_alternative<If>(insn) ? 0x32 : 0x38;
            Condition cond = static_cast<Condition>(f.opcode - base);
            f.opcode = static_cast<uint8_t>(base + static_cast<uint8_t>(detail::negate(cond)));
            f.offset = 5;
            raw::InsnFields jump;
            jump.opcode = 0x2a;
            jump.offset = static_cast<int32_t>(offset);
            ok = raw::encode_insn(f, out.insns) && raw::encode_insn(jump, out.insns);
            break;
        }
        }
        if (!ok)
            fail_at(s.item, "the instruction's operands do not fit its encoding");
    }
    if (out.insns.size() != main_size)
        fail(Error::Kind::Invalid, std::format("{}: internal error laying out code", where_));
    out.insns.insert(out.insns.end(), payloads.begin(), payloads.end());

    // Try ranges.  Ranges may overlap; split the code at every range
    // boundary, give each piece the handlers of the ranges covering it in
    // order until a catch-all (the runtime takes the first matching catch),
    // then join neighbours with equal handlers.  A range's
    // own catch list is kept as it is, duplicates included.
    struct Handler
    {
        std::vector<std::pair<uint32_t, uint32_t>> catches; // type index, address
        std::optional<uint32_t> catch_all;
        bool operator==(const Handler &) const = default;
    };
    struct Piece
    {
        uint32_t start, end;
        Handler handler;
    };
    std::vector<uint32_t> bounds;
    for (const TryRange &t : code.tries) {
        uint32_t start = label_addr(t.start);
        uint32_t end = label_addr(t.end);
        if (start < end) {
            bounds.push_back(start);
            bounds.push_back(end);
        }
    }
    std::sort(bounds.begin(), bounds.end());
    bounds.erase(std::unique(bounds.begin(), bounds.end()), bounds.end());
    std::vector<Piece> pieces;
    for (std::size_t b = 0; b + 1 < bounds.size(); ++b) {
        Piece piece{bounds[b], bounds[b + 1], {}};
        for (const TryRange &t : code.tries) {
            if (piece.handler.catch_all)
                break; // nothing after a catch-all is reached
            if (label_addr(t.start) > piece.start || label_addr(t.end) < piece.end)
                continue;
            for (const Catch &c : t.catches)
                piece.handler.catches.emplace_back(pools_.type(c.type), label_addr(c.handler));
            if (t.catch_all)
                piece.handler.catch_all = label_addr(*t.catch_all);
        }
        if (piece.handler.catches.empty() && !piece.handler.catch_all)
            continue;
        if (!pieces.empty() && pieces.back().end == piece.start &&
            pieces.back().handler == piece.handler)
            pieces.back().end = piece.end;
        else
            pieces.push_back(std::move(piece));
    }
    if (!pieces.empty()) {
        std::vector<Handler> handlers;
        std::vector<uint16_t> handler_offsets;
        raw::ByteWriter list;
        std::vector<std::size_t> piece_handler;
        for (const Piece &p : pieces) {
            auto it = std::find(handlers.begin(), handlers.end(), p.handler);
            piece_handler.push_back(static_cast<std::size_t>(it - handlers.begin()));
            if (it == handlers.end())
                handlers.push_back(p.handler);
        }
        list.uleb128(static_cast<uint32_t>(handlers.size()));
        for (const Handler &h : handlers) {
            if (list.size() > 0xFFFF)
                fail(Error::Kind::TooLarge, std::format("{}: too many exception handlers", where_));
            handler_offsets.push_back(static_cast<uint16_t>(list.size()));
            int32_t count = static_cast<int32_t>(h.catches.size());
            list.sleb128(h.catch_all ? -count : count);
            for (const auto &[type, address] : h.catches) {
                list.uleb128(type);
                list.uleb128(address);
            }
            if (h.catch_all)
                list.uleb128(*h.catch_all);
        }
        out.handlers = list.take();
        for (std::size_t k = 0; k < pieces.size(); ++k) {
            // A try_item covers at most 65535 code units and starts at an instruction.
            for (uint32_t start = pieces[k].start; start < pieces[k].end;) {
                uint32_t end = pieces[k].end;
                if (end - start > 0xFFFF)
                    end = *std::prev(std::upper_bound(addr.begin(), addr.end(), start + 0xFFFF));
                out.tries.push_back(
                    {start, static_cast<uint16_t>(end - start), handler_offsets[piece_handler[k]]});
                start = end;
            }
        }
        if (out.tries.size() > 0xFFFF)
            fail(Error::Kind::TooLarge, std::format("{}: too many try ranges", where_));
    }

    // Debug info: replay the markers through the state machine.
    if (debug_info) {
        bool any = !code.parameter_names.empty();
        for (const Item &item : items)
            any = any ||
                  (!std::holds_alternative<Insn>(item) && !std::holds_alternative<Label>(item));
        if (any) {
            raw::ByteWriter d;
            uint32_t line = 0;
            for (const Item &item : items)
                if (const LineNumber *l = std::get_if<LineNumber>(&item)) {
                    line = l->line;
                    break;
                }
            d.uleb128(line);
            d.uleb128(static_cast<uint32_t>(code.parameter_names.size()));
            for (const auto &name : code.parameter_names)
                d.uleb128p1(name ? pools_.string(*name) : raw::NO_INDEX);
            uint32_t at = 0;
            auto advance_to = [&](uint32_t address) {
                if (address > at) {
                    d.u8(raw::DBG_ADVANCE_PC);
                    d.uleb128(address - at);
                    at = address;
                }
            };
            for (uint32_t i = 0; i < items.size(); ++i) {
                const Item &item = items[i];
                const uint32_t address = addr[i];
                if (const LineNumber *l = std::get_if<LineNumber>(&item)) {
                    int32_t line_delta = static_cast<int32_t>(l->line - line);
                    if (line_delta < -4 || line_delta > 10) {
                        d.u8(raw::DBG_ADVANCE_LINE);
                        d.sleb128(line_delta);
                        line_delta = 0;
                    }
                    uint32_t addr_delta = address - at;
                    uint32_t special = static_cast<uint32_t>(line_delta + 4) + addr_delta * 15 +
                                       raw::DBG_FIRST_SPECIAL;
                    if (addr_delta > 17 || special > 0xFF) {
                        advance_to(address);
                        special = static_cast<uint32_t>(line_delta + 4) + raw::DBG_FIRST_SPECIAL;
                    }
                    d.u8(static_cast<uint8_t>(special));
                    at = address;
                    line = l->line;
                }
                else if (const LocalStart *s = std::get_if<LocalStart>(&item)) {
                    advance_to(address);
                    const LocalVariable &v = s->local.get();
                    d.u8(v.signature ? raw::DBG_START_LOCAL_EXTENDED : raw::DBG_START_LOCAL);
                    d.uleb128(s->reg);
                    d.uleb128p1(v.name ? pools_.string(*v.name) : raw::NO_INDEX);
                    d.uleb128p1(v.type ? pools_.type(*v.type) : raw::NO_INDEX);
                    if (v.signature)
                        d.uleb128p1(pools_.string(*v.signature));
                }
                else if (const LocalEnd *e = std::get_if<LocalEnd>(&item)) {
                    advance_to(address);
                    d.u8(raw::DBG_END_LOCAL);
                    d.uleb128(e->reg);
                }
                else if (const LocalRestart *r = std::get_if<LocalRestart>(&item)) {
                    advance_to(address);
                    d.u8(raw::DBG_RESTART_LOCAL);
                    d.uleb128(r->reg);
                }
                else if (std::holds_alternative<PrologueEnd>(item)) {
                    advance_to(address);
                    d.u8(raw::DBG_SET_PROLOGUE_END);
                }
                else if (std::holds_alternative<EpilogueBegin>(item)) {
                    advance_to(address);
                    d.u8(raw::DBG_SET_EPILOGUE_BEGIN);
                }
                else if (const SetSourceFile *f = std::get_if<SetSourceFile>(&item)) {
                    advance_to(address);
                    d.u8(raw::DBG_SET_FILE);
                    d.uleb128p1(f->name ? pools_.string(*f->name) : raw::NO_INDEX);
                }
            }
            d.u8(raw::DBG_END_SEQUENCE);
            out.debug = d.take();
        }
    }
    return out;
}

} // namespace dexsplit::model::detail

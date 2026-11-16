#include <algorithm>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <tuple>
#include <unordered_map>

#include "model/io.hpp"
#include "raw/constants.hpp"
#include "raw/mutf8.hpp"
#include "raw/opcodes.hpp"
#include "raw/parser.hpp"
#include "raw/parsing_utils.hpp"
#include "raw/types.hpp"

namespace dexsplit::model {

namespace {

// The reader can find malformed data at any depth — in a pool, a nested
// value, an instruction, the debug info — so it reports it with an exception
// that read() turns into an Error.  Nothing else throws it.
struct ReadFailure
{
    Error error;
};

constexpr int kMaxValueDepth = 64;

ValueKind kind_at(uint8_t opcode, uint8_t base) { return static_cast<ValueKind>(opcode - base); }

class Reader
{
  public:
    Reader(std::span<const uint8_t> bytes, const raw::DexFile &file, const ReadOptions &options)
        : bytes_(bytes), file_(file), options_(options), strings_(file.string_ids().size()),
          protos_(file.proto_ids().size()), fields_(file.field_ids().size()),
          methods_(file.method_ids().size()), method_handles_(file.method_handles().size()),
          call_sites_(file.call_site_ids().size())
    {
    }

    Dex run(uint32_t version)
    {
        Dex dex;
        dex.version = version;
        for (const raw::ClassDefItem &cd : file_.class_defs()) {
            where_.clear();
            const std::string &type = type_at(cd.class_idx).get();
            if (options_.keep_class && !options_.keep_class(type))
                continue;
            dex.classes.push_back(read_class(cd));
        }
        return dex;
    }

  private:
    // ===== failures =====

    [[noreturn]] void fail(std::string_view message) const
    {
        std::string text =
            where_.empty() ? std::string(message) : std::format("{}: {}", where_, message);
        throw ReadFailure{Error{Error::Kind::Malformed, std::move(text), {}}};
    }

    template <class T> T check(std::expected<T, raw::ParseError> r) const
    {
        if (!r)
            fail(r.error().message);
        return std::move(*r);
    }

    uint32_t read_uleb128(uint32_t &offset) const
    {
        return check(raw::parse_utils::read_uleb128(bytes_, offset));
    }

    // ===== pools: each entry is decoded once and shared =====

    // Lazily filled caches indexed like the file's id tables.
    template <class T> struct Cache
    {
        explicit Cache(std::size_t n) : values(n), done(n, false) {}
        std::vector<Shared<T>> values;
        std::vector<bool> done;
    };

    const Shared<std::string> &string_at(uint32_t idx)
    {
        if (idx >= strings_.values.size())
            fail(std::format("string index {} is out of range", idx));
        if (!strings_.done[idx]) {
            auto s = raw::mutf8::decode_string_data(bytes_, file_.string_ids()[idx]);
            if (!s)
                fail(std::format("string {}: {}", idx, s.error().message));
            strings_.values[idx] = std::move(*s);
            strings_.done[idx] = true;
        }
        return strings_.values[idx];
    }

    const Shared<std::string> &type_at(uint32_t idx)
    {
        if (idx >= file_.type_ids().size())
            fail(std::format("type index {} is out of range", idx));
        return string_at(file_.type_ids()[idx]);
    }

    const Shared<std::string> &proto_at(uint32_t idx)
    {
        if (idx >= protos_.values.size())
            fail(std::format("prototype index {} is out of range", idx));
        if (!protos_.done[idx]) {
            const raw::ProtoIdItem &p = file_.proto_ids()[idx];
            std::string proto = "(";
            if (p.parameters_off != 0) {
                raw::TypeList params =
                    check(raw::parser::parse_type_list(bytes_, p.parameters_off));
                for (uint16_t t : params.type_ids)
                    proto += type_at(t).get();
            }
            proto += ')';
            proto += type_at(p.return_type_idx).get();
            protos_.values[idx] = std::move(proto);
            protos_.done[idx] = true;
        }
        return protos_.values[idx];
    }

    const Shared<FieldId> &field_at(uint32_t idx)
    {
        if (idx >= fields_.values.size())
            fail(std::format("field index {} is out of range", idx));
        if (!fields_.done[idx]) {
            const raw::FieldIdItem &f = file_.field_ids()[idx];
            fields_.values[idx] = FieldId{type_at(f.class_idx).get(), string_at(f.name_idx).get(),
                                          type_at(f.type_idx).get()};
            fields_.done[idx] = true;
        }
        return fields_.values[idx];
    }

    const Shared<MethodId> &method_at(uint32_t idx)
    {
        if (idx >= methods_.values.size())
            fail(std::format("method index {} is out of range", idx));
        if (!methods_.done[idx]) {
            const raw::MethodIdItem &m = file_.method_ids()[idx];
            methods_.values[idx] = MethodId{type_at(m.class_idx).get(), string_at(m.name_idx).get(),
                                            proto_at(m.proto_idx).get()};
            methods_.done[idx] = true;
        }
        return methods_.values[idx];
    }

    const Shared<MethodHandle> &method_handle_at(uint32_t idx)
    {
        if (idx >= method_handles_.values.size())
            fail(std::format("method handle index {} is out of range", idx));
        if (!method_handles_.done[idx]) {
            const raw::MethodHandleItem &h = file_.method_handles()[idx];
            if (h.method_handle_type > 0x08)
                fail(std::format("bad method handle type {}", h.method_handle_type));
            MethodHandle handle;
            handle.kind = static_cast<MethodHandleKind>(h.method_handle_type);
            if (h.method_handle_type <= 0x03)
                handle.member = field_at(h.field_or_method_id).get();
            else
                handle.member = method_at(h.field_or_method_id).get();
            method_handles_.values[idx] = std::move(handle);
            method_handles_.done[idx] = true;
        }
        return method_handles_.values[idx];
    }

    const Shared<CallSite> &call_site_at(uint32_t idx)
    {
        if (idx >= call_sites_.values.size())
            fail(std::format("call site index {} is out of range", idx));
        if (!call_sites_.done[idx]) {
            uint32_t offset = file_.call_site_ids()[idx].call_site_off;
            std::vector<Value> values = read_array(offset, 0);
            if (values.size() < 3)
                fail(std::format("call site {} has fewer than 3 values", idx));
            const auto *bootstrap = std::get_if<MethodHandle>(&values[0].data);
            const auto *name = std::get_if<Value::String>(&values[1].data);
            const auto *type = std::get_if<Value::MethodType>(&values[2].data);
            if (!bootstrap || !name || !type)
                fail(std::format("call site {} does not start with a method handle, a name "
                                 "and a method type",
                                 idx));
            CallSite site;
            site.bootstrap = *bootstrap;
            site.method_name = name->value;
            site.method_type = type->proto;
            site.extra_args.assign(std::make_move_iterator(values.begin() + 3),
                                   std::make_move_iterator(values.end()));
            site.share_key = idx + 1;
            call_sites_.values[idx] = std::move(site);
            call_sites_.done[idx] = true;
        }
        return call_sites_.values[idx];
    }

    // ===== encoded values =====

    uint64_t read_le(uint32_t &offset, uint32_t size)
    {
        if (offset > bytes_.size() || bytes_.size() - offset < size)
            fail("encoded value runs past the end of the file");
        uint64_t v = 0;
        for (uint32_t i = 0; i < size; ++i)
            v |= uint64_t{bytes_[offset + i]} << (8 * i);
        offset += size;
        return v;
    }

    static int64_t sign_extend(uint64_t v, uint32_t size)
    {
        unsigned shift = 64 - 8 * size;
        return static_cast<int64_t>(v << shift) >> shift;
    }

    Value read_value(uint32_t &offset, int depth)
    {
        if (depth > kMaxValueDepth)
            fail("encoded values nest too deeply");
        if (offset >= bytes_.size())
            fail("encoded value runs past the end of the file");
        const uint8_t header = bytes_[offset++];
        const uint32_t type = header & 0x1F;
        const uint32_t arg = header >> 5;
        auto limit = [&](uint32_t max_arg) {
            if (arg > max_arg)
                fail(std::format("bad size {} for encoded value type 0x{:02x}", arg + 1, type));
        };
        auto index = [&] {
            limit(3);
            return static_cast<uint32_t>(read_le(offset, arg + 1));
        };
        switch (type) {
        case 0x00:
            limit(0);
            return Value{Value::Byte{static_cast<int8_t>(read_le(offset, 1))}};
        case 0x02:
            limit(1);
            return Value{
                Value::Short{static_cast<int16_t>(sign_extend(read_le(offset, arg + 1), arg + 1))}};
        case 0x03:
            limit(1);
            return Value{Value::Char{static_cast<char16_t>(read_le(offset, arg + 1))}};
        case 0x04:
            limit(3);
            return Value{
                Value::Int{static_cast<int32_t>(sign_extend(read_le(offset, arg + 1), arg + 1))}};
        case 0x06:
            return Value{Value::Long{sign_extend(read_le(offset, arg + 1), arg + 1)}};
        case 0x10: {
            limit(3);
            // Stored right-zero-extended: the bytes are the high end of the bits.
            uint64_t bits = read_le(offset, arg + 1) << (8 * (3 - arg));
            return Value{Value::Float{std::bit_cast<float>(static_cast<uint32_t>(bits))}};
        }
        case 0x11: {
            uint64_t bits = read_le(offset, arg + 1) << (8 * (7 - arg));
            return Value{Value::Double{std::bit_cast<double>(bits)}};
        }
        case 0x15:
            return Value{Value::MethodType{proto_at(index()).get()}};
        case 0x16:
            return Value{method_handle_at(index()).get()};
        case 0x17:
            return Value{Value::String{string_at(index()).get()}};
        case 0x18:
            return Value{Value::Type{type_at(index()).get()}};
        case 0x19:
            return Value{Value::Field{field_at(index()).get()}};
        case 0x1a:
            return Value{Value::Method{method_at(index()).get()}};
        case 0x1b:
            return Value{Value::Enum{field_at(index()).get()}};
        case 0x1c:
            limit(0);
            return Value{Value::Array{read_array(offset, depth + 1)}};
        case 0x1d:
            limit(0);
            return Value{Shared<EncodedAnnotation>(read_encoded_annotation(offset, depth + 1))};
        case 0x1e:
            limit(0);
            return Value{Value::Null{}};
        case 0x1f:
            limit(1);
            return Value{Value::Boolean{arg == 1}};
        default:
            fail(std::format("bad encoded value type 0x{:02x}", type));
        }
    }

    std::vector<Value> read_array(uint32_t &offset, int depth)
    {
        uint32_t count = read_uleb128(offset);
        std::vector<Value> values;
        // Every value takes at least one byte: the file bounds the count.
        values.reserve(std::min<std::size_t>(count, bytes_.size() - offset));
        for (uint32_t i = 0; i < count; ++i)
            values.push_back(read_value(offset, depth));
        return values;
    }

    EncodedAnnotation read_encoded_annotation(uint32_t &offset, int depth)
    {
        EncodedAnnotation a;
        a.type = type_at(read_uleb128(offset)).get();
        uint32_t count = read_uleb128(offset);
        a.elements.reserve(std::min<std::size_t>(count, (bytes_.size() - offset) / 2));
        for (uint32_t i = 0; i < count; ++i) {
            NamedValue element;
            element.name = string_at(read_uleb128(offset)).get();
            element.value = read_value(offset, depth);
            a.elements.push_back(std::move(element));
        }
        return a;
    }

    // ===== annotations =====

    AnnotationItem read_annotation_item(uint32_t offset)
    {
        if (offset >= bytes_.size())
            fail("annotation item is past the end of the file");
        uint8_t visibility = bytes_[offset++];
        if (visibility > 0x02)
            fail(std::format("bad annotation visibility {}", visibility));
        AnnotationItem item;
        item.visibility = static_cast<AnnotationVisibility>(visibility);
        item.annotation = read_encoded_annotation(offset, 0);
        return item;
    }

    std::vector<AnnotationItem> read_annotation_set(uint32_t offset)
    {
        std::vector<AnnotationItem> out;
        if (offset == 0)
            return out;
        raw::AnnotationSetItem set = check(raw::parser::parse_annotation_set(bytes_, offset));
        out.reserve(set.entries.size());
        for (uint32_t entry : set.entries)
            out.push_back(read_annotation_item(entry));
        return out;
    }

    // ===== classes =====

    ClassDef read_class(const raw::ClassDefItem &cd)
    {
        ClassDef c;
        c.type = type_at(cd.class_idx).get();
        where_ = c.type;
        c.access = static_cast<AccessFlags>(cd.access_flags);
        if (cd.superclass_idx != raw::NO_INDEX)
            c.superclass = type_at(cd.superclass_idx).get();
        if (cd.interfaces_off != 0) {
            raw::TypeList list = check(raw::parser::parse_type_list(bytes_, cd.interfaces_off));
            for (uint16_t t : list.type_ids)
                c.interfaces.push_back(type_at(t).get());
        }
        if (cd.source_file_idx != raw::NO_INDEX)
            c.source_file = string_at(cd.source_file_idx).get();

        // Annotations directory: class annotations here, member ones by index.
        std::map<uint32_t, uint32_t> field_annotations;
        std::map<uint32_t, uint32_t> method_annotations;
        std::map<uint32_t, uint32_t> parameter_annotations;
        if (cd.annotations_off != 0) {
            raw::AnnotationsDirectoryItem dir =
                check(raw::parser::parse_annotations_directory(bytes_, cd.annotations_off));
            c.annotations = read_annotation_set(dir.class_annotations_off);
            for (const auto &f : dir.field_annotations)
                field_annotations[f.field_idx] = f.annotations_off;
            for (const auto &m : dir.method_annotations)
                method_annotations[m.method_idx] = m.annotations_off;
            for (const auto &p : dir.parameter_annotations)
                parameter_annotations[p.method_idx] = p.annotations_off;
        }

        if (cd.class_data_off != 0) {
            raw::ClassDataItem data =
                check(raw::parser::parse_class_data(bytes_, cd.class_data_off));

            std::vector<Value> static_values;
            if (cd.static_values_off != 0) {
                uint32_t offset = cd.static_values_off;
                static_values = read_array(offset, 0);
            }
            if (static_values.size() > data.static_fields.size())
                fail("more static values than static fields");

            auto add_field = [&](const raw::EncodedField &ef) {
                const Shared<FieldId> &id = field_at(ef.field_idx);
                if (file_.field_ids()[ef.field_idx].class_idx != cd.class_idx)
                    fail(std::format("field {}.{} is listed in the class data of {}",
                                     id->class_descriptor, id->name, c.type));
                FieldDef f;
                f.name = id->name;
                f.type = id->type;
                f.access = static_cast<AccessFlags>(ef.access_flags);
                if (auto it = field_annotations.find(ef.field_idx); it != field_annotations.end()) {
                    f.annotations = read_annotation_set(it->second);
                    field_annotations.erase(it);
                }
                c.fields.push_back(std::move(f));
            };
            for (std::size_t i = 0; i < data.static_fields.size(); ++i) {
                add_field(data.static_fields[i]);
                if (i < static_values.size())
                    c.fields.back().initial_value = std::move(static_values[i]);
            }
            for (const raw::EncodedField &ef : data.instance_fields)
                add_field(ef);

            auto add_method = [&](const raw::EncodedMethod &em) {
                const Shared<MethodId> &id = method_at(em.method_idx);
                if (file_.method_ids()[em.method_idx].class_idx != cd.class_idx)
                    fail(std::format("method {}->{}{} is listed in the class data of {}",
                                     id->class_descriptor, id->name, id->proto, c.type));
                MethodDef m;
                m.name = id->name;
                m.proto = id->proto;
                m.access = static_cast<AccessFlags>(em.access_flags);
                where_ = std::format("{}->{}{}", c.type, m.name, m.proto);
                if (auto it = method_annotations.find(em.method_idx);
                    it != method_annotations.end()) {
                    m.annotations = read_annotation_set(it->second);
                    method_annotations.erase(it);
                }
                if (auto it = parameter_annotations.find(em.method_idx);
                    it != parameter_annotations.end()) {
                    raw::AnnotationSetRefList list =
                        check(raw::parser::parse_annotation_set_ref_list(bytes_, it->second));
                    for (uint32_t set : list.entries)
                        m.parameter_annotations.push_back(read_annotation_set(set));
                    parameter_annotations.erase(it);
                }
                if (em.code_off != 0)
                    m.code = read_code(em.code_off);
                where_ = c.type;
                c.methods.push_back(std::move(m));
            };
            for (const raw::EncodedMethod &em : data.direct_methods)
                add_method(em);
            for (const raw::EncodedMethod &em : data.virtual_methods)
                add_method(em);
        }
        else if (cd.static_values_off != 0) {
            fail("static values without static fields");
        }

        if (!field_annotations.empty() || !method_annotations.empty() ||
            !parameter_annotations.empty())
            fail("the annotations directory names a member the class does not define");
        return c;
    }

    // ===== code =====

    struct Payload
    {
        uint32_t start;
        uint32_t units;
    };

    Code read_code(uint32_t code_off);
    Insn convert(const raw::InsnFields &f, uint32_t pos, std::span<const uint16_t> insns,
                 const std::map<uint32_t, Label> &labels);
    std::vector<std::pair<uint32_t, Item>> read_debug_info(uint32_t debug_off, uint32_t code_size,
                                                           Code &code);

    std::span<const uint8_t> bytes_;
    const raw::DexFile &file_;
    const ReadOptions &options_;
    std::string where_;

    Cache<std::string> strings_;
    Cache<std::string> protos_;
    Cache<FieldId> fields_;
    Cache<MethodId> methods_;
    Cache<MethodHandle> method_handles_;
    Cache<CallSite> call_sites_;
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, Shared<LocalVariable>> locals_;
};

Code Reader::read_code(uint32_t code_off)
{
    raw::CodeItem item = check(raw::parser::parse_code_item(bytes_, code_off));
    std::span<const uint16_t> insns(item.insns);
    const uint32_t size = static_cast<uint32_t>(insns.size());

    // Pass 1: instruction boundaries.  Payloads are data inside the code, not
    // instructions; they are found where the walk meets their ident.
    std::vector<uint32_t> starts;
    std::vector<raw::InsnFields> decoded;
    std::map<uint32_t, uint32_t> payloads; // start -> size in code units
    for (uint32_t pos = 0; pos < size;) {
        if ((insns[pos] & 0xFF) == 0 && (insns[pos] >> 8) != 0) {
            auto units = raw::payload_units(insns, pos);
            if (!units || *units > size - pos)
                fail(std::format("bad payload at code offset {}", pos));
            if (pos % 2 != 0)
                fail(std::format("payload at odd code offset {}", pos));
            payloads[pos] = static_cast<uint32_t>(*units);
            pos += static_cast<uint32_t>(*units);
            continue;
        }
        auto f = raw::decode_insn(insns, pos);
        if (!f)
            fail(std::format("code offset {}: {}", pos, f.error().message));
        starts.push_back(pos);
        decoded.push_back(*f);
        pos += raw::opcode_info(f->opcode).units;
    }
    std::vector<bool> is_start(size + 1, false);
    for (uint32_t s : starts)
        is_start[s] = true;

    auto target_of = [&](uint32_t pos, int64_t offset, const char *what) {
        int64_t target = int64_t{pos} + offset;
        if (target < 0 || target >= size || !is_start[static_cast<uint32_t>(target)])
            fail(std::format("{} at code offset {} goes to {}, which is not an instruction", what,
                             pos, target));
        return static_cast<uint32_t>(target);
    };

    // Pass 2: every address something refers to gets a label.
    std::vector<uint32_t> targets;
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        const raw::InsnFields &f = decoded[i];
        const uint32_t pos = starts[i];
        switch (raw::opcode_info(f.opcode).format) {
        case raw::Format::F10t:
        case raw::Format::F20t:
        case raw::Format::F30t:
        case raw::Format::F21t:
        case raw::Format::F22t:
            targets.push_back(target_of(pos, f.offset, "branch"));
            break;
        case raw::Format::F31t: {
            int64_t at = int64_t{pos} + f.offset;
            uint16_t ident = f.opcode == 0x26   ? raw::FILL_ARRAY_DATA_PAYLOAD
                             : f.opcode == 0x2b ? raw::PACKED_SWITCH_PAYLOAD
                                                : raw::SPARSE_SWITCH_PAYLOAD;
            if (at < 0 || at >= size || !payloads.contains(static_cast<uint32_t>(at)) ||
                insns[static_cast<std::size_t>(at)] != ident)
                fail(std::format("instruction at code offset {} has no payload at {}", pos, at));
            if (f.opcode == 0x2b || f.opcode == 0x2c) {
                uint32_t p = static_cast<uint32_t>(at);
                uint32_t count = insns[p + 1];
                uint32_t first = f.opcode == 0x2b ? p + 4 : p + 2 + 2 * count;
                for (uint32_t k = 0; k < count; ++k) {
                    int32_t rel = static_cast<int32_t>(insns[first + 2 * k] |
                                                       (uint32_t{insns[first + 2 * k + 1]} << 16));
                    // A case that goes to the next instruction is dropped
                    // (see convert()), so it needs no label.
                    if (rel != 3)
                        targets.push_back(target_of(pos, rel, "switch case"));
                }
            }
            break;
        }
        default:
            break;
        }
    }
    struct TryOut
    {
        uint32_t start, end;
        const raw::EncodedCatchHandler *handler;
    };
    std::vector<TryOut> tries;
    std::unordered_map<uint32_t, std::size_t> handler_at; // byte offset -> handler
    for (std::size_t k = 0; k < item.handler_byte_offsets.size(); ++k)
        handler_at.emplace(item.handler_byte_offsets[k], k);
    for (const raw::TryItem &t : item.tries) {
        uint32_t end = t.start_addr + uint32_t{t.insn_count};
        if (t.start_addr >= size || end > size || t.insn_count == 0 || !is_start[t.start_addr] ||
            (!is_start[end] && end != size && !payloads.contains(end)))
            fail(std::format("try range at code offset {} does not cover whole instructions",
                             t.start_addr));
        auto h = handler_at.find(t.handler_off);
        if (h == handler_at.end())
            fail(std::format("try range at code offset {} has no handler at {}", t.start_addr,
                             t.handler_off));
        const raw::EncodedCatchHandler &handler = item.handlers[h->second];
        tries.push_back({t.start_addr, end, &handler});
        targets.push_back(t.start_addr);
        targets.push_back(end);
        for (const raw::EncodedTypePair &p : handler.handlers)
            targets.push_back(target_of(0, p.addr, "catch handler"));
        if (handler.catch_all_addr)
            targets.push_back(target_of(0, *handler.catch_all_addr, "catch-all handler"));
    }

    // Labels are numbered in code order, so a read is canonical.
    Code code;
    code.registers = item.registers_size;
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    std::map<uint32_t, Label> labels;
    for (uint32_t t : targets)
        labels.emplace(t, code.new_label());

    std::vector<std::pair<uint32_t, Item>> events;
    if (options_.debug_info && item.debug_info_off != 0)
        events = read_debug_info(item.debug_info_off, size, code);

    // Pass 3: the items.  A label or debug event belongs to the next
    // instruction at or after its address; the alignment nop in front of a
    // payload is padding, not an instruction.
    auto next_label = labels.begin();
    auto next_event = events.begin();
    auto emit_upto = [&](uint32_t address) {
        while (next_label != labels.end() && next_label->first <= address) {
            code.items.emplace_back(next_label->second);
            ++next_label;
        }
        while (next_event != events.end() && next_event->first <= address) {
            code.items.push_back(std::move(next_event->second));
            ++next_event;
        }
    };
    code.items.reserve(decoded.size() + labels.size() + events.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        const uint32_t pos = starts[i];
        const raw::InsnFields &f = decoded[i];
        if (f.opcode == 0x00 && payloads.contains(pos + 1))
            continue; // padding: the next instruction boundary takes its labels
        emit_upto(pos);
        code.items.emplace_back(convert(f, pos, insns, labels));
    }
    emit_upto(size);

    for (const TryOut &t : tries) {
        TryRange range;
        range.start = labels.at(t.start);
        range.end = labels.at(t.end);
        for (const raw::EncodedTypePair &p : t.handler->handlers)
            range.catches.push_back(Catch{type_at(p.type_idx).get(), labels.at(p.addr)});
        if (t.handler->catch_all_addr)
            range.catch_all = labels.at(*t.handler->catch_all_addr);
        code.tries.push_back(std::move(range));
    }
    return code;
}

std::vector<std::pair<uint32_t, Item>> Reader::read_debug_info(uint32_t debug_off,
                                                               uint32_t code_size, Code &code)
{
    raw::DebugInfoItem info = check(raw::parser::parse_debug_info(bytes_, debug_off));
    auto optional_string = [&](uint32_t idx) -> std::optional<std::string> {
        if (idx == raw::NO_INDEX)
            return std::nullopt;
        return string_at(idx).get();
    };
    auto optional_type = [&](uint32_t idx) -> std::optional<std::string> {
        if (idx == raw::NO_INDEX)
            return std::nullopt;
        return type_at(idx).get();
    };
    auto reg_of = [&](const raw::DebugOp &op) {
        if (op.reg > 0xFFFF)
            fail(std::format("debug info names register {}", op.reg));
        return static_cast<Reg>(op.reg);
    };

    for (uint32_t name : info.parameter_names)
        code.parameter_names.push_back(optional_string(name));

    std::vector<std::pair<uint32_t, Item>> events;
    uint64_t address = 0;
    uint32_t line = info.line_start;
    auto add = [&](Item item) {
        // Positions past the end of the code describe no instruction.
        if (address <= code_size)
            events.emplace_back(static_cast<uint32_t>(address), std::move(item));
    };
    for (const raw::DebugOp &op : info.ops) {
        switch (op.opcode) {
        case raw::DBG_ADVANCE_PC:
            address += op.addr_diff;
            break;
        case raw::DBG_ADVANCE_LINE:
            line += static_cast<uint32_t>(op.line_diff);
            break;
        case raw::DBG_START_LOCAL:
        case raw::DBG_START_LOCAL_EXTENDED: {
            auto key = std::make_tuple(op.name_idx, op.type_idx, op.sig_idx);
            auto it = locals_.find(key);
            if (it == locals_.end())
                it = locals_
                         .emplace(key, LocalVariable{optional_string(op.name_idx),
                                                     optional_type(op.type_idx),
                                                     optional_string(op.sig_idx)})
                         .first;
            add(LocalStart{reg_of(op), it->second});
            break;
        }
        case raw::DBG_END_LOCAL:
            add(LocalEnd{reg_of(op)});
            break;
        case raw::DBG_RESTART_LOCAL:
            add(LocalRestart{reg_of(op)});
            break;
        case raw::DBG_SET_PROLOGUE_END:
            add(PrologueEnd{});
            break;
        case raw::DBG_SET_EPILOGUE_BEGIN:
            add(EpilogueBegin{});
            break;
        case raw::DBG_SET_FILE:
            add(SetSourceFile{optional_string(op.name_idx)});
            break;
        default: {
            uint32_t adjusted = op.opcode - raw::DBG_FIRST_SPECIAL;
            line += static_cast<uint32_t>(-4 + static_cast<int32_t>(adjusted % 15));
            address += adjusted / 15;
            add(LineNumber{line});
            break;
        }
        }
    }
    return events;
}

Insn Reader::convert(const raw::InsnFields &f, uint32_t pos, std::span<const uint16_t> insns,
                     const std::map<uint32_t, Label> &labels)
{
    const uint8_t op = f.opcode;
    const Reg a = static_cast<Reg>(f.a);
    const Reg b = static_cast<Reg>(f.b);
    const Reg c = static_cast<Reg>(f.c);
    auto label = [&](int64_t offset) { return labels.at(static_cast<uint32_t>(pos + offset)); };
    auto args = [&] {
        const raw::Format fmt = raw::opcode_info(op).format;
        if (fmt == raw::Format::F3rc || fmt == raw::Format::F4rcc) {
            if (f.c + f.a > 0x10000)
                fail(std::format("register range at code offset {} runs past v65535", pos));
            return RegList::range(c, static_cast<uint16_t>(f.a));
        }
        return RegList(std::span<const Reg>(f.args.data(), f.a));
    };

    if (op == 0x00)
        return Nop{};
    if (op >= 0x01 && op <= 0x09)
        return Move{static_cast<ValueKind>((op - 0x01) / 3), a, b};
    if (op >= 0x0a && op <= 0x0c)
        return MoveResult{kind_at(op, 0x0a), a};
    if (op == 0x0d)
        return MoveException{a};
    if (op == 0x0e)
        return ReturnVoid{};
    if (op >= 0x0f && op <= 0x11)
        return Return{kind_at(op, 0x0f), a};
    switch (op) {
    case 0x12:
    case 0x13:
    case 0x14:
        return Const{a, static_cast<int32_t>(f.literal)};
    case 0x15:
        return Const{a, static_cast<int32_t>(static_cast<uint32_t>(f.literal & 0xFFFF) << 16)};
    case 0x16:
    case 0x17:
    case 0x18:
        return ConstWide{a, f.literal};
    case 0x19:
        return ConstWide{a, static_cast<int64_t>(static_cast<uint64_t>(f.literal & 0xFFFF) << 48)};
    case 0x1a:
    case 0x1b:
        return ConstString{a, string_at(f.index)};
    case 0x1c:
        return ConstClass{a, type_at(f.index)};
    case 0x1d:
        return MonitorEnter{a};
    case 0x1e:
        return MonitorExit{a};
    case 0x1f:
        return CheckCast{a, type_at(f.index)};
    case 0x20:
        return InstanceOf{a, b, type_at(f.index)};
    case 0x21:
        return ArrayLength{a, b};
    case 0x22:
        return NewInstance{a, type_at(f.index)};
    case 0x23:
        return NewArray{a, b, type_at(f.index)};
    case 0x24:
    case 0x25:
        return FilledNewArray{args(), type_at(f.index)};
    case 0x26: {
        uint32_t p = static_cast<uint32_t>(pos + f.offset);
        uint16_t width = insns[p + 1];
        uint64_t count = insns[p + 2] | (uint64_t{insns[p + 3]} << 16);
        FillArrayData fill{a, width, {}};
        uint64_t bytes = count * width;
        fill.data.reserve(static_cast<std::size_t>(bytes));
        for (uint64_t i = 0; i < bytes; ++i) {
            uint16_t unit = insns[p + 4 + static_cast<std::size_t>(i / 2)];
            fill.data.push_back(static_cast<uint8_t>(i % 2 == 0 ? unit & 0xFF : unit >> 8));
        }
        return fill;
    }
    case 0x27:
        return Throw{a};
    case 0x28:
    case 0x29:
    case 0x2a:
        return Goto{label(f.offset)};
    case 0x2b:
    case 0x2c: {
        uint32_t p = static_cast<uint32_t>(pos + f.offset);
        uint32_t count = insns[p + 1];
        auto s32 = [&](uint32_t at) {
            return static_cast<int32_t>(insns[at] | (uint32_t{insns[at + 1]} << 16));
        };
        // A case that goes to the next instruction does what no case does
        // (packed switches fill their gaps that way), so it is left out.
        Switch sw{a, {}};
        auto add_case = [&](int32_t key, int32_t rel) {
            if (rel != 3)
                sw.cases.push_back({key, label(rel)});
        };
        if (op == 0x2b) {
            int32_t first_key = s32(p + 2);
            if (count > 1 && first_key > INT32_MAX - static_cast<int32_t>(count - 1))
                fail(std::format("packed-switch keys at code offset {} overflow", pos));
            for (uint32_t k = 0; k < count; ++k)
                add_case(static_cast<int32_t>(first_key + static_cast<int32_t>(k)),
                         s32(p + 4 + 2 * k));
        }
        else {
            int64_t previous = INT64_MIN;
            for (uint32_t k = 0; k < count; ++k) {
                int32_t key = s32(p + 2 + 2 * k);
                if (key <= previous)
                    fail(std::format("sparse-switch keys at code offset {} are not increasing",
                                     pos));
                previous = key;
                add_case(key, s32(p + 2 + 2 * count + 2 * k));
            }
        }
        return sw;
    }
    case 0x2d:
    case 0x2e:
    case 0x2f:
    case 0x30:
    case 0x31:
        return Compare{static_cast<CompareOp>(op - 0x2d), a, b, c};
    default:
        break;
    }
    if (op >= 0x32 && op <= 0x37)
        return If{static_cast<Condition>(op - 0x32), a, b, label(f.offset)};
    if (op >= 0x38 && op <= 0x3d)
        return IfZero{static_cast<Condition>(op - 0x38), a, label(f.offset)};
    if (op >= 0x44 && op <= 0x4a)
        return ArrayGet{kind_at(op, 0x44), a, b, c};
    if (op >= 0x4b && op <= 0x51)
        return ArrayPut{kind_at(op, 0x4b), a, b, c};
    if (op >= 0x52 && op <= 0x58)
        return InstanceGet{kind_at(op, 0x52), a, b, field_at(f.index)};
    if (op >= 0x59 && op <= 0x5f)
        return InstancePut{kind_at(op, 0x59), a, b, field_at(f.index)};
    if (op >= 0x60 && op <= 0x66)
        return StaticGet{kind_at(op, 0x60), a, field_at(f.index)};
    if (op >= 0x67 && op <= 0x6d)
        return StaticPut{kind_at(op, 0x67), a, field_at(f.index)};
    if (op >= 0x6e && op <= 0x72)
        return Invoke{static_cast<Invoke::Kind>(op - 0x6e), args(), method_at(f.index)};
    if (op >= 0x74 && op <= 0x78)
        return Invoke{static_cast<Invoke::Kind>(op - 0x74), args(), method_at(f.index)};
    if (op >= 0x7b && op <= 0x8f)
        return Unary{static_cast<UnaryOp>(op - 0x7b), a, b};
    if (op >= 0x90 && op <= 0xaf)
        return Binary{static_cast<BinaryOp>(op - 0x90), a, b, c};
    if (op >= 0xb0 && op <= 0xcf)
        return Binary{static_cast<BinaryOp>(op - 0xb0), a, a, b};
    if (op >= 0xd0 && op <= 0xd7)
        return BinaryLiteral{static_cast<LiteralOp>(op - 0xd0), a, b,
                             static_cast<int16_t>(f.literal)};
    if (op >= 0xd8 && op <= 0xe2)
        return BinaryLiteral{static_cast<LiteralOp>(op - 0xd8), a, b,
                             static_cast<int16_t>(f.literal)};
    switch (op) {
    case 0xfa:
    case 0xfb:
        return InvokePolymorphic{args(), method_at(f.index), proto_at(f.proto)};
    case 0xfc:
    case 0xfd:
        return InvokeCustom{args(), call_site_at(f.index)};
    case 0xfe:
        return ConstMethodHandle{a, method_handle_at(f.index)};
    case 0xff:
        return ConstMethodType{a, proto_at(f.index)};
    default:
        fail(std::format("unexpected opcode 0x{:02x} at code offset {}", op, pos));
    }
}

// The version in the magic "dex\nNNN\0", or nullopt if the magic is wrong.
std::optional<uint32_t> version_of(std::span<const uint8_t> bytes)
{
    if (bytes.size() < 8 || bytes[0] != 'd' || bytes[1] != 'e' || bytes[2] != 'x' ||
        bytes[3] != '\n' || bytes[7] != 0)
        return std::nullopt;
    uint32_t version = 0;
    for (int i = 4; i < 7; ++i) {
        if (bytes[i] < '0' || bytes[i] > '9')
            return std::nullopt;
        version = version * 10 + (bytes[i] - '0');
    }
    return version;
}

} // namespace

std::expected<Dex, Error> read(std::span<const uint8_t> bytes, const ReadOptions &options)
{
    std::optional<uint32_t> version = version_of(bytes);
    if (!version)
        return std::unexpected(Error{Error::Kind::Malformed, "not a DEX file (bad magic)", {}});
    if (*version >= 41)
        return std::unexpected(
            Error{Error::Kind::Unsupported,
                  std::format("DEX version {:03} (containers) is not supported", *version),
                  {}});
    if (*version != 35 && *version != 37 && *version != 38 && *version != 39 && *version != 40)
        return std::unexpected(
            Error{Error::Kind::Malformed, std::format("unknown DEX version {:03}", *version), {}});
    auto file = raw::parser::parse_buffer(bytes, {.decode_strings = false});
    if (!file)
        return std::unexpected(Error{Error::Kind::Malformed, file.error().message, {}});
    if (file->header().endian_tag != raw::ENDIAN_CONSTANT)
        return std::unexpected(
            Error{Error::Kind::Unsupported, "big-endian DEX files are not supported", {}});
    try {
        return Reader(bytes, *file, options).run(*version);
    }
    catch (ReadFailure &failure) {
        return std::unexpected(std::move(failure.error));
    }
}

std::expected<Dex, Error> read_file(const std::string &path, const ReadOptions &options)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return std::unexpected(Error{Error::Kind::Io, std::format("cannot open {}", path), {}});
    std::vector<uint8_t> bytes;
    try {
        bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    catch (const std::ios_base::failure &) {
        in.setstate(std::ios::badbit);
    }
    if (in.bad())
        return std::unexpected(Error{Error::Kind::Io, std::format("cannot read {}", path), {}});
    return read(bytes, options);
}

} // namespace dexsplit::model

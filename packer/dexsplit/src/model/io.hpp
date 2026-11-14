#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "model/types.hpp"

namespace dexsplit::model {

/** One problem with a model, and where it is. */
struct Problem
{
    std::string where;   ///< e.g. "Lcom/a/B;->run()V, item 12"; empty for the whole file.
    std::string message; ///< What is wrong.
};

/** Why read() or write() failed. */
struct Error
{
    enum class Kind : uint8_t {
        Io,            ///< The file could not be read or written.
        Malformed,     ///< read(): the input is not a valid DEX file.
        Unsupported,   ///< read(): a DEX feature the model does not support (DEX 041 containers).
        Invalid,       ///< write(): the model breaks a rule of the format; see `problems`.
        TooLarge,      ///< write(): a pool has more entries than the format can index.
        VersionTooLow, ///< write(): the model uses a feature its version does not have.
    };
    Kind kind;
    std::string message;
    /** For Invalid: every problem validate() found. */
    std::vector<Problem> problems;
};

struct ReadOptions
{
    /** Read debug information (line numbers, local variables, parameter
     *  names) into the code; false leaves it out. */
    bool debug_info = true;
    /** If set, only classes whose descriptor it returns true for are read.
     *  The model holds every reference as an owned string, so it takes far
     *  more memory than the analysis layer: reading part of a large file
     *  helps when only part is needed. */
    std::function<bool(std::string_view type)> keep_class;
};

/** Read a whole DEX file into a model.  Reading is strict: a structure the
 *  model could not write back faithfully — an unused opcode, a branch into
 *  the middle of an instruction, a malformed string — is an error.  Rules the
 *  model *can* represent (names, access flags, ...) are not checked here;
 *  validate() and write() check those.
 *
 *  What is not kept: hidden-API flags (boot class path DEX files only) and
 *  the link section are dropped; debug positions past the end of the code
 *  are dropped; payloads no instruction refers to are dropped. */
[[nodiscard]] std::expected<Dex, Error> read(std::span<const uint8_t> bytes,
                                             const ReadOptions &options = {});
[[nodiscard]] std::expected<Dex, Error> read_file(const std::string &path,
                                                  const ReadOptions &options = {});

struct WriteOptions
{
    /** Write debug information; false strips it. */
    bool debug_info = true;
};

/** Write a model as a DEX file.  The model is checked first (validate(),
 *  then required_version()); nothing is written if it fails.  The output is
 *  deterministic: the same model always gives the same bytes.  Reading the
 *  output gives the same model up to normalization: classes ordered so
 *  supertypes come first, members and annotation elements sorted, labels
 *  renumbered in code order, switch cases that only fall through removed,
 *  overlapping try ranges flattened by combining their catches in range order
 *  until a catch-all, and neighbouring ranges with the same handlers joined.
 *  Writing that model again gives the same bytes. */
[[nodiscard]] std::expected<std::vector<uint8_t>, Error> write(const Dex &dex,
                                                               const WriteOptions &options = {});
[[nodiscard]] std::expected<void, Error> write_file(const Dex &dex, const std::string &path,
                                                    const WriteOptions &options = {});

/** Every rule of the format the model breaks.  Empty means write() can
 *  encode it.  The rules are those of ART's DEX file verifier that apply to
 *  the model — names and descriptors, access flags, member uniqueness,
 *  static values — plus what the encoding needs: registers that fit the
 *  instruction and the frame, labels placed exactly once, branch targets
 *  followed by an instruction.  It does not follow the control flow: rules
 *  that only apply to code that can run (a move-result after an invoke, a
 *  move-exception first in a handler, types flowing correctly) are ART's
 *  method verifier's, which checks them at runtime — apps ship dead code
 *  that breaks them. */
[[nodiscard]] std::vector<Problem> validate(const Dex &dex);

/** The lowest DEX version that has every feature @p dex uses: 37 for
 *  default and private interface methods, 38 for invoke-polymorphic,
 *  invoke-custom and method handle / method type values, 39 for
 *  const-method-handle and const-method-type.  Set `dex.version` to it to
 *  opt in; write() never raises the version by itself, because a higher
 *  version also makes ART stricter.
 *
 *  Names may contain space characters at any version, as ART accepts them
 *  (the format reserves them for 040, and Android 10 and older reject them). */
[[nodiscard]] uint32_t required_version(const Dex &dex);

/** How many entries each pool of the written file would have.  The format
 *  indexes types and prototypes with 16 bits (at most 65535 entries) and
 *  fields, methods, method handles and call sites with 16 bits (at most
 *  65536); use this to decide how to split classes across files. */
struct PoolStats
{
    std::size_t strings = 0;
    std::size_t types = 0;
    std::size_t protos = 0;
    std::size_t fields = 0;
    std::size_t methods = 0;
    std::size_t method_handles = 0;
    std::size_t call_sites = 0;
};
[[nodiscard]] PoolStats pool_stats(const Dex &dex);

/** Rename classes everywhere they are referenced.  @p rename gets each class
 *  descriptor ("Lcom/a/B;") and returns its new descriptor, or nullopt to
 *  keep it.  It is applied to every type reference: classes, supertypes,
 *  member ids, prototypes, array types, instructions, catch types,
 *  annotations and values, call sites, debug local types — and the class
 *  names inside generic signatures (dalvik.annotation.Signature, local
 *  variable signatures).
 *
 *  Not changed: class names inside string constants (e.g. for
 *  Class.forName), Kotlin metadata, and the simple name in an InnerClass
 *  annotation.  In a generic signature the inner-class suffix of
 *  `LOuter<...>.Inner;` is kept, so rename an inner class together with its
 *  outer class. */
void rename_types(Dex &dex,
                  const std::function<std::optional<std::string>(std::string_view)> &rename);

} // namespace dexsplit::model

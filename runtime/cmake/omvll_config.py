# O-MVLL obfuscation scheme for the RASP runtime. See https://obfuscator.re/o-mvll/
#
# The runtime build loads this file through cmake/omvll.cmake. It is the obfuscation POLICY: which
# O-MVLL passes run, and on which code.
#
# What this file is, and is not:
#   - It is safe to make public, because O-MVLL itself is public and a policy is not a secret.
#   - It is NOT where the secrecy comes from. That is the per-build seed (RASP_OMVLL_SEED), which is
#     generated fresh for each shipped build and is never committed. With a secret seed, two builds
#     of the same source differ, so a deobfuscator written against one build does not transfer.
#
# O-MVLL calls each method below per module and per function while clang compiles a translation unit,
# and applies whatever the method returns. A method that returns a disabling value (or is left out)
# turns that pass off for that function.
#
# How a function is selected for a pass. The heavy passes use omvll.ObfuscationConfig.default_config,
# O-MVLL's built-in policy helper. Given a module-exclude list, a function-exclude list, a function-
# INCLUDE list and a probability, it turns the pass ON unconditionally for any function whose name
# matches the include list, OFF for an excluded module or function, and otherwise ON with the given
# probability. So every name in the include lists below is obfuscated for certain; the probability only
# reaches the functions no list names.

import os
from functools import lru_cache

import omvll


# Translation units we never obfuscate, matched against the LLVM module name (the source path) as a
# substring. tf-psa-crypto used to be excluded here wholesale; it no longer is, because the decryption
# path runs through it (see CRYPTO_MODULE / CRYPTO_DECRYPTION_FUNCTIONS below). Anything else under a
# third_party/ path stays off-limits: it is not our code to transform.
THIRD_PARTY_MODULES = [
    "third_party",
]

# The functions worth the expensive passes (control-flow flattening, break-control-flow, indirect
# calls and branches, struct/variable access). These are the parts an attacker reads first to learn
# what the runtime checks, how it loads code, and how it turns the protected payload back into runnable
# code. Matched as a demangled-name substring, so a namespace prefix selects every function under it.
# rasp::android::payload:: is the ChaCha20-Poly1305 payload cipher and the dex store; rasp::android::
# loader:: is the on-demand loader that decrypts a class's dex the first time it is used.
SENSITIVE_FUNCTIONS = [
    "rasp::android::checks::",
    "rasp::ios::checks::",
    "rasp::checks::",
    "rasp::android::loader::",
    "rasp::android::payload::",
    "rasp::util::macho::",
    "observe_",
    "find_text",
    "code_signature",
    "integrity",
    "jailbreak",
    "anti_",
]

# The tf-psa-crypto translation units, by module-name substring. Its sources are extracted into the
# build tree under a path that contains "tf-psa-crypto"; our own sources never do, so this substring
# tells a crypto translation unit apart from ours.
CRYPTO_MODULE = "tf-psa-crypto"

# The only tf-psa-crypto functions we obfuscate: the ChaCha20-Poly1305 decryption path that the payload
# cipher calls through PSA. "chacha20_" / "poly1305_" / "chachapoly_" select the stream cipher, the MAC
# and the AEAD that joins them (both the mbedtls_* entry points and their file-local helpers). "psa_aead_"
# selects the PSA AEAD layer the call goes through: the public psa_aead_decrypt in core/psa_crypto.c and
# the mbedtls_psa_aead_* builtin wrappers in drivers/builtin. Everything else in tf-psa-crypto is left
# exactly as upstream ships it: it is third-party and timing-sensitive, and only the decryption path has
# to be as hard to read as our own decrypt code. Key management (psa_import_key, psa_crypto_init) is
# setup, not the decryption transform, so it is deliberately out of scope.
CRYPTO_DECRYPTION_FUNCTIONS = [
    "chacha20_",
    "poly1305_",
    "chachapoly_",
    "psa_aead_",
]

# The include list for every heavy pass: our sensitive code plus the tf-psa-crypto decryption functions.
# The two sets are disjoint by name (our C++ namespaces vs. the mbedtls_/psa_ C names), so one combined
# list selects the right functions in either kind of module.
HEAVY_FUNCTIONS = SENSITIVE_FUNCTIONS + CRYPTO_DECRYPTION_FUNCTIONS


class RaspConfig(omvll.ObfuscationConfig):
    # Global knobs, applied once. shuffle_functions reorders functions in the binary so their layout
    # carries no information. inline_jni_wrappers folds the small JNI entry wrappers into their callee
    # so the JNI boundary is not a clean seam to attach to (Android only; harmless elsewhere).
    omvll.config.global_mod_exclude = THIRD_PARTY_MODULES
    omvll.config.shuffle_functions = True
    omvll.config.inline_jni_wrappers = True

    def __init__(self):
        super().__init__()
        # The per-build seed. A shipped build sets RASP_OMVLL_SEED to a fresh random integer so every
        # build's probability-based passes make different choices and key their output differently. When
        # it is unset (an open-source default build, or a reproducibility check), O-MVLL keeps its own
        # fixed default and the build stays reproducible. The seed is a build input, never committed.
        seed = os.environ.get("RASP_OMVLL_SEED")
        if seed is not None:
            omvll.config.probability_seed = int(seed)

    def _in_crypto_module(self, mod: omvll.Module, func: omvll.Function) -> bool:
        # Whether this translation unit belongs to tf-psa-crypto rather than our own code. Decided with
        # O-MVLL's own module-name matcher: default_config skips (returns False) when the module matches
        # the exclude list, so an excluded CRYPTO_MODULE module gives False here, which this negates to
        # True. Everything else (no includes, probability 100) gives True, i.e. "not crypto".
        return not omvll.ObfuscationConfig.default_config(self, mod, func, [CRYPTO_MODULE], [], [], 100)

    def _cheap_passes_apply(self, mod: omvll.Module, func: omvll.Function) -> bool:
        # The cheap, always-on passes (strings, constants, arithmetic) run on all of our code. In
        # tf-psa-crypto they run only on the named decryption functions, so the rest of the third-party
        # library keeps the exact instructions upstream ships.
        if self._in_crypto_module(mod, func):
            return omvll.ObfuscationConfig.default_config(
                self, mod, func, [], [], CRYPTO_DECRYPTION_FUNCTIONS, 0)
        return True

    def _heavy_pass_on(self, mod: omvll.Module, func: omvll.Function, probability: int) -> bool:
        # A heavy pass is on for certain for any HEAVY_FUNCTIONS name (our sensitive code and the
        # decryption path), and on for our other code with `probability`. Inside tf-psa-crypto the
        # probability is forced to zero, so nothing but the named decryption functions is ever touched.
        reach = 0 if self._in_crypto_module(mod, func) else probability
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], HEAVY_FUNCTIONS, reach)

    # --- Applied to all of our code, and to the tf-psa-crypto decryption functions ---------------

    def obfuscate_string(self, mod: omvll.Module, func: omvll.Function, string: bytes):
        # Encrypt every string literal. This is what hides the probed paths, the hook/jailbreak
        # markers, and the signal names, so `strings` on the library lists none of them.
        if not self._cheap_passes_apply(mod, func):
            return omvll.StringEncOptSkip()
        return omvll.StringEncOptGlobal()

    def obfuscate_constants(self, mod: omvll.Module, func: omvll.Function):
        # Hide integer constants behind opaque computations: the P_TRACED bit, the EXC_MASK_* values,
        # the ELF and Mach-O magics, the thresholds, and the ChaCha20/Poly1305 round constants. A reader
        # can no longer grep the disassembly for a known constant to find a check or the cipher.
        if not self._cheap_passes_apply(mod, func):
            return omvll.OpaqueConstantsSkip()
        return omvll.OpaqueConstantsBool(True)

    def obfuscate_arithmetic(self, mod: omvll.Module, func: omvll.Function):
        # Rewrite arithmetic as mixed boolean-arithmetic. Two rounds is O-MVLL's middle setting: it
        # raises the cost of reading the logic without the size blow-up of deeper rounds.
        if not self._cheap_passes_apply(mod, func):
            return omvll.ArithmeticOpt(False)
        return omvll.ArithmeticOpt(2)

    # --- Applied to the sensitive functions and the decryption path only -------------------------

    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        # Control-flow flattening turns a function's branch structure into a dispatch loop, so the
        # original order of the checks and of the decryption steps is not visible. Expensive in size and
        # speed, so the heavy set only, at a moderate rate for anything outside the include list.
        return omvll.ControlFlowFlatteningOpt(self._heavy_pass_on(mod, func, 30))

    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        # Inserts junk the CPU skips but a disassembler does not, so a linear sweep misreads the code.
        return omvll.BreakControlFlowOpt(self._heavy_pass_on(mod, func, 10))

    def indirect_branch(self, mod: omvll.Module, func: omvll.Function):
        # Turns direct branches into table lookups, so the control-flow graph is not recoverable by
        # reading jump targets.
        return self._heavy_pass_on(mod, func, 20)

    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        # Turns direct calls into computed calls, so the call graph is hidden.
        return self._heavy_pass_on(mod, func, 20)

    def obfuscate_struct_access(self, mod: omvll.Module, func: omvll.Function, struct: omvll.Struct):
        # Hides which struct field is read (e.g. kp_proc.p_flag, the Mach-O header fields, the ChaCha20
        # context state).
        return omvll.StructAccessOpt(self._heavy_pass_on(mod, func, 20))

    def obfuscate_variable_access(self, mod: omvll.Module, func: omvll.Function,
                                  var: omvll.GlobalVariable):
        # Hides access to our global tables (the marker and path lists) so they are not a clean array
        # a reader can dump.
        return omvll.VarAccessOpt(self._heavy_pass_on(mod, func, 20))

    # --- Anti-hook: DECISION PENDING, see the plan (section "Anti-hook and the never-crash rule") --
    #
    # anti_hooking makes a function detect an inline hook on its own prologue. For a RASP it is high
    # value: it directly strengthens the hook checks. But O-MVLL's reaction to a detected hook must be
    # confirmed not to crash the app, because the runtime's first rule is never to crash the customer's
    # app. Until that is confirmed on a device, this stays OFF. Turn it on by returning:
    #
    #   def anti_hooking(self, mod, func):
    #       return omvll.AntiHookOpt(
    #           omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 0))


@lru_cache(maxsize=1)
def omvll_get_config() -> omvll.ObfuscationConfig:
    return RaspConfig()

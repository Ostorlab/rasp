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

import os
from functools import lru_cache

import omvll


# Translation units we never obfuscate. tf-psa-crypto is third-party and timing-sensitive: flattening
# or MBA-ing it risks both correctness and speed, and it is not our code to transform. O-MVLL matches
# these against the LLVM module name (the source path), as a substring.
THIRD_PARTY_MODULES = [
    "tf-psa-crypto",
    "third_party",
]

# Functions we never obfuscate, by demangled-name substring. The on-demand dex decryption runs on the
# app's startup path and must stay fast, so the hot AES/decrypt loop is excluded from the heavy passes.
# (String and constant encoding still apply to it; see obfuscate_string / obfuscate_constants, which
# do not consult this list.)
HOT_PATH_FUNCTIONS = [
    "decrypt_block",
    "aes_",
]

# The functions worth the expensive passes (control-flow flattening, break-control-flow, indirect
# calls and branches, struct/variable access). These are the parts an attacker reads first to learn
# what the runtime checks and how it loads code. Matched as a demangled-name substring, so a namespace
# prefix selects every function under it.
SENSITIVE_FUNCTIONS = [
    "rasp::android::checks::",
    "rasp::ios::checks::",
    "rasp::checks::",
    "rasp::loader::",
    "rasp::util::macho::",
    "observe_",
    "find_text",
    "code_signature",
    "integrity",
    "jailbreak",
    "anti_",
]


class RaspConfig(omvll.ObfuscationConfig):
    # Global knobs, applied once. shuffle_functions reorders functions in the binary so their layout
    # carries no information. inline_jni_wrappers folds the small JNI entry wrappers into their callee
    # so the JNI boundary is not a clean seam to attach to (Android only; harmless elsewhere).
    omvll.config.global_mod_exclude = THIRD_PARTY_MODULES
    omvll.config.global_func_exclude = HOT_PATH_FUNCTIONS
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

    # --- Applied to all of our code --------------------------------------------------------------

    def obfuscate_string(self, mod: omvll.Module, func: omvll.Function, string: bytes):
        # Encrypt every string literal. This is what hides the probed paths, the hook/jailbreak
        # markers, and the signal names, so `strings` on the library lists none of them.
        return omvll.StringEncOptGlobal()

    def obfuscate_constants(self, mod: omvll.Module, func: omvll.Function):
        # Hide integer constants behind opaque computations: the P_TRACED bit, the EXC_MASK_* values,
        # the ELF and Mach-O magics, the thresholds. A reader can no longer grep the disassembly for a
        # known constant to find a check.
        return omvll.OpaqueConstantsBool(True)

    def obfuscate_arithmetic(self, mod: omvll.Module, func: omvll.Function):
        # Rewrite arithmetic as mixed boolean-arithmetic. Two rounds is O-MVLL's middle setting: it
        # raises the cost of reading the logic without the size blow-up of deeper rounds.
        return omvll.ArithmeticOpt(2)

    # --- Applied to the sensitive functions only -------------------------------------------------

    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        # Control-flow flattening turns a function's branch structure into a dispatch loop, so the
        # original order of the checks is not visible. Expensive in size and speed, so sensitive
        # functions only, at a moderate rate.
        return omvll.ControlFlowFlatteningOpt(
            omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 30))

    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        # Inserts junk the CPU skips but a disassembler does not, so a linear sweep misreads the code.
        return omvll.BreakControlFlowOpt(
            omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 10))

    def indirect_branch(self, mod: omvll.Module, func: omvll.Function):
        # Turns direct branches into table lookups, so the control-flow graph is not recoverable by
        # reading jump targets.
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 20)

    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        # Turns direct calls into computed calls, so the call graph is hidden.
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 20)

    def obfuscate_struct_access(self, mod: omvll.Module, func: omvll.Function, struct: omvll.Struct):
        # Hides which struct field is read (e.g. kp_proc.p_flag, the Mach-O header fields).
        return omvll.StructAccessOpt(
            omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 20))

    def obfuscate_variable_access(self, mod: omvll.Module, func: omvll.Function,
                                  var: omvll.GlobalVariable):
        # Hides access to our global tables (the marker and path lists) so they are not a clean array
        # a reader can dump.
        return omvll.VarAccessOpt(
            omvll.ObfuscationConfig.default_config(self, mod, func, [], [], SENSITIVE_FUNCTIONS, 20))

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

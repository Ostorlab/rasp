# The O-MVLL obfuscation scheme of the Android runtime (https://obfuscator.re/o-mvll/): which passes run on which
# functions. Cheap passes run on all first-party code; heavy passes run on the sensitive functions and, by probability,
# elsewhere. The self-decrypt bootstrap (selfdecrypt.cpp/chacha20.cpp/kdf_shovel.cpp) is the only code the packer leaves
# in the clear while it encrypts the rest of the library at rest, so it gets every pass at probability 100 -- a static
# reverse-engineer who can read it must not be able to trace it to the decryptor or recover the key, and the opaque-
# constants pass on kdf_shovel.cpp buries the shovelled derivation bytes. The secret is the per-release seed,
# RASP_OMVLL_SEED, not this file.

import os
import re
from functools import lru_cache

import omvll


# Translation units never obfuscated, by module-name substring.
THIRD_PARTY_MODULES = [
    "third_party",
]

# The clear self-decrypt bootstrap translation units, by module-name substring; they get every pass at probability 100.
BOOTSTRAP_MODULES = [
    "selfdecrypt",
    "chacha20",
    "kdf_shovel",
]

# Our functions that always get the heavy passes, by demangled-name substring.
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

# The literals the runtime reads as constant data: the checks' signal names, the schedule's info strings and
# APK entry names, the probed paths and fields, and the config and text sections' names. Their bytes must
# stay readable in the built library, which the canary in .github/workflows/runtime.yml checks, because the
# local decryption the string pass emits only runs at the uses it rewrites, and which uses it rewrites
# differs by ABI and by optimization: a constant one ABI leaves alone another folds into a call argument
# and encrypts. The runtime still reads the same bytes through data pointers, so they must never be
# encrypted at all; the packer's encryption at rest hides them in the shipped library.
DATA_READ_LITERALS = re.compile(
    rb"(?:"
    rb"(?:root|dbg|hook|mitm|integ|id|emu)\.[a-z_]+"
    rb"|rasp\.v2\.[a-z_.]*"
    rb"|assets/rasp/(?:[a-z]+\.bin|r)"
    rb"|/(?:proc|sys)/.*"
    rb"|TracerPid:"
    rb"|\.init"
    rb"|\.text"
    rb")\Z"
)

# The tf-psa-crypto translation units, by module-name substring.
CRYPTO_MODULE = "tf-psa-crypto"

# The only tf-psa-crypto functions obfuscated: the ChaCha20-Poly1305 decryption path.
CRYPTO_DECRYPTION_FUNCTIONS = [
    "chacha20_",
    "poly1305_",
    "chachapoly_",
    "psa_aead_",
]

HEAVY_FUNCTIONS = SENSITIVE_FUNCTIONS + CRYPTO_DECRYPTION_FUNCTIONS


def _is_bootstrap(mod: omvll.Module) -> bool:
    """True when `mod` is one of the clear self-decrypt bootstrap translation units."""
    return any(entry in mod.name for entry in BOOTSTRAP_MODULES)


class RaspConfig(omvll.ObfuscationConfig):
    omvll.config.global_mod_exclude = THIRD_PARTY_MODULES
    omvll.config.shuffle_functions = True
    omvll.config.inline_jni_wrappers = True

    def __init__(self):
        super().__init__()
        seed = os.environ.get("RASP_OMVLL_SEED")
        if seed is not None:
            # The plugin's binding takes a 32-bit signed int, so the seed folds into one: any wider value would
            # overflow it and fail the build.
            omvll.config.probability_seed = int(seed) & 0x7FFFFFFF

    def _in_crypto_module(self, mod: omvll.Module, func: omvll.Function) -> bool:
        # default_config returns False for an excluded module.
        return not omvll.ObfuscationConfig.default_config(self, mod, func, [CRYPTO_MODULE], [], [], 100)

    def _cheap_passes_apply(self, mod: omvll.Module, func: omvll.Function) -> bool:
        if _is_bootstrap(mod):
            return True
        if self._in_crypto_module(mod, func):
            return omvll.ObfuscationConfig.default_config(
                self, mod, func, [], [], CRYPTO_DECRYPTION_FUNCTIONS, 0)
        return True

    def _heavy_pass_on(self, mod: omvll.Module, func: omvll.Function, probability: int) -> bool:
        if _is_bootstrap(mod):
            return True
        # default_config matches mangled names, which never contain `a::b::`.
        if any(entry in func.demangled_name for entry in SENSITIVE_FUNCTIONS):
            return True
        reach = 0 if self._in_crypto_module(mod, func) else probability
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], HEAVY_FUNCTIONS, reach)

    def obfuscate_string(self, mod: omvll.Module, func: omvll.Function, string: bytes):
        if not self._cheap_passes_apply(mod, func):
            return omvll.StringEncOptSkip()
        content = string if isinstance(string, bytes) else string.encode()
        if DATA_READ_LITERALS.match(content.rstrip(b"\x00")):
            return omvll.StringEncOptSkip()
        return omvll.StringEncOptLocal()

    def obfuscate_constants(self, mod: omvll.Module, func: omvll.Function):
        if not self._cheap_passes_apply(mod, func):
            return omvll.OpaqueConstantsSkip()
        return omvll.OpaqueConstantsBool(True)

    def obfuscate_arithmetic(self, mod: omvll.Module, func: omvll.Function):
        if not self._cheap_passes_apply(mod, func):
            return omvll.ArithmeticOpt(False)
        return omvll.ArithmeticOpt(2)

    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ControlFlowFlatteningOpt(self._heavy_pass_on(mod, func, 30))

    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        return omvll.BreakControlFlowOpt(self._heavy_pass_on(mod, func, 10))

    def indirect_branch(self, mod: omvll.Module, func: omvll.Function):
        return self._heavy_pass_on(mod, func, 20)

    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        return self._heavy_pass_on(mod, func, 20)

    def obfuscate_struct_access(self, mod: omvll.Module, func: omvll.Function, struct: omvll.Struct):
        return omvll.StructAccessOpt(self._heavy_pass_on(mod, func, 20))

    def obfuscate_variable_access(self, mod: omvll.Module, func: omvll.Function,
                                  var: omvll.GlobalVariable):
        return omvll.VarAccessOpt(self._heavy_pass_on(mod, func, 20))

    # anti_hooking stays off until it is confirmed on a device that it can't crash the app.


@lru_cache(maxsize=1)
def omvll_get_config() -> omvll.ObfuscationConfig:
    return RaspConfig()

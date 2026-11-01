# The O-MVLL obfuscation scheme for the self-decrypt bootstrap (https://obfuscator.re/o-mvll/): which passes run on which
# functions. The only code worth obfuscating is the clear bootstrap -- the translation units that stay unencrypted and
# must resist a static reverse-engineer who wants to trace them to the decryptor and recover the key. So every heavy pass
# runs, at probability 100, on all functions in selfdecrypt.cpp, chacha20.cpp and the generated kdf_shovel.cpp (whose
# opaque-constants pass buries the shovelled derivation bytes), and nothing runs anywhere else (the rest of the runtime is
# encrypted at rest, so obfuscating it would only cost build time). The secret is the per-release seed, RASP_OMVLL_SEED,
# not this file. The O-MVLL API names match the reference scheme on the feature/android-obfuscation branch.

import os
from functools import lru_cache

import omvll

# Bootstrap translation units, matched by module-name substring.
BOOTSTRAP_MODULES = ("selfdecrypt", "chacha20", "kdf_shovel")


def _is_bootstrap(mod: omvll.Module) -> bool:
    """True when `mod` is one of the clear bootstrap translation units."""
    return any(entry in mod.name for entry in BOOTSTRAP_MODULES)


class RaspConfig(omvll.ObfuscationConfig):
    omvll.config.shuffle_functions = True

    def __init__(self):
        super().__init__()
        seed = os.environ.get("RASP_OMVLL_SEED")
        if seed is not None:
            omvll.config.probability_seed = int(seed)

    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ControlFlowFlatteningOpt(_is_bootstrap(mod))

    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        return omvll.BreakControlFlowOpt(_is_bootstrap(mod))

    def indirect_branch(self, mod: omvll.Module, func: omvll.Function):
        return _is_bootstrap(mod)

    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        return _is_bootstrap(mod)

    def obfuscate_constants(self, mod: omvll.Module, func: omvll.Function):
        if _is_bootstrap(mod):
            return omvll.OpaqueConstantsBool(True)
        return omvll.OpaqueConstantsSkip()

    def obfuscate_arithmetic(self, mod: omvll.Module, func: omvll.Function):
        if _is_bootstrap(mod):
            return omvll.ArithmeticOpt(2)
        return omvll.ArithmeticOpt(False)

    def obfuscate_string(self, mod: omvll.Module, func: omvll.Function, string: bytes):
        if _is_bootstrap(mod):
            return omvll.StringEncOptLocal()
        return omvll.StringEncOptSkip()

    def obfuscate_struct_access(self, mod: omvll.Module, func: omvll.Function, struct: omvll.Struct):
        return omvll.StructAccessOpt(_is_bootstrap(mod))

    def obfuscate_variable_access(self, mod: omvll.Module, func: omvll.Function, var: omvll.GlobalVariable):
        return omvll.VarAccessOpt(_is_bootstrap(mod))


@lru_cache(maxsize=1)
def omvll_get_config() -> omvll.ObfuscationConfig:
    return RaspConfig()

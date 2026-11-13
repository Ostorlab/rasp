# The O-MVLL obfuscation scheme of the mobile runtime (https://obfuscator.re/o-mvll/): which passes run on which
# functions. Cheap passes run on all first-party code the plugin sees; heavy passes run on the sensitive functions
# and, by probability, elsewhere. The plugin only sees a target's own translation units; this parent's Android build
# does not apply it. On iOS it is on RaspRuntime alone, including that target's
# C++/Objective-C++ sources and directly compiled core host bridge. Linked static libraries (rasp_core, rasp_plugins,
# individual plugins and crypto) are compiled without the plugin (see runtime/ios/CMakeLists.txt).
# The bootstrap selectors below describe dormant historical integration, not shipped coverage or key secrecy.
# RASP_OMVLL_SEED is a diagnostic build input controlling part of the plugin's RNG behavior, not a cryptographic
# key. One seed does not establish reproducible binaries or resistance to extraction.

import os
import re
from functools import lru_cache

import omvll
import omvll_seed

# Translation units never obfuscated, by module-name substring.
THIRD_PARTY_MODULES = [
    "third_party",
]

# The clear self-decrypt bootstrap translation units, by module-name substring; they get every pass at probability 100.
# Historical Android integration only; these match no current iOS source or Android plugin compilation.
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
    "rasp::ios::util::",
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
# encrypted at all. This parent does not encrypt native Android libraries at rest. On iOS
# there is no at-rest layer, so these stay readable in the shipped framework --
# __rasp_config, the Mach-O lookup strings in util/macho.cpp, and the probe-source names and the artifact,
# marker, folder and root literals the iOS checks iterate over (jailbreak.cpp's kArtifactPaths, hooks.cpp's
# kFrameworkMarkers/kTweakFolders/kJailbreakRoots, mitm.cpp's kTunnelPrefixes, virtualizer.cpp's kSystemRoots
# and emulator.cpp's kSimulatorMachines) are the iOS entries here.
DATA_READ_LITERALS = re.compile(
    rb"(?:"
    rb"(?:root|dbg|hook|mitm|integ|id|emu)\.[a-z_]+"
    rb"|rasp\.v2\.[a-z_.]*"
    # iOS probe source names, stored in constexpr arrays and reported as the observation's source through
    # data pointers: debugger.cpp's kProbes and jailbreak.cpp's kPathSources.
    rb"|(?:access|stat|sysctl|getppid|task_get_exception_ports)"
    # iOS jailbreak artifact paths and the sandbox probe (jailbreak.cpp kArtifactPaths/kSandboxProbe), iterated
    # by observe_paths, plus hooks.cpp's tweak folders and rootless-jailbreak roots and virtualizer.cpp's system
    # roots -- all read as constant data through span/array iteration, so the string pass must never encrypt them.
    rb"|/Applications/(?:Cydia|Sileo|Zebra)\.app"
    rb"|/Library/MobileSubstrate/MobileSubstrate\.dylib"
    rb"|/usr/lib/(?:libhooker\.dylib|libsubstitute\.dylib|substrate|TweakInject)"
    rb"|/usr/sbin/sshd|/usr/bin/ssh|/bin/bash|/bin/sh|/etc/apt"
    rb"|/private/var/lib/(?:apt|cydia)|/private/var/stash"
    rb"|/var/jb(?:/usr/bin/sshd|/Library/MobileSubstrate/MobileSubstrate\.dylib)?"
    rb"|/var/checkra1n\.dmg|/jb"
    rb"|/private/\.rasp_sandbox_probe"
    rb"|/library/mobilesubstrate/dynamiclibraries/|/library/substitute/(?:dynamiclibraries|helpers)/"
    rb"|/usr/lib/(?:tweakinject|ellekit)/"
    rb"|/var/jb/|/private/var/jb/|/private/preboot/|/procursus/"
    rb"|/usr/lib/|/System/|/private/var/containers/Bundle/Application/|/Cryptexes/OS/System/"
    rb"|frida-agent|frida-gadget|fridagadget|libcycript|cydiasubstrate|mobilesubstrate|libsubstrate"
    rb"|substrateloader|substrateinserter|substratebootstrap|libsubstitute|libhooker|libblackjack"
    rb"|libellekit|tweakinject|tweakloader|sslkillswitch"
    rb"|getifaddrs|CFNetworkCopySystemProxySettings|trust_store|dyld"
    rb"|utun|ipsec|ppp|tun|tap"
    # emulator.cpp kSimulatorMachines, iterated by observe_machine_tell (std::ranges::any_of) through data
    # pointers: if encrypted, the emu.simulator probe stops detecting simulators on-device.
    rb"|x86_64|arm64|i386"
    rb"|assets/rasp/(?:[a-z]+\.bin|r)"
    rb"|/(?:proc|sys)/.*"
    # Provenance source identifiers and fixed arrays are consumed through data pointers.
    rb"|proc_maps_v1|dl_iterate_phdr_v1|application_classloader_v1|dyld_v1"
    rb"|none|platform|context_absent|native_unavailable|denied|io|malformed|input_limit|jni|cleanup|race|deadline"
    rb"|complete|unsupported|error|timeout|custom|path|dex|inmemory|delegate_last|runtime_named|boot_named"
    rb"|dalvik\.system\.(?:PathClassLoader|DexClassLoader|InMemoryDexClassLoader|DelegateLastClassLoader)"
    rb"|co\.ostorlab\.rasp\.GeneratingClassLoader|java\.lang\.BootClassLoader"
    rb"|TracerPid:"
    rb"|__rasp_config"
    rb"|__DATA"
    # Integrity's section and source names are also read through constexpr string_view data pointers.
    rb"|__text|file|memory|integ\.text_sha256"
    rb"|__TEXT"
    rb"|\.init"
    rb"|\.text"
    rb")\Z"
)

# The tf-psa-crypto translation units, by module-name substring.
CRYPTO_MODULE = "tf-psa-crypto"

# Dormant crypto selectors; linking crypto never compiles its target with this plugin.
CRYPTO_DECRYPTION_FUNCTIONS = [
    "chacha20_",
    "poly1305_",
    "chachapoly_",
    "psa_aead_",
]

HEAVY_FUNCTIONS = SENSITIVE_FUNCTIONS + CRYPTO_DECRYPTION_FUNCTIONS


def _is_bootstrap(mod: omvll.Module) -> bool:
    """True when `mod` is one of the clear self-decrypt bootstrap translation units (Android only)."""
    return any(entry in mod.name for entry in BOOTSTRAP_MODULES)


class RaspConfig(omvll.ObfuscationConfig):
    omvll.config.global_mod_exclude = THIRD_PARTY_MODULES
    omvll.config.shuffle_functions = True
    omvll.config.inline_jni_wrappers = True

    def __init__(self) -> None:
        super().__init__()
        policy = omvll_seed.parse_policy(
            os.environ.get("RASP_OMVLL_SEED"), os.environ.get("RASP_OMVLL_SEED_MODE")
        )
        omvll.config.probability_seed = policy.seed

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

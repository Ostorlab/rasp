/* A stand-in for the runtime's binary in the packer's tests: it reserves the space for the config as the runtime does
 * (runtime/core/src/embedded_config.cpp), in its own section, starting as `{}`. */

#ifdef __APPLE__
__attribute__((section("__DATA,__rasp_config"), used))
#else
__attribute__((section(".rasp_config"), used))
#endif
volatile char embedded_config[4096] = "{}";

const volatile char* config(void) { return embedded_config; }

cmake_minimum_required(VERSION 3.22.1)
project(rasp_core C)

add_library(rasp_core SHARED
    rasp_jni.c
    detectors.c
    signals.c
    sha256.c
    report.c
    weave.c
    guard.c
    literals.c
    strobf.c
    wbaes.c
    securestore.c
    integrity.c
)

target_compile_options(rasp_core PRIVATE -Wall -Wextra -Werror -O2 -fvisibility=hidden)
target_link_libraries(rasp_core log dl)

# Release artifacts expose only the JNI entry point and carry no local symbol table.
target_link_options(rasp_core PRIVATE "$<$<CONFIG:Release>:-Wl,--strip-all>")

# Also hide toolchain-generated globals (NDK r21 exports ELF boundary symbols otherwise).
target_link_options(rasp_core PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
set_property(TARGET rasp_core APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")

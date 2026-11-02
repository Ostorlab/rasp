# O-MVLL obfuscation of the self-decrypt bootstrap (opt-in; see cmake/omvll.cmake). The plugin is downloaded by pinned
# SHA, not committed.
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/omvll.cmake)

# The self-decrypt bootstrap. kdf_blob.c is NOT a library source: it is compiled separately by gen_kdf_shovel.py and only
# its machine code ships, shovelled as immediates by the generated kdf_shovel.cpp. The bootstrap decrypts the library's
# own .text/.rodata/.eh_frame, which the packer encrypts; it lives in the clear, page-isolated .stubcode section.
if(ANDROID_ABI STREQUAL "arm64-v8a")
  set(rasp_selfdecrypt_arch aarch64)
elseif(ANDROID_ABI STREQUAL "x86_64")
  set(rasp_selfdecrypt_arch x86_64)
else()
  message(FATAL_ERROR "the self-decrypt bootstrap supports arm64-v8a and x86_64, not ${ANDROID_ABI}")
endif()
string(REGEX REPLACE "^android-" "" rasp_android_api "${ANDROID_PLATFORM}")
get_filename_component(rasp_ndk_bin ${CMAKE_CXX_COMPILER} DIRECTORY)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(rasp_kdf_dir ${CMAKE_CURRENT_BINARY_DIR}/selfdecrypt)
set(rasp_kdf_cpp ${rasp_kdf_dir}/kdf_shovel.cpp)
set(rasp_kdf_header ${rasp_kdf_dir}/kdf_shovel.h)
add_custom_command(
  OUTPUT ${rasp_kdf_cpp} ${rasp_kdf_header}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_kdf_shovel.py
          --cc ${rasp_ndk_bin}/clang
          --target ${rasp_selfdecrypt_arch}-linux-android${rasp_android_api}
          --arch ${rasp_selfdecrypt_arch}
          --src ${CMAKE_CURRENT_SOURCE_DIR}/src/selfdecrypt/kdf_blob.c
          --out-dir ${rasp_kdf_dir}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/selfdecrypt/kdf_blob.c
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_kdf_shovel.py
  VERBATIM)
set_source_files_properties(${rasp_kdf_cpp} PROPERTIES GENERATED TRUE)

add_library(rasp SHARED
  src/entry.cpp
  src/monitoring.cpp
  src/apk/archive.cpp
  src/apk/location.cpp
  src/checks/debugger.cpp
  src/checks/emulator.cpp
  src/checks/hooks.cpp
  src/checks/identity.cpp
  src/checks/integrity.cpp
  src/checks/mitm.cpp
  src/checks/root.cpp
  src/loader/loader.cpp
  src/loader/loader_dex.cpp
  src/payload/cipher.cpp
  src/payload/dex_store.cpp
  src/selfdecrypt/selfdecrypt.cpp
  src/selfdecrypt/chacha20.cpp
  src/selfdecrypt/meta.cpp
  ${rasp_kdf_cpp}
  src/util/apk_file.cpp
  src/util/system_property.cpp)
target_include_directories(rasp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${rasp_kdf_dir})
target_link_libraries(rasp PRIVATE rasp_core rasp_plugins rasp_loader_dex rasp_tfpsacrypto rasp_warnings rasp_language
  rasp_shipped nativehelper)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)
target_link_options(rasp PRIVATE $<$<CONFIG:Release>:-Wl,--strip-all>)

# Page-isolate the clear bootstrap after .text (the packer activates it). The bootstrap runs before .rodata is decrypted,
# so -fno-jump-tables keeps its switches out of the encrypted .rodata; the entry is a global constructor.
target_link_options(rasp PRIVATE -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/src/selfdecrypt/sections.ld)
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)
set_source_files_properties(src/selfdecrypt/selfdecrypt.cpp
  PROPERTIES COMPILE_OPTIONS "-Wno-global-constructors;-fno-jump-tables")
set_source_files_properties(src/selfdecrypt/chacha20.cpp ${rasp_kdf_cpp}
  PROPERTIES COMPILE_OPTIONS "-fno-jump-tables")

# Obfuscate the bootstrap translation units (the scheme in cmake/omvll_config.py only touches
# selfdecrypt.cpp/chacha20.cpp/kdf_shovel.cpp; the rest is a no-op). Opt-in via RASP_OBFUSCATE.
rasp_obfuscate(rasp)

if(RASP_LOGGING)
  target_sources(rasp PRIVATE src/util/logging.cpp)
  target_link_libraries(rasp PRIVATE log)
endif()

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
  src/util/apk_file.cpp
  src/util/system_property.cpp)
target_include_directories(rasp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(rasp PRIVATE rasp_core rasp_plugins rasp_loader_dex rasp_tfpsacrypto rasp_warnings rasp_language
  rasp_shipped nativehelper)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)
target_link_options(rasp PRIVATE $<$<CONFIG:Release>:-Wl,--strip-all>)
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)

if(RASP_LOGGING)
  target_sources(rasp PRIVATE src/util/logging.cpp)
  target_link_libraries(rasp PRIVATE log)
endif()

include(${PROJECT_SOURCE_DIR}/cmake/omvll.cmake)
# rasp and rasp_core hold our own code. rasp_builtin and rasp_tfpsacrypto are the two tf-psa-crypto
# targets that compile the decryption path: rasp_builtin has the ChaCha20, Poly1305, ChaChaPoly and PSA
# AEAD builtin sources, rasp_tfpsacrypto has core/psa_crypto.c with the public psa_aead_decrypt. The
# omvll scheme obfuscates only the named decryption functions inside the two crypto targets.
foreach(rasp_first_party_target rasp rasp_core rasp_builtin rasp_tfpsacrypto)
  rasp_obfuscate(${rasp_first_party_target})
endforeach()

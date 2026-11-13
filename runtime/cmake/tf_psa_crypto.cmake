set(RASP_TF_PSA_CRYPTO_VERSION 1.1.1)
set(RASP_TF_PSA_CRYPTO_ARCHIVE
  ${CMAKE_CURRENT_LIST_DIR}/../third_party/tf-psa-crypto/tf-psa-crypto-${RASP_TF_PSA_CRYPTO_VERSION}-source.tar.xz)
set(RASP_TF_PSA_CRYPTO_SHA256 b1d193ddc13daa4fd6240bdb0fa5a8df2858e9a0128a12e2462e54d34d6c4508)
set(RASP_TF_PSA_CRYPTO_DIR ${CMAKE_BINARY_DIR}/tf-psa-crypto/tf-psa-crypto-${RASP_TF_PSA_CRYPTO_VERSION})

file(SHA256 ${RASP_TF_PSA_CRYPTO_ARCHIVE} _rasp_tf_psa_crypto_actual)
if(NOT _rasp_tf_psa_crypto_actual STREQUAL RASP_TF_PSA_CRYPTO_SHA256)
  message(FATAL_ERROR
    "vendored TF-PSA-Crypto ${RASP_TF_PSA_CRYPTO_ARCHIVE} has sha256 ${_rasp_tf_psa_crypto_actual}, "
    "expected ${RASP_TF_PSA_CRYPTO_SHA256}")
endif()

if(NOT EXISTS ${RASP_TF_PSA_CRYPTO_DIR}/CMakeLists.txt)
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tf-psa-crypto)
  file(ARCHIVE_EXTRACT INPUT ${RASP_TF_PSA_CRYPTO_ARCHIVE} DESTINATION ${CMAKE_BINARY_DIR}/tf-psa-crypto)
endif()

enable_language(C)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(TF_PSA_CRYPTO_TARGET_PREFIX rasp_)
set(TF_PSA_CRYPTO_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/../third_party/tf-psa-crypto/crypto_config.h
  CACHE FILEPATH "The TF-PSA-Crypto configuration of the runtime" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build TF-PSA-Crypto programs" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Build TF-PSA-Crypto tests" FORCE)
set(GEN_FILES OFF CACHE BOOL "Generate TF-PSA-Crypto's generated files" FORCE)
set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "Treat TF-PSA-Crypto's compiler warnings as errors" FORCE)
add_subdirectory(${RASP_TF_PSA_CRYPTO_DIR} ${CMAKE_BINARY_DIR}/tf-psa-crypto-build EXCLUDE_FROM_ALL SYSTEM)

# The reporting plugin owns a separate crypto island and must not inherit the runtime target namespace.
unset(TF_PSA_CRYPTO_TARGET_PREFIX)

add_library(rasp SHARED
  ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp
  src/local_policy_bridge.cpp
  src/builtin.cpp
  src/events/window_bridge.cpp
  src/events/window_events.cpp
  src/events/capture_bridge.cpp
  src/events/capture_events.cpp
  src/checks/capture.cpp
  src/checks/overlay.cpp
  src/entry.cpp
  src/monitoring.cpp
  src/apk/archive.cpp
  src/apk/location.cpp
  src/checks/debugger.cpp
  src/checks/emulator.cpp
  src/checks/hooks.cpp
  src/checks/module_provenance.cpp
  src/checks/module_provenance_io.c
  src/checks/loader_provenance.cpp
  src/checks/loader_provenance_jni.c
  src/checks/identity.cpp
  src/checks/integrity.cpp
  src/checks/mitm.cpp
  src/checks/context_exposure.cpp
  src/checks/root_namespace.cpp
  src/checks/root.cpp
  src/checks/service_exposure.cpp
  src/loader/loader.cpp
  src/loader/loader_dex.cpp
  src/payload/cipher.cpp
  src/payload/dex_store.cpp
  src/util/apk_file.cpp
  src/util/elf.cpp
  src/util/direct_syscall.cpp
  src/util/app_storage.cpp
  src/util/private_storage.cpp
  src/util/application_context.cpp
  src/util/package_manager.cpp
  src/util/package_identity.cpp
  src/util/signing_certificates.cpp
  src/util/jni.cpp
  src/util/service_components.cpp
  src/util/system_property.cpp)
target_include_directories(rasp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/posix/include ${PROJECT_SOURCE_DIR}/core/src)
target_link_libraries(rasp PRIVATE rasp_core rasp_plugins rasp_loader_dex rasp_tfpsacrypto rasp_warnings rasp_language
  rasp_shipped nativehelper)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)
target_link_options(rasp PRIVATE "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/policy_exports.map")
set_property(TARGET rasp APPEND PROPERTY LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/policy_exports.map)
target_link_options(rasp PRIVATE $<$<CONFIG:Release>:-Wl,--strip-all>)
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)

if(RASP_LOGGING)
  target_sources(rasp PRIVATE src/util/logging.cpp)
  target_link_libraries(rasp PRIVATE log)
endif()

include(${PROJECT_SOURCE_DIR}/cmake/capabilities.cmake)
rasp_capabilities(rasp android ${ANDROID_ABI} ${ANDROID_PLATFORM_LEVEL})

cmake_minimum_required(VERSION 4.4)
project(CaptureHost LANGUAGES OBJCXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS" OR NOT IS_DIRECTORY "${RASP_FRAMEWORK}")
  message(FATAL_ERROR "Supply an actual iOS toolchain and -DRASP_FRAMEWORK=/path/RaspRuntime.framework")
endif()
add_executable(CaptureHost MACOSX_BUNDLE main.mm)
target_compile_options(CaptureHost PRIVATE -fobjc-arc -Wall -Wextra -Werror -Wunguarded-availability)
target_include_directories(CaptureHost PRIVATE "${RASP_FRAMEWORK}/Headers")
target_link_libraries(CaptureHost PRIVATE "${RASP_FRAMEWORK}/RaspRuntime" "-framework UIKit" "-framework Foundation")
set_target_properties(CaptureHost PROPERTIES
  MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist"
  XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "12.0"
  XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
  XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "co.ostorlab.rasp.capturefixture"
  XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/Frameworks"
  XCODE_EMBED_FRAMEWORKS "${RASP_FRAMEWORK}"
  XCODE_EMBED_FRAMEWORKS_CODE_SIGN_ON_COPY YES)

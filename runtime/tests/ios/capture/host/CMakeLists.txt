cmake_minimum_required(VERSION 4.4)
project(CaptureHost LANGUAGES OBJCXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS" OR NOT IS_DIRECTORY "${RASP_FRAMEWORK}")
  message(FATAL_ERROR "Supply an actual iOS toolchain and -DRASP_FRAMEWORK=/path/RaspRuntime.framework")
endif()
add_executable(CaptureHost MACOSX_BUNDLE main.mm)
target_compile_options(CaptureHost PRIVATE -fobjc-arc -nostdinc++ -Wall -Wextra -Werror -Wunguarded-availability)
target_include_directories(CaptureHost PRIVATE "${RASP_FRAMEWORK}/Headers")
target_link_libraries(CaptureHost PRIVATE "${RASP_FRAMEWORK}/RaspRuntime" "-framework UIKit" "-framework Foundation")
set_target_properties(CaptureHost PROPERTIES
  MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist"
  XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "12.0"
  XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
  XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "co.ostorlab.rasp.capturefixture"
  BUILD_WITH_INSTALL_RPATH TRUE
  INSTALL_RPATH "@executable_path/Frameworks")
add_custom_command(TARGET CaptureHost POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_BUNDLE_DIR:CaptureHost>/Frameworks"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${RASP_FRAMEWORK}"
    "$<TARGET_BUNDLE_DIR:CaptureHost>/Frameworks/RaspRuntime.framework"
  VERBATIM)

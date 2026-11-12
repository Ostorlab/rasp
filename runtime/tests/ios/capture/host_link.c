/// Actual iOS SDK C/Objective-C/C++/Objective-C++ compile/link probe; never executed.
#include <RaspRuntime/ios_capture.h>

int main(void) {
  int32_t result = rasp_ios_capture_start(RASP_IOS_CAPTURE_SCREENSHOTS | RASP_IOS_CAPTURE_RECORDING);
  result += rasp_ios_capture_select_scene((void*)0);
  result += rasp_ios_capture_select_legacy_window((void*)0);
  result += rasp_ios_capture_clear_selection((void*)0);
  result += rasp_ios_capture_refresh();
  result += rasp_ios_capture_stop();
  return (int)result;
}

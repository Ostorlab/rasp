/// Public bounded Foundation lookup for opt-in hooks diagnostics.
#include "util/provenance_bundle.h"

#import <Foundation/Foundation.h>
#include <string>
#include <vector>
namespace rasp::ios::util {
provenance::Locations provenance_bundle() {
  @autoreleasepool {
    NSString* const path = [NSBundle mainBundle].bundlePath;
    if (path == nil || path.length == 0 || path.length > 4096) {
      return {};
    }
    std::vector<char> bytes(4097);
    if ([path getCString:bytes.data() maxLength:bytes.size() encoding:NSUTF8StringEncoding] == NO) {
      return {};
    }
    const provenance::Locations result{
        .apk_paths = {},
        .native_directory = {},
        .bundle_directory = std::string(bytes.data()),
        .available = true,
    };
    return provenance::valid_locations(result) ? result : provenance::Locations{};
  }
}
}  // namespace rasp::ios::util

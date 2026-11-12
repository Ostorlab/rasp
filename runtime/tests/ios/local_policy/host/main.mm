/// Harmless real UIKit host operation, gated immediately before its in-memory mutation.
#import <UIKit/UIKit.h>
#include <string.h>

#include "local_policy_host.h"

/// Explicit host expectation is compiled before packing, never learned from runtime info.
#ifndef POLICY_EXPECTED_SHA256
#define POLICY_EXPECTED_SHA256 "093f2b8093e5c12d1d1b8f14f1fa945b87a4a03d15d891b55af861da06d4124e"
#endif

/// Own only host UI and a harmless receipt count; never runtime C++ objects.
@interface PolicyHost : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow* window;
@property(nonatomic, strong) UILabel* statusLabel;
@property(nonatomic) NSUInteger receipts;
@end

@implementation PolicyHost
/// Initialize real application UI; policy queries never register capture observers.
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)options {
  static_cast<void>(application);
  static_cast<void>(options);
  self.window = [[UIWindow alloc] initWithFrame:CGRectMake(0, 0, 390, 844)];
  UIViewController* controller = [UIViewController new];
  controller.view.backgroundColor = UIColor.whiteColor;
  self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 110)];
  self.statusLabel.numberOfLines = 0;
  self.statusLabel.text = @"Demo receipts: 0. No device health or attestation claim.";
  [controller.view addSubview:self.statusLabel];
  UIButton* append = [UIButton buttonWithType:UIButtonTypeSystem];
  append.frame = CGRectMake(20, 210, 320, 50);
  [append setTitle:@"Append a demo receipt" forState:UIControlStateNormal];
  [append addTarget:self action:@selector(appendReceipt) forControlEvents:UIControlEventTouchUpInside];
  [controller.view addSubview:append];
  self.window.rootViewController = controller;
  [self.window makeKeyAndVisible];
  return YES;
}
/// The actual adapted operation returns before mutating receipts on every denial/error.
- (void)appendReceipt {
  struct RaspLocalGateRequestV1 request{};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  memcpy(request.operation, "append_demo_receipt", sizeof("append_demo_receipt"));
  memcpy(request.expected_policy_sha256, POLICY_EXPECTED_SHA256, 65);
  struct RaspLocalGateResultV1 decision{};
  const int32_t status = rasp_local_policy_gate_v1(&request, sizeof(request), &decision, sizeof(decision));
  if (status != RASP_LOCAL_OK || (decision.action != RASP_LOCAL_ALLOW && decision.action != RASP_LOCAL_REPORT)) {
    self.statusLabel.text =
        [NSString stringWithFormat:@"Denied/unavailable before append. Receipts: %lu; status %d; reason %u",
                                   static_cast<unsigned long>(self.receipts), status, decision.reason];
    return;
  }
  ++self.receipts;
  self.statusLabel.text =
      [NSString stringWithFormat:@"Receipts: %lu; %@", static_cast<unsigned long>(self.receipts),
                                 decision.action == RASP_LOCAL_REPORT ? @"explicit report-only branch, not enforced"
                                                                      : @"adapted local gate allowed"];
}
@end

/// Normal unsigned fixture application entry; no swizzle or automatic sensitive interception.
int main(int argc, char* argv[]) {
  @autoreleasepool {
    return UIApplicationMain(argc, argv, nil, NSStringFromClass(PolicyHost.class));
  }
}

/// Harmless host opt-in fixture; records status codes only, never screen content.
#import <UIKit/UIKit.h>

#include "ios_capture.h"

/// Buttons explicitly opt in and select only this controller's actual scene/window.
@interface CaptureViewController : UIViewController
@property(nonatomic, strong) UILabel* result;
@end
@implementation CaptureViewController
/// Builds the operator controls; runtime debug cycle output supplies primitive observations.
- (void)viewDidLoad {
  [super viewDidLoad];
  self.view.backgroundColor = UIColor.whiteColor;
  UIStackView* stack = [[UIStackView alloc] init];
  stack.axis = UILayoutConstraintAxisVertical;
  stack.spacing = 16;
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  NSArray<NSString*>* titles = @[
    @"Start screenshot only", @"Start capture state only", @"Start both", @"Select this scene/window",
    @"Clear this selection", @"Refresh", @"Stop", @"Open another scene"
  ];
  for (NSUInteger index = 0; index < titles.count; ++index) {
    UIButton* button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.tag = static_cast<NSInteger>(index);
    [button setTitle:titles[index] forState:UIControlStateNormal];
    [button addTarget:self action:@selector(action:) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:button];
  }
  self.result = [[UILabel alloc] init];
  self.result.numberOfLines = 0;
  self.result.text =
      @"Opt-in is off. No screen contents are collected. Use device screenshot/recording controls manually.";
  [stack addArrangedSubview:self.result];
  [self.view addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [stack.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:20],
    [stack.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-20],
    [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor]
  ]];
}
/// Calls only explicit host APIs, leaving screenshot/recording initiation to the operator.
- (void)action:(UIButton*)button {
  int32_t status = RASP_IOS_CAPTURE_OK;
  switch (button.tag) {
    case 0:
      status = rasp_ios_capture_start(RASP_IOS_CAPTURE_SCREENSHOTS);
      break;
    case 1:
      status = rasp_ios_capture_start(RASP_IOS_CAPTURE_RECORDING);
      break;
    case 2:
      status = rasp_ios_capture_start(RASP_IOS_CAPTURE_SCREENSHOTS | RASP_IOS_CAPTURE_RECORDING);
      break;
    case 3:
      if (__builtin_available(iOS 13.0, *)) {
        if (self.view.window.windowScene != nil) {
          status = rasp_ios_capture_select_scene((__bridge void*)self.view.window.windowScene);
          break;
        }
      }
      status = rasp_ios_capture_select_legacy_window((__bridge void*)self.view.window);
      break;
    case 4:
      if (__builtin_available(iOS 13.0, *)) {
        if (self.view.window.windowScene != nil) {
          status = rasp_ios_capture_clear_selection((__bridge void*)self.view.window.windowScene);
          break;
        }
      }
      status = rasp_ios_capture_clear_selection((__bridge void*)self.view.window);
      break;
    case 5:
      status = rasp_ios_capture_refresh();
      break;
    case 6:
      status = rasp_ios_capture_stop();
      break;
    case 7:
      if (__builtin_available(iOS 17.0, *)) {
        UISceneSessionActivationRequest* request =
            [UISceneSessionActivationRequest requestWithRole:UIWindowSceneSessionRoleApplication];
        [UIApplication.sharedApplication activateSceneSessionForRequest:request errorHandler:nil];
      } else if (__builtin_available(iOS 13.0, *)) {
        [UIApplication.sharedApplication requestSceneSessionActivation:nil
                                                          userActivity:nil
                                                               options:nil
                                                          errorHandler:nil];
      } else {
        status = RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE;
      }
      break;
    default:
      status = RASP_IOS_CAPTURE_INVALID_ARGUMENT;
      break;
  }
  self.result.text = [NSString stringWithFormat:@"Operation %ld returned %d. Check the development runtime's cycle "
                                                @"observations. No scene identifier or screen contents are recorded.",
                                                static_cast<long>(button.tag), status];
}
@end

/// Owns the app's actual scene window; the runtime retains only a weak selection.
API_AVAILABLE(ios(13.0))
@interface CaptureSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow* window;
@end
@implementation CaptureSceneDelegate
/// Creates a harmless window; selection remains an explicit operator action.
- (void)scene:(UIScene*)scene willConnectToSession:(UISceneSession*)session options:(UISceneConnectionOptions*)options {
  static_cast<void>(session);
  static_cast<void>(options);
  if (![scene isKindOfClass:UIWindowScene.class]) {
    return;
  }
  self.window = [[UIWindow alloc] initWithWindowScene:static_cast<UIWindowScene*>(scene)];
  self.window.rootViewController = [[CaptureViewController alloc] init];
  [self.window makeKeyAndVisible];
}
/// Explicit host teardown is safe even if another scene has since become selected.
- (void)sceneDidDisconnect:(UIScene*)scene {
  static_cast<void>(rasp_ios_capture_clear_selection((__bridge void*)scene));
  self.window = nil;
}
@end

/// Legacy iOS 12 application host; multi-scene hosts are created through the scene manifest.
@interface CaptureAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow* window;
@end
@implementation CaptureAppDelegate
/// Does not opt in automatically; controls demonstrate all three independent host selections.
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)options {
  static_cast<void>(application);
  static_cast<void>(options);
  if (__builtin_available(iOS 13.0, *)) {
    return YES;
  }
  self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
  self.window.rootViewController = [[CaptureViewController alloc] init];
  [self.window makeKeyAndVisible];
  return YES;
}
@end
/// Normal UIKit entry point; no capture session is created or screen content read by this fixture.
int main(int argc, char* argv[]) {
  @autoreleasepool {
    return UIApplicationMain(argc, argv, nil, NSStringFromClass(CaptureAppDelegate.class));
  }
}

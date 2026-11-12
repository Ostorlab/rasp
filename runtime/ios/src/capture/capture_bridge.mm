/// Explicit UIKit host opt-in; the detached worker receives only primitive state.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <array>
#include <cstdint>
#include <pthread.h>
#include <span>

#include "capture/capture_events.h"
#include "rasp/ios_capture.h"

using rasp::ios::capture::Availability;
using rasp::ios::capture::capture_events;
using rasp::ios::capture::SampleKind;
using rasp::ios::capture::Scope;

/// Main-thread-only owner of one weak selected object and fixed observer/cleanup slots.
__attribute__((visibility("hidden")))
@interface RaspCaptureCoordinator : NSObject {
 @public
  std::int64_t session_;
  std::int64_t generation_;
  std::int64_t selection_ordinal_;
  std::uint32_t options_;
  BOOL running_;
  BOOL scene_mode_;
  BOOL application_active_;
  BOOL infrastructure_ready_;
  BOOL selection_ready_;
  BOOL selection_present_;
  BOOL entry_in_progress_;
  __weak id selected_;
  __weak UIScreen* screen_;
  id trait_token_;
  id screen_token_;
  id screenshot_token_;
  std::array<id, 7> lifecycle_tokens_;
  NSTimer* timer_;
}
/// Installs only the shared application lifecycle/timer slots.
- (BOOL)install_process;
/// Installs the one independent screenshot subscription.
- (BOOL)install_screenshot;
/// Installs the selected trait/screen observer and confirms ownership before initial sampling.
- (int32_t)install_selected:(id)object modern:(BOOL)modern screen:(UIScreen*)screen;
/// Starts or safely repeats explicit opt-in.
- (int32_t)start:(uint32_t)options;
/// Selects a validated live UIKit object, invalidating prior ownership first.
- (int32_t)select:(id)object scene:(BOOL)scene;
/// Invalidates selection and removes only its exact owned tokens.
- (BOOL)clear_capture:(Availability)reason remove_lifecycle:(BOOL)remove_lifecycle;
/// Samples current UIKit state on main, without selecting a scene.
- (int32_t)refresh;
/// Samples current selected ownership after shared process activity has been checked.
- (int32_t)refresh_capture;
/// Samples only the current generation, reserving order before UIKit access.
- (void)sample:(SampleKind)kind;
/// Removes a notification token only on successful removal.
- (BOOL)remove_notification:(id __strong*)token;
/// Installs one lifecycle observer in a bounded fixed slot.
- (BOOL)observe:(NSNotificationName)name slot:(NSUInteger)slot scene:(BOOL)scene;
/// Applies lifecycle primitives before any invalidated sample can be drained.
- (void)lifecycle:(NSNotification*)notification scene:(BOOL)scene;
/// Stops all sources before cleanup; retains only inert failed cleanup slots.
- (int32_t)stop;
@end

@implementation RaspCaptureCoordinator
- (BOOL)remove_notification:(id __strong*)token {
  if (*token == nil) {
    return YES;
  }
  @try {
    [NSNotificationCenter.defaultCenter removeObserver:*token];
    *token = nil;
    return YES;
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    return NO;
  }
}
- (BOOL)observe:(NSNotificationName)name slot:(NSUInteger)slot scene:(BOOL)scene {
  if (slot >= 7 || std::span{lifecycle_tokens_}[slot] != nil) {
    return NO;
  }
  __weak RaspCaptureCoordinator* weak_self = self;
  const std::int64_t session = session_;
  const std::int64_t selection = selection_ordinal_;
  std::span{lifecycle_tokens_}[slot] = [NSNotificationCenter.defaultCenter
      addObserverForName:name
                  object:nil
                   queue:nil
              usingBlock:^(NSNotification* notification) {
                if (pthread_main_np() == 0) {
                  capture_events().reject(session, scene ? 1 : 0, 0, true);
                  if (!scene) {
                    capture_events().reject(session, 1, 0, true);
                  }
                  return;
                }
                RaspCaptureCoordinator* owner = weak_self;
                if (owner == nil || !owner->running_ || owner->session_ != session ||
                    (scene && owner->selection_ordinal_ != selection)) {
                  return;
                }
                @try {
                  [owner lifecycle:notification scene:scene];
                } @catch (NSException* exception) {
                  static_cast<void>(exception);
                  capture_events().failure(session, scene ? 1 : 0, Availability::kError);
                  if (!scene) {
                    capture_events().failure(session, 1, Availability::kError);
                  }
                }
              }];
  return std::span{lifecycle_tokens_}[slot] != nil;
}
- (BOOL)clear_capture:(Availability)reason remove_lifecycle:(BOOL)remove_lifecycle {
  capture_events().invalidate(session_, reason);
  generation_ = 0;
  BOOL clean = YES;
  if (trait_token_ != nil) {
    @try {
      if (__builtin_available(iOS 17.0, *)) {
        id owner = selected_;
        if (owner != nil && [owner isKindOfClass:UIWindowScene.class]) {
          [static_cast<UIWindowScene*>(owner) unregisterForTraitChanges:trait_token_];
        }
        trait_token_ = nil;
      } else {
        clean = NO;
      }
    } @catch (NSException* exception) {
      static_cast<void>(exception);
      clean = NO;
    }
  }
  if (![self remove_notification:&screen_token_]) {
    clean = NO;
  }
  if (remove_lifecycle) {
    for (NSUInteger index = 3; index < 7; ++index) {
      if (![self remove_notification:&std::span{lifecycle_tokens_}[index]]) {
        clean = NO;
      }
    }
  }
  screen_ = nil;
  if (!clean) {
    capture_events().failure(session_, 1, Availability::kTeardownError);
  }
  return clean;
}
- (BOOL)install_process {
  BOOL healthy = YES;
  @try {
    healthy = [self observe:UIApplicationDidBecomeActiveNotification slot:0 scene:NO];
    if (![self observe:UIApplicationWillResignActiveNotification slot:1 scene:NO]) {
      healthy = NO;
    }
    if (![self observe:UIApplicationDidEnterBackgroundNotification slot:2 scene:NO]) {
      healthy = NO;
    }
    __weak RaspCaptureCoordinator* weak_self = self;
    const std::int64_t session = session_;
    timer_ = [NSTimer timerWithTimeInterval:5.0
                                    repeats:YES
                                      block:^(NSTimer* timer) {
                                        static_cast<void>(timer);
                                        if (pthread_main_np() == 0) {
                                          capture_events().reject(session, 0, 0, true);
                                          capture_events().reject(session, 1, 0, true);
                                          return;
                                        }
                                        RaspCaptureCoordinator* owner = weak_self;
                                        if (owner == nil || owner->session_ != session || !owner->running_) {
                                          return;
                                        }
                                        @try {
                                          static_cast<void>([owner refresh]);
                                        } @catch (NSException* exception) {
                                          static_cast<void>(exception);
                                          capture_events().failure(session, 0, Availability::kError);
                                          capture_events().failure(session, 1, Availability::kError);
                                        }
                                      }];
    if (timer_ == nil) {
      healthy = NO;
    } else {
      [NSRunLoop.mainRunLoop addTimer:timer_ forMode:NSRunLoopCommonModes];
    }
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    healthy = NO;
  }
  return healthy;
}
- (BOOL)install_screenshot {
  const std::int64_t session = session_;
  @try {
    screenshot_token_ =
        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationUserDidTakeScreenshotNotification
                                                        object:nil
                                                         queue:nil
                                                    usingBlock:^(NSNotification* notification) {
                                                      static_cast<void>(notification);
                                                      capture_events().screenshot(session);
                                                    }];
    return screenshot_token_ != nil;
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    return NO;
  }
}
- (int32_t)start:(uint32_t)options {
  if (running_) {
    return options_ == options ? RASP_IOS_CAPTURE_NO_CHANGE : RASP_IOS_CAPTURE_OPTIONS_CONFLICT;
  }
  const int32_t cleanup = [self stop];
  if (cleanup == RASP_IOS_CAPTURE_CLEANUP_ERROR) {
    return cleanup;
  }
  session_ = capture_events().start((options & RASP_IOS_CAPTURE_SCREENSHOTS) != 0,
                                    (options & RASP_IOS_CAPTURE_RECORDING) != 0);
  if (session_ <= 0) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  options_ = options;
  running_ = YES;
  application_active_ = UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
  const BOOL healthy = [self install_process];
  infrastructure_ready_ = healthy;
  if (!healthy) {
    capture_events().failure(session_, 0, Availability::kRegistrationError);
    capture_events().failure(session_, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if ((options_ & RASP_IOS_CAPTURE_SCREENSHOTS) != 0 && ![self install_screenshot]) {
    capture_events().failure(session_, 0, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (screenshot_token_ != nil) {
    capture_events().screenshot_ready(session_, application_active_);
  }
  return RASP_IOS_CAPTURE_OK;
}
- (int32_t)select:(id)object scene:(BOOL)scene {
  if (!running_) {
    return RASP_IOS_CAPTURE_NOT_STARTED;
  }
  if ((options_ & RASP_IOS_CAPTURE_RECORDING) == 0) {
    return RASP_IOS_CAPTURE_NOT_REQUESTED;
  }
  if (!infrastructure_ready_) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (selection_present_ && selected_ == object && scene_mode_ == scene) {
    return RASP_IOS_CAPTURE_NO_CHANGE;
  }
  if (![self clear_capture:Availability::kNoSelection remove_lifecycle:YES]) {
    return RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  selected_ = nil;
  if (selection_ordinal_ == INT64_MAX) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  ++selection_ordinal_;
  selected_ = object;
  selection_present_ = YES;
  scene_mode_ = scene;
  selection_ready_ = NO;
  BOOL healthy = YES;
  if (scene) {
    if (__builtin_available(iOS 13.0, *)) {
      healthy = [self observe:UISceneDidActivateNotification slot:3 scene:YES];
      if (![self observe:UISceneWillDeactivateNotification slot:4 scene:YES]) {
        healthy = NO;
      }
      if (![self observe:UISceneDidEnterBackgroundNotification slot:5 scene:YES]) {
        healthy = NO;
      }
      if (![self observe:UISceneDidDisconnectNotification slot:6 scene:YES]) {
        healthy = NO;
      }
    } else {
      return RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE;
    }
  }
  if (!healthy) {
    capture_events().failure(session_, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  selection_ready_ = YES;
  return [self refresh];
}
- (void)sample:(SampleKind)kind {
  const std::int64_t generation = generation_;
  const std::int64_t serial = capture_events().ticket(session_, generation);
  if (serial <= 0) {
    return;
  }
  id object = selected_;
  if (object == nil) {
    static_cast<void>([self clear_capture:Availability::kOwnerGone remove_lifecycle:YES]);
    selection_present_ = NO;
    return;
  }
  int state = -1;
  if (scene_mode_) {
    if (__builtin_available(iOS 17.0, *)) {
      const UISceneCaptureState actual = static_cast<UIWindowScene*>(object).traitCollection.sceneCaptureState;
      switch (actual) {
        case UISceneCaptureStateInactive:
          state = 0;
          break;
        case UISceneCaptureStateActive:
          state = 1;
          break;
        case UISceneCaptureStateUnspecified:
          state = 2;
          break;
        default:
          break;
      }
    } else {
      UIScreen* screen = screen_;
      if (screen != nil) {
        state = screen.isCaptured ? 1 : 0;
      }
    }
  } else {
    if (__builtin_available(iOS 17.0, *)) {
      return;
    } else {
      UIScreen* screen = screen_;
      if (screen != nil) {
        state = screen.isCaptured ? 1 : 0;
      }
    }
  }
  capture_events().sample(session_, generation, serial, kind, state);
}
- (int32_t)refresh {
  if (!running_) {
    return RASP_IOS_CAPTURE_NOT_STARTED;
  }
  if (!infrastructure_ready_) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
    application_active_ = NO;
  }
  if (screenshot_token_ != nil && timer_ != nil) {
    capture_events().screenshot_ready(session_, application_active_);
  }
  @try {
    return [self refresh_capture];
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    capture_events().failure(session_, 1, Availability::kError);
    return RASP_IOS_CAPTURE_UNAVAILABLE;
  }
}
- (int32_t)refresh_capture {
  if ((options_ & RASP_IOS_CAPTURE_RECORDING) == 0) {
    return RASP_IOS_CAPTURE_OK;
  }
  if (!selection_present_) {
    return RASP_IOS_CAPTURE_OK;
  }
  id object = selected_;
  if (object == nil) {
    static_cast<void>([self clear_capture:Availability::kOwnerGone remove_lifecycle:YES]);
    selection_present_ = NO;
    return RASP_IOS_CAPTURE_OK;
  }
  if (!selection_ready_) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  BOOL eligible = application_active_;
  UIScreen* screen = nil;
  BOOL modern = NO;
  if (scene_mode_) {
    if (__builtin_available(iOS 13.0, *)) {
      UIWindowScene* scene = static_cast<UIWindowScene*>(object);
      eligible = scene.activationState == UISceneActivationStateForegroundActive;
      if (__builtin_available(iOS 17.0, *)) {
        modern = YES;
      } else {
        screen = scene.screen;
      }
    }
  } else {
    UIWindow* window = static_cast<UIWindow*>(object);
    eligible = eligible && !window.hidden;
    screen = window.screen;
  }
  if (!eligible) {
    return [self clear_capture:Availability::kInactive remove_lifecycle:NO] ? RASP_IOS_CAPTURE_OK
                                                                            : RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  if (generation_ > 0 && (modern || screen_ == screen)) {
    [self sample:SampleKind::kResample];
    return RASP_IOS_CAPTURE_OK;
  }
  if (![self clear_capture:Availability::kUnavailableState remove_lifecycle:NO]) {
    return RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  if (!modern && screen == nil) {
    capture_events().failure(session_, 1, Availability::kError);
    return RASP_IOS_CAPTURE_UNAVAILABLE;
  }
  return [self install_selected:object modern:modern screen:screen];
}
- (int32_t)install_selected:(id)object modern:(BOOL)modern screen:(UIScreen*)screen {
  generation_ = capture_events().open(session_, modern ? Scope::kScene : Scope::kScreen);
  if (generation_ <= 0) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  __weak RaspCaptureCoordinator* weak_self = self;
  const std::int64_t session = session_;
  const std::int64_t generation = generation_;
  @try {
    if (modern) {
      if (__builtin_available(iOS 17.0, *)) {
        trait_token_ = [static_cast<UIWindowScene*>(object)
            registerForTraitChanges:@[ UITraitSceneCaptureState.class ]
                        withHandler:^(id<UITraitEnvironment> environment, UITraitCollection* previous) {
                          static_cast<void>(environment);
                          static_cast<void>(previous);
                          if (pthread_main_np() == 0) {
                            capture_events().reject(session, 1, generation, true);
                            return;
                          }
                          RaspCaptureCoordinator* owner = weak_self;
                          if (owner == nil || !owner->running_ || owner->session_ != session ||
                              owner->generation_ != generation) {
                            capture_events().reject(session, 1, generation, false);
                            return;
                          }
                          @try {
                            [owner sample:SampleKind::kCallback];
                          } @catch (NSException* exception) {
                            static_cast<void>(exception);
                            capture_events().failure(session, 1, Availability::kError);
                          }
                        }];
      }
    } else {
      screen_ = screen;
      screen_token_ = [NSNotificationCenter.defaultCenter
          addObserverForName:UIScreenCapturedDidChangeNotification
                      object:nil
                       queue:nil
                  usingBlock:^(NSNotification* notification) {
                    if (pthread_main_np() == 0) {
                      capture_events().reject(session, 1, generation, true);
                      return;
                    }
                    RaspCaptureCoordinator* owner = weak_self;
                    if (owner == nil || !owner->running_ || owner->session_ != session ||
                        owner->generation_ != generation) {
                      capture_events().reject(session, 1, generation, false);
                      return;
                    }
                    if (notification.object != owner->screen_) {
                      return;
                    }
                    @try {
                      [owner sample:SampleKind::kCallback];
                    } @catch (NSException* exception) {
                      static_cast<void>(exception);
                      capture_events().failure(session, 1, Availability::kError);
                    }
                  }];
    }
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    capture_events().failure(session_, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if ((modern && trait_token_ == nil) || (!modern && screen_token_ == nil)) {
    capture_events().failure(session_, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  capture_events().registered(session_, generation_);
  [self sample:SampleKind::kInitial];
  return RASP_IOS_CAPTURE_OK;
}
- (void)lifecycle:(NSNotification*)notification scene:(BOOL)scene {
  if (scene) {
    if (notification.object != selected_) {
      return;
    }
    if (__builtin_available(iOS 13.0, *)) {
      if ([notification.name isEqualToString:UISceneDidDisconnectNotification]) {
        const BOOL clean = [self clear_capture:Availability::kDisconnected remove_lifecycle:YES];
        selection_present_ = NO;
        if (clean) {
          selected_ = nil;
        }
        return;
      }
      if (![notification.name isEqualToString:UISceneDidActivateNotification]) {
        static_cast<void>([self clear_capture:Availability::kInactive remove_lifecycle:NO]);
        return;
      }
    }
  } else {
    application_active_ = [notification.name isEqualToString:UIApplicationDidBecomeActiveNotification];
    if (!application_active_) {
      if (screenshot_token_ != nil) {
        capture_events().screenshot_ready(session_, false);
      }
      if (!scene_mode_) {
        static_cast<void>([self clear_capture:Availability::kInactive remove_lifecycle:NO]);
      }
      return;
    }
  }
  static_cast<void>([self refresh]);
}
- (int32_t)stop {
  const BOOL was_running = running_;
  capture_events().stop(session_);
  running_ = NO;
  infrastructure_ready_ = NO;
  BOOL clean = [self clear_capture:Availability::kDeactivated remove_lifecycle:YES];
  for (NSUInteger index = 0; index < 3; ++index) {
    if (![self remove_notification:&std::span{lifecycle_tokens_}[index]]) {
      clean = NO;
    }
  }
  if (![self remove_notification:&screenshot_token_]) {
    clean = NO;
  }
  @try {
    [timer_ invalidate];
    timer_ = nil;
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    clean = NO;
  }
  selection_present_ = NO;
  if (clean) {
    selected_ = nil;
    options_ = 0;
    capture_events().cleanup_complete(session_);
  } else {
    capture_events().failure(session_, 0, Availability::kTeardownError);
    capture_events().failure(session_, 1, Availability::kTeardownError);
  }
  if (!clean) {
    return RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  return was_running ? RASP_IOS_CAPTURE_OK : RASP_IOS_CAPTURE_NO_CHANGE;
}
@end

namespace {
/// Process lifetime retained coordinator; access and ARC bridging only on main.
[[nodiscard]] void*& coordinator_storage() {
  static void* storage = nullptr;
  return storage;
}
/// Obtains the main-thread owner only after an explicit start.
[[nodiscard]] RaspCaptureCoordinator* coordinator(bool create) {
  if (coordinator_storage() == nullptr && create) {
    RaspCaptureCoordinator* owner = [[RaspCaptureCoordinator alloc] init];
    coordinator_storage() = (__bridge_retained void*)owner;
  }
  return (__bridge RaspCaptureCoordinator*)coordinator_storage();
}
/// Enforces thread/target before any UIKit or weak ownership access.
[[nodiscard]] int32_t entry_status() {
  if (pthread_main_np() == 0) {
    return RASP_IOS_CAPTURE_WRONG_THREAD;
  }
  return rasp::ios::capture::capture_platform() == rasp::ios::capture::Platform::kUnsupported
             ? RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE
             : RASP_IOS_CAPTURE_OK;
}
/// Contains Foundation failures within this adapter TU, without C++ exception support.
/// Explicit success/catch guard cleanup avoids ObjC++ @finally's C++ termination path.
[[nodiscard]] int32_t perform(bool create, uint32_t affected, int32_t (^operation)(RaspCaptureCoordinator*)) {
  const int32_t status = entry_status();
  if (status != RASP_IOS_CAPTURE_OK) {
    return status;
  }
  @autoreleasepool {
    RaspCaptureCoordinator* owner = nil;
    @try {
      owner = coordinator(create);
      if (owner == nil) {
        return create ? RASP_IOS_CAPTURE_UNAVAILABLE : RASP_IOS_CAPTURE_NOT_STARTED;
      }
      if (owner->entry_in_progress_) {
        return RASP_IOS_CAPTURE_UNAVAILABLE;
      }
      owner->entry_in_progress_ = YES;
      const int32_t result = operation(owner);
      owner->entry_in_progress_ = NO;
      return result;
    } @catch (NSException* exception) {
      static_cast<void>(exception);
      if (owner != nil) {
        owner->entry_in_progress_ = NO;
        if ((affected & RASP_IOS_CAPTURE_SCREENSHOTS) != 0) {
          capture_events().failure(owner->session_, 0, Availability::kError);
        }
        if ((affected & RASP_IOS_CAPTURE_RECORDING) != 0) {
          capture_events().failure(owner->session_, 1, Availability::kError);
        }
      }
      return RASP_IOS_CAPTURE_UNAVAILABLE;
    }
  }
}
}  // namespace
int32_t rasp_ios_capture_start(uint32_t options) {
  return perform(true, UINT32_C(3), ^int32_t(RaspCaptureCoordinator* owner) {
    if (options == 0 || (options & ~UINT32_C(3)) != 0) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    return [owner start:options];
  });
}
int32_t rasp_ios_capture_select_scene(void* window_scene) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (window_scene == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    if (__builtin_available(iOS 13.0, *)) {
      id object = (__bridge id)window_scene;
      if (![object isKindOfClass:UIWindowScene.class]) {
        return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
      }
      return [owner select:object scene:YES];
    }
    return RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE;
  });
}
int32_t rasp_ios_capture_select_legacy_window(void* window) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (window == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    id object = (__bridge id)window;
    if (![object isKindOfClass:UIWindow.class]) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    if (__builtin_available(iOS 17.0, *)) {
      return RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE;
    }
    if (__builtin_available(iOS 13.0, *)) {
      if (static_cast<UIWindow*>(object).windowScene != nil) {
        return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
      }
    }
    return [owner select:object scene:NO];
  });
}
int32_t rasp_ios_capture_clear_selection(void* selected_object) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (selected_object == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    if (!owner->running_) {
      return RASP_IOS_CAPTURE_NOT_STARTED;
    }
    if (owner->selected_ != (__bridge id)selected_object) {
      return RASP_IOS_CAPTURE_NO_CHANGE;
    }
    const BOOL clean = [owner clear_capture:Availability::kNoSelection remove_lifecycle:YES];
    if (clean) {
      owner->selected_ = nil;
      owner->selection_present_ = NO;
    }
    return clean ? RASP_IOS_CAPTURE_OK : RASP_IOS_CAPTURE_CLEANUP_ERROR;
  });
}
int32_t rasp_ios_capture_refresh(void) {
  return perform(false, UINT32_C(3), ^int32_t(RaspCaptureCoordinator* owner) {
    return [owner refresh];
  });
}
int32_t rasp_ios_capture_stop(void) {
  const int32_t status = perform(false, UINT32_C(3), ^int32_t(RaspCaptureCoordinator* owner) {
    return [owner stop];
  });
  return status == RASP_IOS_CAPTURE_NOT_STARTED ? RASP_IOS_CAPTURE_NO_CHANGE : status;
}

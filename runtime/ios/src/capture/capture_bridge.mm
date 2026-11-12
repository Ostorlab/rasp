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
  std::int64_t capture_session;
  std::int64_t capture_generation;
  std::int64_t capture_selection_ordinal;
  std::uint32_t capture_options;
  BOOL capture_running;
  BOOL capture_scene_mode;
  BOOL capture_application_active;
  BOOL capture_infrastructure_ready;
  BOOL capture_selection_ready;
  BOOL capture_selection_present;
  BOOL capture_entry_in_progress;
  __weak id capture_selected;
  __weak UIScreen* capture_screen;
  id capture_trait_token;
  id capture_screen_token;
  id capture_screenshot_token;
  std::array<id, 7> capture_lifecycle_tokens;
  NSTimer* capture_timer;
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
  if (slot >= 7 || std::span{capture_lifecycle_tokens}[slot] != nil) {
    return NO;
  }
  __weak RaspCaptureCoordinator* weak_self = self;
  const std::int64_t session = capture_session;
  const std::int64_t selection = capture_selection_ordinal;
  std::span{capture_lifecycle_tokens}[slot] = [NSNotificationCenter.defaultCenter
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
                if (owner == nil || !owner->capture_running || owner->capture_session != session ||
                    (scene && owner->capture_selection_ordinal != selection)) {
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
  return std::span{capture_lifecycle_tokens}[slot] != nil;
}
- (BOOL)clear_capture:(Availability)reason remove_lifecycle:(BOOL)remove_lifecycle {
  capture_events().invalidate(capture_session, reason);
  capture_generation = 0;
  BOOL clean = YES;
  if (capture_trait_token != nil) {
    @try {
      if (__builtin_available(iOS 17.0, *)) {
        id owner = capture_selected;
        if (owner != nil && [owner isKindOfClass:UIWindowScene.class]) {
          [static_cast<UIWindowScene*>(owner) unregisterForTraitChanges:capture_trait_token];
        }
        capture_trait_token = nil;
      } else {
        clean = NO;
      }
    } @catch (NSException* exception) {
      static_cast<void>(exception);
      clean = NO;
    }
  }
  if (![self remove_notification:&capture_screen_token]) {
    clean = NO;
  }
  if (remove_lifecycle) {
    for (NSUInteger index = 3; index < 7; ++index) {
      if (![self remove_notification:&std::span{capture_lifecycle_tokens}[index]]) {
        clean = NO;
      }
    }
  }
  capture_screen = nil;
  if (!clean) {
    capture_events().failure(capture_session, 1, Availability::kTeardownError);
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
    const std::int64_t session = capture_session;
    capture_timer =
        [NSTimer timerWithTimeInterval:5.0
                               repeats:YES
                                 block:^(NSTimer* timer) {
                                   static_cast<void>(timer);
                                   if (pthread_main_np() == 0) {
                                     capture_events().reject(session, 0, 0, true);
                                     capture_events().reject(session, 1, 0, true);
                                     return;
                                   }
                                   RaspCaptureCoordinator* owner = weak_self;
                                   if (owner == nil || owner->capture_session != session || !owner->capture_running) {
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
    if (capture_timer == nil) {
      healthy = NO;
    } else {
      [NSRunLoop.mainRunLoop addTimer:capture_timer forMode:NSRunLoopCommonModes];
    }
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    healthy = NO;
  }
  return healthy;
}
- (BOOL)install_screenshot {
  const std::int64_t session = capture_session;
  @try {
    capture_screenshot_token =
        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationUserDidTakeScreenshotNotification
                                                        object:nil
                                                         queue:nil
                                                    usingBlock:^(NSNotification* notification) {
                                                      static_cast<void>(notification);
                                                      capture_events().screenshot(session);
                                                    }];
    return capture_screenshot_token != nil;
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    return NO;
  }
}
- (int32_t)start:(uint32_t)options {
  if (capture_running) {
    return capture_options == options ? RASP_IOS_CAPTURE_NO_CHANGE : RASP_IOS_CAPTURE_OPTIONS_CONFLICT;
  }
  const int32_t cleanup = [self stop];
  if (cleanup == RASP_IOS_CAPTURE_CLEANUP_ERROR) {
    return cleanup;
  }
  capture_session = capture_events().start((options & RASP_IOS_CAPTURE_SCREENSHOTS) != 0,
                                           (options & RASP_IOS_CAPTURE_RECORDING) != 0);
  if (capture_session <= 0) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  capture_options = options;
  capture_running = YES;
  capture_application_active = UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
  const BOOL healthy = [self install_process];
  capture_infrastructure_ready = healthy;
  if (!healthy) {
    capture_events().failure(capture_session, 0, Availability::kRegistrationError);
    capture_events().failure(capture_session, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if ((capture_options & RASP_IOS_CAPTURE_SCREENSHOTS) != 0 && ![self install_screenshot]) {
    capture_events().failure(capture_session, 0, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (capture_screenshot_token != nil) {
    capture_events().screenshot_ready(capture_session, capture_application_active);
  }
  return RASP_IOS_CAPTURE_OK;
}
- (int32_t)select:(id)object scene:(BOOL)scene {
  if (!capture_running) {
    return RASP_IOS_CAPTURE_NOT_STARTED;
  }
  if ((capture_options & RASP_IOS_CAPTURE_RECORDING) == 0) {
    return RASP_IOS_CAPTURE_NOT_REQUESTED;
  }
  if (!capture_infrastructure_ready) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (capture_selection_present && capture_selected == object && capture_scene_mode == scene) {
    return RASP_IOS_CAPTURE_NO_CHANGE;
  }
  if (![self clear_capture:Availability::kNoSelection remove_lifecycle:YES]) {
    return RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  capture_selected = nil;
  if (capture_selection_ordinal == INT64_MAX) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  ++capture_selection_ordinal;
  capture_selected = object;
  capture_selection_present = YES;
  capture_scene_mode = scene;
  capture_selection_ready = NO;
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
    capture_events().failure(capture_session, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  capture_selection_ready = YES;
  return [self refresh];
}
- (void)sample:(SampleKind)kind {
  const std::int64_t generation = capture_generation;
  const std::int64_t serial = capture_events().ticket(capture_session, generation);
  if (serial <= 0) {
    return;
  }
  id object = capture_selected;
  if (object == nil) {
    static_cast<void>([self clear_capture:Availability::kOwnerGone remove_lifecycle:YES]);
    capture_selection_present = NO;
    return;
  }
  int state = -1;
  if (capture_scene_mode) {
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
      UIScreen* screen = capture_screen;
      if (screen != nil) {
        state = screen.isCaptured ? 1 : 0;
      }
    }
  } else {
    if (__builtin_available(iOS 17.0, *)) {
      return;
    }
    UIScreen* screen = capture_screen;
    if (screen != nil) {
      state = screen.isCaptured ? 1 : 0;
    }
  }
  capture_events().sample(capture_session, generation, serial, kind, state);
}
- (int32_t)refresh {
  if (!capture_running) {
    return RASP_IOS_CAPTURE_NOT_STARTED;
  }
  if (!capture_infrastructure_ready) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if (UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
    capture_application_active = NO;
  }
  if (capture_screenshot_token != nil && capture_timer != nil) {
    capture_events().screenshot_ready(capture_session, capture_application_active);
  }
  @try {
    return [self refresh_capture];
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    capture_events().failure(capture_session, 1, Availability::kError);
    return RASP_IOS_CAPTURE_UNAVAILABLE;
  }
}
- (int32_t)refresh_capture {
  if ((capture_options & RASP_IOS_CAPTURE_RECORDING) == 0) {
    return RASP_IOS_CAPTURE_OK;
  }
  if (!capture_selection_present) {
    return RASP_IOS_CAPTURE_OK;
  }
  id object = capture_selected;
  if (object == nil) {
    static_cast<void>([self clear_capture:Availability::kOwnerGone remove_lifecycle:YES]);
    capture_selection_present = NO;
    return RASP_IOS_CAPTURE_OK;
  }
  if (!capture_selection_ready) {
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  BOOL eligible = capture_application_active;
  UIScreen* screen = nil;
  BOOL modern = NO;
  if (capture_scene_mode) {
    if (__builtin_available(iOS 13.0, *)) {
      auto* const scene = static_cast<UIWindowScene*>(object);
      eligible = scene.activationState == UISceneActivationStateForegroundActive;
      if (__builtin_available(iOS 17.0, *)) {
        modern = YES;
      } else {
        screen = scene.screen;
      }
    }
  } else {
    auto* const window = static_cast<UIWindow*>(object);
    eligible = eligible && !window.hidden;
    screen = window.screen;
  }
  if (!eligible) {
    return [self clear_capture:Availability::kInactive remove_lifecycle:NO] ? RASP_IOS_CAPTURE_OK
                                                                            : RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  if (capture_generation > 0 && (modern || capture_screen == screen)) {
    [self sample:SampleKind::kResample];
    return RASP_IOS_CAPTURE_OK;
  }
  if (![self clear_capture:Availability::kUnavailableState remove_lifecycle:NO]) {
    return RASP_IOS_CAPTURE_CLEANUP_ERROR;
  }
  if (!modern && screen == nil) {
    capture_events().failure(capture_session, 1, Availability::kError);
    return RASP_IOS_CAPTURE_UNAVAILABLE;
  }
  return [self install_selected:object modern:modern screen:screen];
}
- (int32_t)install_selected:(id)object modern:(BOOL)modern screen:(UIScreen*)screen {
  capture_generation = capture_events().open(capture_session, modern ? Scope::kScene : Scope::kScreen);
  if (capture_generation <= 0) {
    return RASP_IOS_CAPTURE_EXHAUSTED;
  }
  __weak RaspCaptureCoordinator* weak_self = self;
  const std::int64_t session = capture_session;
  const std::int64_t generation = capture_generation;
  @try {
    if (modern) {
      if (__builtin_available(iOS 17.0, *)) {
        capture_trait_token = [static_cast<UIWindowScene*>(object)
            registerForTraitChanges:@[ UITraitSceneCaptureState.class ]
                        withHandler:^(id<UITraitEnvironment> environment, UITraitCollection* previous) {
                          static_cast<void>(environment);
                          static_cast<void>(previous);
                          if (pthread_main_np() == 0) {
                            capture_events().reject(session, 1, generation, true);
                            return;
                          }
                          RaspCaptureCoordinator* owner = weak_self;
                          if (owner == nil || !owner->capture_running || owner->capture_session != session ||
                              owner->capture_generation != generation) {
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
      capture_screen = screen;
      capture_screen_token = [NSNotificationCenter.defaultCenter
          addObserverForName:UIScreenCapturedDidChangeNotification
                      object:nil
                       queue:nil
                  usingBlock:^(NSNotification* notification) {
                    if (pthread_main_np() == 0) {
                      capture_events().reject(session, 1, generation, true);
                      return;
                    }
                    RaspCaptureCoordinator* owner = weak_self;
                    if (owner == nil || !owner->capture_running || owner->capture_session != session ||
                        owner->capture_generation != generation) {
                      capture_events().reject(session, 1, generation, false);
                      return;
                    }
                    if (notification.object != owner->capture_screen) {
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
    capture_events().failure(capture_session, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  if ((modern && capture_trait_token == nil) || (!modern && capture_screen_token == nil)) {
    capture_events().failure(capture_session, 1, Availability::kRegistrationError);
    return RASP_IOS_CAPTURE_REGISTRATION_ERROR;
  }
  capture_events().registered(capture_session, capture_generation);
  [self sample:SampleKind::kInitial];
  return RASP_IOS_CAPTURE_OK;
}
- (void)lifecycle:(NSNotification*)notification scene:(BOOL)scene {
  if (scene) {
    if (notification.object != capture_selected) {
      return;
    }
    if (__builtin_available(iOS 13.0, *)) {
      if ([notification.name isEqualToString:UISceneDidDisconnectNotification]) {
        const BOOL clean = [self clear_capture:Availability::kDisconnected remove_lifecycle:YES];
        capture_selection_present = NO;
        if (clean) {
          capture_selected = nil;
        }
        return;
      }
      if (![notification.name isEqualToString:UISceneDidActivateNotification]) {
        static_cast<void>([self clear_capture:Availability::kInactive remove_lifecycle:NO]);
        return;
      }
    }
  } else {
    capture_application_active = [notification.name isEqualToString:UIApplicationDidBecomeActiveNotification];
    if (!capture_application_active) {
      if (capture_screenshot_token != nil) {
        capture_events().screenshot_ready(capture_session, false);
      }
      if (!capture_scene_mode) {
        static_cast<void>([self clear_capture:Availability::kInactive remove_lifecycle:NO]);
      }
      return;
    }
  }
  static_cast<void>([self refresh]);
}
- (int32_t)stop {
  const BOOL was_running = capture_running;
  capture_events().stop(capture_session);
  capture_running = NO;
  capture_infrastructure_ready = NO;
  BOOL clean = [self clear_capture:Availability::kDeactivated remove_lifecycle:YES];
  for (NSUInteger index = 0; index < 3; ++index) {
    if (![self remove_notification:&std::span{capture_lifecycle_tokens}[index]]) {
      clean = NO;
    }
  }
  if (![self remove_notification:&capture_screenshot_token]) {
    clean = NO;
  }
  @try {
    [capture_timer invalidate];
    capture_timer = nil;
  } @catch (NSException* exception) {
    static_cast<void>(exception);
    clean = NO;
  }
  capture_selection_present = NO;
  if (clean) {
    capture_selected = nil;
    capture_options = 0;
    capture_events().cleanup_complete(capture_session);
  } else {
    capture_events().failure(capture_session, 0, Availability::kTeardownError);
    capture_events().failure(capture_session, 1, Availability::kTeardownError);
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
    RaspCaptureCoordinator* const owner = [[RaspCaptureCoordinator alloc] init];
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
      if (owner->capture_entry_in_progress) {
        return RASP_IOS_CAPTURE_UNAVAILABLE;
      }
      owner->capture_entry_in_progress = YES;
      const int32_t result = operation(owner);
      owner->capture_entry_in_progress = NO;
      return result;
    } @catch (NSException* exception) {
      static_cast<void>(exception);
      if (owner != nil) {
        owner->capture_entry_in_progress = NO;
        if ((affected & RASP_IOS_CAPTURE_SCREENSHOTS) != 0) {
          capture_events().failure(owner->capture_session, 0, Availability::kError);
        }
        if ((affected & RASP_IOS_CAPTURE_RECORDING) != 0) {
          capture_events().failure(owner->capture_session, 1, Availability::kError);
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
/// Preserve the approved public void* function-pointer type; the borrowed UIKit object is not const.
/// NOLINTNEXTLINE(misc-const-correctness)
int32_t rasp_ios_capture_select_scene(void* window_scene) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (window_scene == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    if (__builtin_available(iOS 13.0, *)) {
      id const object = (__bridge id)window_scene;
      if (![object isKindOfClass:UIWindowScene.class]) {
        return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
      }
      return [owner select:object scene:YES];
    }
    return RASP_IOS_CAPTURE_UNSUPPORTED_TARGET_OR_MODE;
  });
}
/// Preserve the approved public void* function-pointer type; the borrowed UIKit object is not const.
/// NOLINTNEXTLINE(misc-const-correctness)
int32_t rasp_ios_capture_select_legacy_window(void* window) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (window == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    id const object = (__bridge id)window;
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
/// Preserve the approved public void* function-pointer type; the borrowed UIKit object is not const.
/// NOLINTNEXTLINE(misc-const-correctness)
int32_t rasp_ios_capture_clear_selection(void* selected_object) {
  return perform(false, RASP_IOS_CAPTURE_RECORDING, ^int32_t(RaspCaptureCoordinator* owner) {
    if (selected_object == nullptr) {
      return RASP_IOS_CAPTURE_INVALID_ARGUMENT;
    }
    if (!owner->capture_running) {
      return RASP_IOS_CAPTURE_NOT_STARTED;
    }
    if (owner->capture_selected != (__bridge id)selected_object) {
      return RASP_IOS_CAPTURE_NO_CHANGE;
    }
    const BOOL clean = [owner clear_capture:Availability::kNoSelection remove_lifecycle:YES];
    if (clean) {
      owner->capture_selected = nil;
      owner->capture_selection_present = NO;
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

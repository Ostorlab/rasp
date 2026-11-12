/// macOS SDK fixture of the actual iOS adapter; replaces only sandbox URL selection and iOS data-protection services.
#include "rasp/private_storage.h"

#import <Foundation/Foundation.h>
#include <gtest/gtest.h>
#import <objc/runtime.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "support/files.h"

/// The test process never asks for or changes its real Application Support directory.
@interface StorageFixtureManager : NSFileManager
@property(nonatomic, strong) NSURL* fixtureRoot;
@property(nonatomic) BOOL refuseProtection;
@end
@implementation StorageFixtureManager
- (NSURL*)URLForDirectory:(NSSearchPathDirectory)directory
                 inDomain:(NSSearchPathDomainMask)domain
        appropriateForURL:(NSURL*)url
                   create:(BOOL)create
                    error:(NSError**)error {
  static_cast<void>(directory);
  static_cast<void>(domain);
  static_cast<void>(url);
  static_cast<void>(create);
  static_cast<void>(error);
  return self.fixtureRoot;
}
- (BOOL)setAttributes:(NSDictionary*)attributes ofItemAtPath:(NSString*)path error:(NSError**)error {
  static_cast<void>(attributes);
  static_cast<void>(path);
  static_cast<void>(error);
  return !self.refuseProtection;
}
- (NSDictionary*)attributesOfItemAtPath:(NSString*)path error:(NSError**)error {
  static_cast<void>(path);
  static_cast<void>(error);
  return @{NSFileProtectionKey : NSFileProtectionCompleteUntilFirstUserAuthentication};
}
@end

namespace rasp {
namespace {
/// Replaces a Foundation boundary only inside this isolated fixture executable and restores it on scope exit.
class ScopedMethod {
 public:
  ScopedMethod(Method method, IMP replacement)
      : method_(method), original_(method_setImplementation(method, replacement)), replacement_(replacement) {}
  ~ScopedMethod() {
    static_cast<void>(method_setImplementation(method_, original_));
    static_cast<void>(imp_removeBlock(replacement_));
  }
  ScopedMethod(const ScopedMethod&) = delete;
  ScopedMethod& operator=(const ScopedMethod&) = delete;
  ScopedMethod(ScopedMethod&&) = delete;
  ScopedMethod& operator=(ScopedMethod&&) = delete;

 private:
  Method method_;
  IMP original_;
  IMP replacement_;
};

/// Binds the public Foundation sandbox-selection API to a fixture parent without changing the runtime implementation.
[[nodiscard]] IMP sandbox_manager(StorageFixtureManager* manager) {
  return imp_implementationWithBlock(^(id /*receiver*/) {
    return manager;
  });
}

TEST(ApplePrivateStorage, acquire_whenSandboxUrlIsUnavailable_returnsExplicitUnavailable) {
  @autoreleasepool {
    StorageFixtureManager* manager = [[StorageFixtureManager alloc] init];
    const ScopedMethod selection(class_getClassMethod([NSFileManager class], @selector(defaultManager)),
                                 sandbox_manager(manager));
    const auto storage = acquire_private_storage();
    ASSERT_FALSE(storage.has_value());
    EXPECT_EQ(storage.error(), StorageError::kUnavailable);
  }
}

TEST(ApplePrivateStorage, acquire_whenProtectionCannotBeSet_doesNotCreateAnIdentity) {
  @autoreleasepool {
    const test_support::TemporaryDirectory directory;
    StorageFixtureManager* manager = [[StorageFixtureManager alloc] init];
    manager.fixtureRoot = [NSURL fileURLWithFileSystemRepresentation:directory.path().c_str()
                                                         isDirectory:YES
                                                       relativeToURL:nil];
    manager.refuseProtection = YES;
    const ScopedMethod selection(class_getClassMethod([NSFileManager class], @selector(defaultManager)),
                                 sandbox_manager(manager));
    const auto storage = acquire_private_storage();
    ASSERT_FALSE(storage.has_value());
    EXPECT_EQ(storage.error(), StorageError::kBackupExclusionFailed);
    EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
  }
}

TEST(ApplePrivateStorage, acquire_whenBackupExclusionFails_doesNotExposeAQueueOrCreateIdentity) {
  @autoreleasepool {
    const test_support::TemporaryDirectory directory;
    StorageFixtureManager* manager = [[StorageFixtureManager alloc] init];
    NSURL* root = [NSURL fileURLWithFileSystemRepresentation:directory.path().c_str()
                                                 isDirectory:YES
                                               relativeToURL:nil];
    manager.fixtureRoot = root;
    const ScopedMethod selection(class_getClassMethod([NSFileManager class], @selector(defaultManager)),
                                 sandbox_manager(manager));
    const ScopedMethod exclusion(
        class_getInstanceMethod(object_getClass(root), @selector(setResourceValue:forKey:error:)),
        imp_implementationWithBlock(^(id /*receiver*/, id /*value*/, NSURLResourceKey /*key*/, NSError** /*error*/) {
          return NO;
        }));
    const auto storage = acquire_private_storage();
    ASSERT_FALSE(storage.has_value());
    EXPECT_EQ(storage.error(), StorageError::kBackupExclusionFailed);
    EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
  }
}

TEST(ApplePrivateStorage, acquire_whenOwnedLegacyParentIsSelected_preservesIdentityAndVerifiesBackupExclusion) {
  @autoreleasepool {
    const test_support::TemporaryDirectory directory;
    constexpr std::string_view kIdentity = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b";
    ASSERT_TRUE(test_support::write_file(directory.path() + "/rasp_install_id", kIdentity));
    ASSERT_EQ(chmod((directory.path() + "/rasp_install_id").c_str(), 0644), 0);
    StorageFixtureManager* manager = [[StorageFixtureManager alloc] init];
    NSURL* root = [NSURL fileURLWithFileSystemRepresentation:directory.path().c_str()
                                                 isDirectory:YES
                                               relativeToURL:nil];
    manager.fixtureRoot = root;
    const ScopedMethod selection(class_getClassMethod([NSFileManager class], @selector(defaultManager)),
                                 sandbox_manager(manager));
    auto storage = acquire_private_storage();
    ASSERT_TRUE(storage.has_value());
    EXPECT_EQ(storage->install_id(), kIdentity);
    NSNumber* excluded = nil;
    NSURL* child = [root URLByAppendingPathComponent:@"rasp_private" isDirectory:YES];
    EXPECT_TRUE([child getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:nullptr]);
    EXPECT_TRUE([excluded boolValue]);
    EXPECT_TRUE(storage->close().has_value());
  }
}

TEST(ApplePrivateStorage, acquire_whenFreshDirectoryUsesSecurityRandom_persistsOneVersionFourIdentity) {
  @autoreleasepool {
    const test_support::TemporaryDirectory directory;
    StorageFixtureManager* manager = [[StorageFixtureManager alloc] init];
    manager.fixtureRoot = [NSURL fileURLWithFileSystemRepresentation:directory.path().c_str()
                                                         isDirectory:YES
                                                       relativeToURL:nil];
    const ScopedMethod selection(class_getClassMethod([NSFileManager class], @selector(defaultManager)),
                                 sandbox_manager(manager));
    auto first = acquire_private_storage();
    ASSERT_TRUE(first.has_value());
    const std::string identity(first->install_id());
    ASSERT_EQ(identity.size(), 36U);
    EXPECT_EQ(identity[14], '4');
    EXPECT_NE(std::string_view("89ab").find(identity[19]), std::string_view::npos);
    ASSERT_TRUE(first->close().has_value());
    auto second = acquire_private_storage();
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->install_id(), identity);
    EXPECT_TRUE(second->close().has_value());
  }
}
}  // namespace
}  // namespace rasp

/* The test app the release packs: it starts UIKit with no delegate and does nothing else, so it stays up with an empty
 * screen once it is signed and installed. Declared here because the build has no iOS SDK. */
int UIApplicationMain(int argc, char *argv[], const void *principal_class_name, const void *delegate_class_name);

int main(int argc, char *argv[]) { return UIApplicationMain(argc, argv, 0, 0); }

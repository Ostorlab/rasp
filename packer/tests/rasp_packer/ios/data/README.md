# Test executables

Two arm64 iOS executables of `int main(void) { return 0; }`, built on macOS with Xcode:

```
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --sdk iphoneos --find clang)
$CC -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 -O2 main.c -o arm64_app
cp arm64_app arm64_app_signed
codesign -s - arm64_app_signed
```

`arm64_app` has no code signature; `arm64_app_signed` has an ad-hoc one.

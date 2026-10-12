# Test apps

The release workflow packs every app in this folder with the packer it is about to release, and checks each protected app. If one app fails, the release stops before anything is tagged.

To test another app, add its file to the platform's folder and a row to the platform's table below.

## iOS (`ios/`)

An iOS app must be an IPA with an arm64 executable that isn't encrypted, so not an App Store download. For each protected IPA, the release checks that:

- the runtime framework is embedded, and is the one the packer ships;
- the framework's `Info.plist` has a build id;
- every arm64 slice of the main executable loads the runtime and searches `@executable_path/Frameworks`;
- the app's code signature is gone, and the main executable is still executable.

| File | Source | Minimum iOS | Built with | SHA-256 |
|---|---|---|---|---|
| `swiftvulnerableapp.ipa` | [`ostorlab_insecure_ios_swift_app` v0.7](https://github.com/Ostorlab/ostorlab_insecure_ios_swift_app/releases/tag/v0.7) | 16.0 | Xcode 15.0.1, iOS 17.0 SDK | `15c3ac41ac511bc93102df30d5295bbbfd75346986cbbcff883108e95b85833b` |

## Android (`android/`)

An Android app must be an APK with a `classes.dex`. For each protected APK, the release checks that:

- the stub loader replaces the app's `classes.dex`, and is the one the packer ships;
- every native runtime library the packer ships is embedded, one per ABI, unchanged;
- the runtime config and the encrypted payload are present, and the config has a build id;
- the manifest declares the stub as the application class;
- the app's v1 signature files (`META-INF/MANIFEST.MF` and the `.SF`, `.RSA`, `.DSA` and `.EC` files) and its original secondary dex files are gone.

| File | Source | Licence | SHA-256 |
|---|---|---|---|
| `InsecureBankv2.apk` | [`Android-InsecureBankv2` 2.3.1](https://github.com/dineshshetty/Android-InsecureBankv2/releases/tag/2.3.1) | MIT | `b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4` |

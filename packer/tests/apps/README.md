# Test apps

The release workflow packs every app in this folder with the packer it is about to release. For each protected app, it checks that:

- the runtime framework is embedded, and is the one the packer ships;
- the framework's `Info.plist` has a build id;
- every arm64 slice of the main executable loads the runtime and searches `@executable_path/Frameworks`;
- the app's code signature is gone, and the main executable is still executable.

If one app fails, the release stops before anything is tagged.

To test another app, add its file to the platform's folder and a row to the table below. An iOS app must be an IPA with an arm64 executable that isn't encrypted, so not an App Store download.

## iOS (`ios/`)

| File | Source | Minimum iOS | Built with | SHA-256 |
|---|---|---|---|---|
| `swiftvulnerableapp.ipa` | [`ostorlab_insecure_ios_swift_app` v0.7](https://github.com/Ostorlab/ostorlab_insecure_ios_swift_app/releases/tag/v0.7) | 16.0 | Xcode 15.0.1, iOS 17.0 SDK | `15c3ac41ac511bc93102df30d5295bbbfd75346986cbbcff883108e95b85833b` |

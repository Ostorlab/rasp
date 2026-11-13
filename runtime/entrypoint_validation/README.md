# Local entry-point source adapters

Local entry-point source adapters are an opt-in package compiled into the host.
The stateless classifier matches exact app-compiled routes; a match has no
authorization or telemetry effect. The [integration contract](../../docs/entrypoint-validation.md)
and real [reference handlers](../tests/entrypoint_validation/README.md) show boundary
validation, fresh native gate and actual closed dispatch together.

- C/ObjC/C++ hosts compile `src/link_validation.c` and include `include/`.
  Symbols are hidden; never link this optional target into RaspRuntime/librasp.
- Android compiles `android/co/ostorlab/rasp/entry/EntryPointValidation.java` into
  the customer app. Restricted profiles use exact package/signing-history pins
  and a host-declared signature permission at the live invocation boundary.
  The host calls the **existing** RuntimeBridge gate with its compiled operation/
  hash immediately before its mapped effect. Use the existing bridge jar only
  as compileOnly; never bundle a second bridge or native method.
- Apple compiles the C classifier, `ios/url_bytes.c` and
  `ios/EntryPointValidation.swift` with the host. Its bridging header includes
  `ios/url_bytes.h` and the existing installed native policy header. Add this
  package's `include/`, `ios/` and the installed framework Headers to the host
  search paths. Link the existing framework, Foundation/UIKit/CoreFoundation.
  The reference app also compiles unchanged RT20 source/clock for its separate
  deliberate confirmation action; no C++ object crosses a framework boundary.

Configuration is immutable app source, not a URL-supplied rule/permission/result.
One bounded table admits 1..16 exact argument-free routes; caller profiles <= 4.
Each profile has 1..2 SHA256 pins of 32 bytes each. Unknown/malformed configuration rejects wholly. Sources expose
finite local diagnostics, never a cached grant. The URL's delivered representation
is bounded to 1024 ASCII bytes; v1 rejects encodings/IDNA/ports/queries/fragments.

No callbacks are installed by this package. Customers adapt every intended
Activity/Binder/provider/UIKit effect boundary and explicitly own lifecycle,
cancellation, scope replacement and any public pending route. Unadapted paths,
async/oneway IPC, generic Binder/XPC, SwiftUI/WebView/framework routing and direct
sensitive mutations remain unsupported. Preserve the customer's App/Universal
Links and signing configuration; domains and sourceApplication grant no caller
or server authority. No signing/enrollment keys or cloud/customer effects are
needed to compile these sources.


Host shrinkers must include `android/consumer-rules.pro` alongside the existing
bridge/stub keep rules. It keeps the API 35-only helper isolated so optimization
cannot move newer platform references into API 31 code. The real reference builder
accepts optional `R8_JAR` pointing at the SDK's existing d8.jar for a minified
compile; neither D8 nor R8 compilation proves device loading or caller identity.

// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RaspCore",
    platforms: [.iOS(.v14), .macOS(.v13)],
    products: [.library(name: "RaspCore", targets: ["RaspCore"])],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", exact: "3.12.3")],
    targets: [
        .target(name: "RaspCore", dependencies: [.product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))], path: "Classes/Core"),
        .testTarget(name: "RaspCoreTests", dependencies: ["RaspCore"], path: "Tests/RaspCoreTests", resources: [.copy("localhost.der")])
    ],
    swiftLanguageVersions: [.v5]
)

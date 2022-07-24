// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "SelfSignedCert",
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
        .tvOS(.v14)
    ],
    products: [
        .library(
            name: "SelfSignedCert",
            targets: ["SelfSignedCert"]
        )
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "2.1.0")),
        .package(name: "SwiftBytes", url: "https://github.com/dapperstout/swift-bytes.git", from: "0.8.0"),

        .package(name: "Quick", url: "https://github.com/Quick/Quick.git", from: "5.0.0"),
        .package(name: "Nimble", url: "https://github.com/Quick/Nimble.git", from: "10.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SelfSignedCert",
            dependencies: [
                "SwiftBytes"
            ],
            path: "SelfSignedCert",
            exclude: ["Info.plist"]
        ),
        .testTarget(
            name: "SelfSignedCertTests",
            dependencies: [
                "Quick",
                "Nimble",
                "SelfSignedCert",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "SelfSignedCertTests",
            resources: [
                .copy("certdata.der"),
                .copy("pubkey.bin"),
                .process("Fixtures"),
            ]
        )
    ]
)

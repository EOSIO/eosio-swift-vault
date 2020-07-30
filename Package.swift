// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EosioSwiftVaultSignatureProvider",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(
            name: "EosioSwiftVaultSignatureProvider",
            targets: ["EosioSwiftVaultSignatureProvider"]),
    ],
    dependencies: [
        .package(name: "EosioSwift", url: "https://github.com/EOSIO/eosio-swift", .branch("spm-support")),
        .package(name: "EosioSwiftEcc", url: "https://github.com/EOSIO/eosio-swift-ecc", .branch("spm-support")),
        .package(name: "EosioSwiftVault", url: "https://github.com/EOSIO/eosio-swift-vault", .branch("spm-support")),
         .package(url: "https://github.com/realm/SwiftLint", from: "0.39.1")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "EosioSwiftVaultSignatureProvider",
            dependencies: [
                "EosioSwift",
                "EosioSwiftEcc",
                "EosioSwiftVault"
            ]),
        .testTarget(
            name: "EosioSwiftVaultSignatureProviderTests",
            dependencies: ["EosioSwiftVaultSignatureProvider"]),
    ]
)

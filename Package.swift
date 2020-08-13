// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EosioSwiftVault",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_14)
    ],
    products: [
        .library(
            name: "EosioSwiftVaultSignatureProvider",
            targets: ["EosioSwiftVaultSignatureProvider"]),
        .library(
            name: "EosioSwiftVault",
            targets: ["EosioSwiftVault"]),
    ],
    dependencies: [
        .package(name: "EosioSwift", url: "https://github.com/EOSIO/eosio-swift", .branch("spm-support")),
        .package(name: "EosioSwiftEcc", url: "https://github.com/EOSIO/eosio-swift-ecc", .branch("spm-support")),
        .package(url: "https://github.com/realm/SwiftLint", from: "0.39.1")
    ],
    targets: [
        .target(
            name: "EosioSwiftVault",
            dependencies: ["EosioSwift", "EosioSwiftEcc"],
            path: "Sources/EosioSwiftVault"),
        .target(
            name: "EosioSwiftVaultSignatureProvider",
            dependencies: ["EosioSwift", "EosioSwiftEcc", "EosioSwiftVault"],
            path: "Sources/EosioSwiftVaultSignatureProvider"),
        .testTarget(
            name: "EosioSwiftVaultTests",
            dependencies: ["EosioSwiftVault"],
            path: "Tests/EosioSwiftVaultTests"),
        .testTarget(
            name: "EosioSwiftVaultSignatureProviderTests",
            dependencies: ["EosioSwiftVaultSignatureProvider"],
            path: "Tests/EosioSwiftVaultSignatureProviderTests"),
    ]
)

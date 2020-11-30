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
        .package(name: "EosioSwift", url: "https://github.com/EOSIO/eosio-swift", from: "1.0.0"),
        .package(url: "https://github.com/realm/SwiftLint", from: "0.39.1")
    ],
    targets: [
        .target(
            name: "EosioSwiftVault",
            dependencies: [
                .product(name: "EosioSwift", package: "EosioSwift"),
                .product(name: "EosioSwiftEcc", package: "EosioSwift")
            ],
            path: "Sources/EosioSwiftVault"),
        .target(
            name: "EosioSwiftVaultSignatureProvider",
            dependencies: [
                .product(name: "EosioSwift", package: "EosioSwift"),
                .product(name: "EosioSwiftEcc", package: "EosioSwift"),
                "EosioSwiftVault"
            ],
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

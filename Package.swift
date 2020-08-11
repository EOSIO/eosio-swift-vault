// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EosioSwiftVault",
    platforms: [
        .iOS(.v12)
    ],
    products: [
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
            dependencies: ["EosioSwift", "EosioSwiftEcc"]),
        .testTarget(
            name: "EosioSwiftVaultTests",
            dependencies: ["EosioSwiftVault"]),
    ]
)

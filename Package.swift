// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MachInjector",
    platforms: [.macOS(.v11)],
    products: [
        .library(
            name: "MachInjector",
            targets: ["MachInjector"]
        ),
    ],
    targets: [
        .target(
            name: "MachInjector"
        ),
    ]
)

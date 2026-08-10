// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MachInjector",
    platforms: [.macOS(.v10_15)],
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
        .testTarget(
            name: "MachInjectorTests",
            dependencies: ["MachInjector"],
            // Reaches MIMachInjectorRemapInternal.h, which sits beside the
            // implementation rather than in `include/` so it stays out of the
            // MachInjector module. The tests need the real MIRemapSegment
            // layout; redeclaring it here would drift the moment the struct
            // changes.
            cSettings: [.headerSearchPath("../../Sources/MachInjector")]
        ),
    ]
)

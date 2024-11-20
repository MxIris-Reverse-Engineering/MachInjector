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
        .library(
            name: "MachInjectorUI",
            targets: ["MachInjectorUI"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/MxIris-Reverse-Engineering/LaunchServicesPrivate", branch: "main"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "MachInjector"
        ),
        .target(
            name: "MachInjectorUI",
            dependencies: [
                .product(name: "LaunchServicesPrivate", package: "LaunchServicesPrivate")
            ]
        ),

    ]
)

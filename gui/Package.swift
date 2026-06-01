// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WireGuardCGUI",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "WireGuardCGUI", targets: ["WireGuardCGUI"])
    ],
    targets: [
        .executableTarget(name: "WireGuardCGUI")
    ]
)

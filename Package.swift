// swift-tools-version:4.2
import PackageDescription

let package = Package(
    name: "PairingCrypto",
    dependencies: [
      .package(url:"https://github.com/ChaosCoder/CPBC.git", from: "1.0.0")
    ],
    targets: [
        .target(name: "PairingCrypto", path: "Sources"),
        .testTarget(name: "PairingCryptoTests", dependencies: ["PairingCrypto"], path: "Tests")
    ]
)

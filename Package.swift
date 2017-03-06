import PackageDescription

let package = Package(
    name: "PairingCrypto",
    dependencies: [
      .Package(url:"https://github.com/ChaosCoder/CPBC.git", majorVersion: 1)
    ]
)

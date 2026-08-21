// swift-tools-version:5.9
import PackageDescription

// Standalone package that unit-tests only the pure amount-parsing helpers in
// ../ios/AmountParsing.swift (symlinked into Sources/AmountParsing/) — deliberately has no
// dependency on WalletCore/ExpoModulesCore or the host app's gitignored, prebuild-generated
// ios/ Xcode project, so `swift test` works standalone and in CI. See README.md.
let package = Package(
  name: "ConformanceTests",
  targets: [
    .target(name: "AmountParsing", path: "Sources/AmountParsing"),
    .testTarget(
      name: "AmountParsingConformanceTests",
      dependencies: ["AmountParsing"],
      path: "Tests/AmountParsingConformanceTests"
    ),
  ]
)

// swift-tools-version:5.9
//
//  Package.swift
//  LeafFFI
//
//  Distributes the Rust leaf + wg-netstack static library as a binary
//  xcframework, so Picard can consume it over SwiftPM instead of vendoring the
//  artifact.
//
//  Two modes:
//
//  * Release (default) — the xcframework zip attached to a GitHub release,
//    pinned by checksum. This is what CI and other developers get.
//  * Local — set LEAF_LOCAL_XCFRAMEWORK to use a locally built artifact
//    instead, for iterating on the Rust side without cutting a release:
//
//        ./scripts/build_apple_xcframework.sh
//        LEAF_LOCAL_XCFRAMEWORK=1 xcodebuild ...   # or export it in your shell
//
//    The path is relative to this package, so the build script's default
//    output location is used as-is.
//
//  Cut a release with ./scripts/package_spm.sh <version>, which builds, zips,
//  computes the checksum and rewrites the URL below.
//

import Foundation
import PackageDescription

let version = "0.1.0"
let checksum = "99715622f5d1dd665b6b36f3ea52facfeec19accd78fd16e2305ff26688fa8a1"

let useLocalBinary = ProcessInfo.processInfo.environment["LEAF_LOCAL_XCFRAMEWORK"] != nil

let binaryTarget: Target = useLocalBinary
    ? .binaryTarget(
        name: "LeafFFI",
        path: "target/apple/release/leaf.xcframework"
      )
    : .binaryTarget(
        name: "LeafFFI",
        url: "https://github.com/chkp-aviads/leaf/releases/download/\(version)/leaf.xcframework.zip",
        checksum: checksum
      )

let package = Package(
    name: "LeafFFI",
    // Matches the deployment targets the binary is actually built with; see
    // setup_env in scripts/apple_common.sh. iOS 10 no longer links, because
    // aws-lc-sys emits objects referencing ___chkstk_darwin.
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(name: "LeafFFI", targets: ["LeafFFI"])
    ],
    targets: [binaryTarget]
)

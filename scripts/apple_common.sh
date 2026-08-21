#!/usr/bin/env sh

# scripts/apple_common.sh

set -ex

setup_env() {
    # The script is assumed to run in the root of the workspace
    
    # Default values
    mode=release
    release_flag=--release
    package=leaf-ffi
    name=leaf
    lib=lib$name.a

    if [ "$1" = "debug" ]; then
        mode=debug
        release_flag=
    fi

    # iOS 10.0 no longer links: aws-lc-sys compiles objects that reference
    # ___chkstk_darwin, which is absent from that old runtime, so the dylib
    # crate-type fails with "symbol(s) not found for architecture arm64".
    # 13.0 matches the minimum Picard itself targets.
    export IPHONEOS_DEPLOYMENT_TARGET=13.0
    export MACOSX_DEPLOYMENT_TARGET=10.15
    
    # Output directories
    BASE_DIR="target/apple/$mode"
    INCLUDE_DIR="$BASE_DIR/include"
}

clean_dir() {
    rm -rf "$BASE_DIR"
    mkdir -p "$BASE_DIR"
    mkdir -p "$INCLUDE_DIR"
}

build_macos_libs() {
    rustup target add x86_64-apple-darwin
    rustup target add aarch64-apple-darwin

    cargo build -p $package $release_flag --no-default-features --features "default-aws-lc" --target x86_64-apple-darwin
    cargo build -p $package $release_flag --no-default-features --features "default-aws-lc" --target aarch64-apple-darwin

    mkdir -p "$BASE_DIR/macos"

    lipo -create \
        -arch x86_64 "target/x86_64-apple-darwin/$mode/$lib" \
        -arch arm64 "target/aarch64-apple-darwin/$mode/$lib" \
        -output "$BASE_DIR/macos/$lib"
}

build_ios_libs() {
    rustup target add aarch64-apple-ios
    rustup target add x86_64-apple-ios
    rustup target add aarch64-apple-ios-sim

    cargo build -p $package $release_flag --no-default-features --features "default-aws-lc" --target aarch64-apple-ios
    cargo build -p $package $release_flag --no-default-features --features "default-aws-lc" --target x86_64-apple-ios
    cargo build -p $package $release_flag --no-default-features --features "default-aws-lc" --target aarch64-apple-ios-sim

    mkdir -p "$BASE_DIR/ios"
    mkdir -p "$BASE_DIR/ios-sim"

    cp "target/aarch64-apple-ios/$mode/$lib" "$BASE_DIR/ios/"
    
    lipo -create \
        -arch x86_64 "target/x86_64-apple-ios/$mode/$lib" \
        -arch arm64 "target/aarch64-apple-ios-sim/$mode/$lib" \
        -output "$BASE_DIR/ios-sim/$lib"
}

generate_header() {
    # Check for cbindgen
    if ! command -v cbindgen >/dev/null 2>&1; then
        cargo install cbindgen
    fi

    mkdir -p "$INCLUDE_DIR"
    cbindgen \
        --config "$package/cbindgen.toml" \
        "$package/src/lib.rs" > "$INCLUDE_DIR/$name.h"

    # Module name deliberately differs from the library name: "leaf" as a Swift
    # module would shadow nothing useful and reads oddly at the import site.
    # LeafFFI matches the SwiftPM binaryTarget that consumes it.
    cat << EOF > "$INCLUDE_DIR/module.modulemap"
module LeafFFI {
    header "$name.h"
    export *
}
EOF
}

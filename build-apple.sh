#! /bin/sh

if [ "$(uname)" != "Darwin" ]; then
    echo "This script is for macOS only."
    exit 1
fi

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
cargo install cbindgen

cargo update

echo "Building..."

echo "cargo build --release --target x86_64-apple-darwin"
cargo build --release --target x86_64-apple-darwin

echo "cargo build --release --target aarch64-apple-darwin"
cargo build --release --target aarch64-apple-darwin

echo "cargo build --release --target aarch64-apple-ios"
cargo build --release --target aarch64-apple-ios

echo "cargo build --release --target x86_64-apple-ios"
cargo build --release --target x86_64-apple-ios

echo "cargo build --release --target aarch64-apple-ios-sim"
cargo build --release --target aarch64-apple-ios-sim

echo "Generating includes..."
mkdir -p target/include/
rm -rf target/include/*
cbindgen --config cbindgen.toml -l C --cpp-compat -o target/include/overtls.h
cat > target/include/overtls.modulemap <<EOF
framework module overtls {
    umbrella header "overtls.h"
    export *
    module * { export * }
}
EOF

echo "lipo..."
echo "Simulator"
lipo -create \
    target/aarch64-apple-ios-sim/release/libovertls.a \
    target/x86_64-apple-ios/release/libovertls.a \
    -output ./target/libovertls-ios-sim.a

echo "MacOS"
lipo -create \
    target/aarch64-apple-darwin/release/libovertls.a \
    target/x86_64-apple-darwin/release/libovertls.a \
    -output ./target/libovertls-macos.a

echo "Creating XCFramework"
rm -rf ./overtls.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/release/libovertls.a -headers ./target/include/ \
    -library ./target/libovertls-ios-sim.a -headers ./target/include/ \
    -library ./target/libovertls-macos.a -headers ./target/include/ \
    -output ./overtls.xcframework

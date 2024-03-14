#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
cargo install cbindgen

cargo update

echo "Building..."
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

echo "Generating includes..."
mkdir -p target/include/
cbindgen --config cbindgen.toml -l C -o target/include/overtls.h
cat > target/include/module.modulemap <<EOF
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

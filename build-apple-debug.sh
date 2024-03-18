#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios
cargo install cbindgen

cargo update

echo "Building..."
cargo build --target aarch64-apple-ios

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

echo "Creating XCFramework"
rm -rf ./overtls.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/debug/libovertls.a -headers ./target/include/ \
    -output ./overtls.xcframework

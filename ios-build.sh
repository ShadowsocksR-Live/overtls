# #! /usr/bin/bash

cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
lipo -create target/aarch64-apple-ios/release/libovertls.a target/x86_64-apple-ios/release/libovertls.a -output target/libovertls.a
cbindgen --config cbindgen.toml -l C -o target/overtls-ffi.h


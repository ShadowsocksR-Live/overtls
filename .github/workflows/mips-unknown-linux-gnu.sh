#!/bin/bash

# Change to the directory where the script is located
cd "$(dirname "$0")"

# Set up rust build environment
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
sudo apt install -y patchelf gcc-mips-linux-gnu binutils-mips-linux-gnu musl-tools

# Set up for glibc
rm -rf ~/.rustup/mips-unknown-linux-gnu.json
rustc +nightly \
    -Z unstable-options \
    --print target-spec-json \
    --target mips-unknown-linux-gnu \
    > ~/.rustup/mips-unknown-linux-gnu.json

# Edit the JSON file to change `is-builtin` to `false` and add `+soft-float` to `features` list
sed -i 's/"is-builtin": true/"is-builtin": false/' ~/.rustup/mips-unknown-linux-gnu.json
sed -i 's/"features": "/"features": "\+soft-float,/' ~/.rustup/mips-unknown-linux-gnu.json

cd ../..

# Configure linker
mkdir .cargo
rm -rf .cargo/config.toml
cat > .cargo/config.toml <<EOF
[target.mips-unknown-linux-gnu]
linker = "mips-linux-gnu-gcc"
EOF

cargo +nightly build --release -Zbuild-std --target ~/.rustup/mips-unknown-linux-gnu.json


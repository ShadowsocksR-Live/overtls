#!/bin/bash

# curl -s https://api.github.com/repos/cross-rs/cross/releases/latest \
#     | grep cross-x86_64-unknown-linux-gnu.tar.gz \
#     | cut -d : -f 2,3 \
#     | tr -d \" \
#     | wget -qi -

# tar -zxvf cross-x86_64-unknown-linux-gnu.tar.gz -C /usr/bin
# rm -f cross-x86_64-unknown-linux-gnu.tar.gz

source /home/runner/.cargo/env
rustup default stable
cargo install cross --git https://github.com/cross-rs/cross --rev 36c0d7810ddde073f603c82d896c2a6c886ff7a4 --root /usr/local/
cross --version

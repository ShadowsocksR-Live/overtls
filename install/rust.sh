#!/bin/bash

function dependency_install() {
    source /etc/os-release

    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        sudo yum -y install python3 qrencode curl wget git lsof bc unzip make libtool openssl vim
        sudo yum -y install crontabs zlib zlib-devel gcc-c++ openssl-devel
    elif [[ "${ID}" == "debian" || "${ID}" == "ubuntu" || "${ID}" == "linuxmint" ]]; then
        sudo apt update -y
        sudo apt -y install python3 qrencode curl wget git lsof bc unzip make libtool openssl vim
        sudo apt -y install cron cmake zlib1g zlib1g-dev build-essential autoconf libssl-dev
        if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
            sudo apt -y install inetutils-ping
        fi
    else
        echo -e "Current system is ${ID} ${VERSION_ID} is not in the list of supported systems, installation is interrupted "
        exit 1
    fi
}

function rust_install() {
    # Download Rust installation script
    rm -rf rustup.sh
    curl https://sh.rustup.rs -sSf > rustup.sh

    # Run Rust installation script, and wait for user input of "1"
    echo "Installing Rust..."
    sh rustup.sh -y <<EOF
1
EOF

    # Add Rust to PATH
    source $HOME/.cargo/env

    # Verify Rust installation
    rustc --version
    cargo --version

    rm -rf rustup.sh
}

function main() {
    dependency_install
    rust_install
}

main "$@"


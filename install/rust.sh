#!/bin/bash

function linux_dependency_install() {
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
    if cargo --version; then
        echo "Rust is already installed, skipping..."
        exit 0
    fi
    local os_name=$(uname)
    if [[ "${os_name}" == "Darwin" ]]; then
        if ! xcode-select -p >/dev/null; then
            echo "Xcode is not installed, please install it first"
            exit 1
        else
            echo "Xcode is installed, continue..."
            xcode-select --install 2>&1 | grep installed || { echo "Xcode Command Line Tools not found. Please install and try again." && exit 1; }
        fi
    elif [[ "${os_name}" == "Linux" ]]; then
        linux_dependency_install
    else
        echo "Unsupported system: ${os_name}, installation is interrupted "
        exit 1
    fi
    rust_install
}

main "$@"


# overtls

[![Crates.io](https://img.shields.io/crates/v/overtls.svg)](https://crates.io/crates/overtls)
![overtls](https://docs.rs/overtls/badge.svg)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/overtls)
[![Download](https://img.shields.io/crates/d/overtls.svg)](https://crates.io/crates/overtls)
[![License](https://img.shields.io/crates/l/overtls.svg?style=flat)](https://github.com/ShadowsocksR-Live/overtls/blob/master/LICENSE)


[中文版](readme-cn.md)

overtls is a [SOCKS5](https://en.wikipedia.org/wiki/SOCKS#SOCKS5) type proxy,
which implements data transmission through TLS and supports TCP and UDP traffic forwarding at the same time.

The function is complete and the code is concise, and the core function is 1200 lines of code in total.

> `OverTLS` is a Rust implementation of [SSRoT](https://github.com/ShadowsocksR-Live/shadowsocksr-native) without `SSR` and `SS`, only retaining `oT`, which is fast and stable.
> ```kotlin
>     fun isOverTLS() : Boolean =
>         over_tls_enable && method == "none" && obfs == "plain" && protocol == "origin"
> ```

## Principle

In order to effectively deceive [GFW](https://en.wikipedia.org/wiki/Great_Firewall),
directly using [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) as proxy protocol is the simplest way,
because `TLS` protocol is the data transmission standard of internet in fact,
so the `GFW` cannot block the `TLS` protocol, and the `TLS` protocol is an encryption protocol,
so `GFW` cannot know the content of the data transmitted through the `TLS` protocol.

We can take advantage of this feature to encapsulate the encryption and decryption process on
the client and server sides as a proxy service, so that encrypted TCP and UDP proxies can
be performed under `GFW` surveillance.

The overtls client first establishes a TLS connection with the overtls server,
and then the data exchange between the overtls client and the overtls server is encrypted.

We simply agree that the overtls client accessing a unique resource `uri` is considered to be a proxy,
and the server will forward the packets containing this `uri` to the specified destination address.

This is how our proxy is achieved.

Thus, the data exchange between the overtls server and the overtls client is encrypted,
while the data exchange between the overtls server and the target server is in "plaintext".

In summary, we need to prepare the following things
- A `VPS` host with a public `IP`, which must be purchased by yourself.
- A `domain name`, which can be purchased or applied for free, and resolve the `domain name` to the `IP` of the `VPS` host.
- A pair of `https` certificates/private keys, which can be purchased or applied for free at [Let's Encrypt](https://letsencrypt.org/) .
- An http server software (such as [nginx](https://www.nginx.com/) ), and provide site resources for masquerading purposes or acting as a front `reverse proxy`.

## Installation

### Install from crates.io

If you have installed the [Rust](https://rustup.rs/), you can install overtls directly.
```bash
cargo install overtls --root /usr/local/
```

### Pre-compiled binary file

Can be compiled directly from the source code, or you can download the pre-compiled binary file
from the [Release page](https://github.com/shadowsocksr-live/overtls/releases).

### Compile from source code

To compile from source code, you need to install the [Rust](https://www.rust-lang.org/)
programming language environment first, and then run the following commands to compile overtls.

```bash
git clone https://github.com/shadowsocksr-live/overtls.git
cd overtls
cargo build --release
sudo cp target/release/overtls-bin /usr/local/bin/
```

## Server-side one-click installation script

Before installation, please prepare a `VPS` host with a public `IP` and a `domain name`,
and resolve the `domain name` to this host `IP`, then run the following command and follow the prompts,
if everything goes smoothly, the result will be overtls server and nginx front proxy installed on your host,
and apply for a certificate.

Currently only 3 `CPU` architectures of `Linux` machines are supported: `x86_64`, `armv7` and `arm64`.

```bash
sudo apt install -y wget # Debian/Ubuntu
sudo yum install -y wget # CentOS
wget https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install-musl.sh
chmod +x overtls-install-musl.sh
./overtls-install-musl.sh
sudo systemctl start overtls
```

### Installation script with Caddy
<details>
<summary>Steps of installing with Caddy</summary>

```bash
sudo apt install -y wget # Debian/Ubuntu
wget https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install-caddy.sh
bash ./overtls-install-caddy.sh
sudo systemctl start overtls
```

</details>

## Usage

### Server
```bash
overtls-bin -r server -c config.json
```

### Client
```bash
overtls-bin -r client -c config.json
```

If you want to see log info, you can create a `.env` file in current dir (`pwd`)
with `RUST_LOG=overtls=trace` as content.

### Configuration file
```json
{
    "tunnel_path": "/secret-tunnel-path/",

    "server_settings": {
        "certfile": "/etc/mysite_cert/fullchain.pem",
        "keyfile": "/etc/mysite_cert/privkey.pem",
        "forward_addr": "http://127.0.0.1:80",
        "listen_host": "0.0.0.0",
        "listen_port": 443
    },

    "client_settings": {
        "server_host": "123.45.67.89",
        "server_port": 443,
        "server_domain": "example.com",
        "listen_host": "127.0.0.1",
        "listen_port": 1080
    }
}
```

The configuration file is very simple. It is common to both `server` and `client`.
-    When the application is running as a `server`, the `server_settings` section is valid and the `client_settings` section is ignored.
-    When the program is run as a `client`, the `client_settings` section is valid and the `server_settings` section is ignored.

The `certfile` and `keyfile` are optional, and the software will become `https` protocol server after the correct pairing, and the non-flip traffic will be forwarded directly to the `forward_addr` destination. If the `certfile` and `keyfile` are incorrectly matched or simply do not exist, you will need the help of a previous `reverse proxy` such as `nginx` to work.

>    If the forward_addr option does not exist, the default value is `http://127.0.0.1:80`, which is the port `80` on which the local `nginx` listens to `http`.

Note the `tunnel_path` configuration, please make sure to change it to your own unique complex string, otherwise `GFW` will block you immediately.

> The `tunnel_path` option now can be a string or an array of strings, like `["/secret-tunnel-path/", "/another-secret-tunnel-path/"]`.
> Overtls client side will select the first one to use.
> In the server side, it will check the incoming request with the entire array of strings. 

>    For testing purposes, the `disable_tls` option is provided to have the ability to disable `TLS`; that is, if this option exists and is true, the software will transmit traffic in `plain text`; for security reasons, please do not use it on official occasions.

This example shows the configuration file of the least entry, the complete configuration file can refer to [config.json](config.json).

### Self-signed certificate usage

If you have not owned a `domain name`, you can use the `openssl` command to generate a self-signed certificate
for testing purposes.

```bash
sudo apt install -y wget # Debian/Ubuntu
sudo yum install -y wget # CentOS
wget https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/overtls-install-selfsign.sh
bash ./overtls-install-selfsign.sh
```
> Note: The `GFW` maybe block your server since you are using a self-signed certificate.
>       So please do not use it for long-term production purposes.

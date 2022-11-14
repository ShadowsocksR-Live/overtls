pub mod client;
pub mod cmdopt;
pub mod config;
pub mod server;
pub mod tls;
pub mod weirduri;

use bytes::BytesMut;
use socks5_proto::Address;

pub fn program_name() -> String {
    let name = std::env::args()
        .next()
        .as_ref()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .map(String::from);
    name.unwrap_or_default()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

pub fn convert_addess_to_string(addr: &Address, url_safe: bool) -> String {
    let mut buf = BytesMut::with_capacity(1024);
    addr.write_to_buf(&mut buf);
    let config = if url_safe {
        base64::URL_SAFE_NO_PAD
    } else {
        base64::STANDARD_NO_PAD
    };
    base64::encode_config(&buf, config)
}

pub async fn convert_string_to_address(s: &str, url_safe: bool) -> anyhow::Result<Address> {
    let config = if url_safe {
        base64::URL_SAFE_NO_PAD
    } else {
        base64::STANDARD_NO_PAD
    };
    let buf = base64::decode_config(s, config)?;
    Address::read_from(&mut &buf[..]).await.map_err(|e| e.into())
}

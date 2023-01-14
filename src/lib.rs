pub mod client;
pub mod cmdopt;
pub mod config;
pub mod server;
pub mod tls;
pub mod traffic_audit;
pub mod udprelay;
pub mod webapi;
pub mod weirduri;

use bytes::BytesMut;
use socks5_impl::protocol::Address;

pub const STREAM_BUFFER_SIZE: usize = 1024 * 32;

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

use base64::{engine::general_purpose, Engine as _};

pub fn addess_to_b64str(addr: &Address, url_safe: bool) -> String {
    let mut buf = BytesMut::with_capacity(1024);
    addr.write_to_buf(&mut buf);
    if url_safe {
        general_purpose::URL_SAFE_NO_PAD.encode(buf)
    } else {
        general_purpose::STANDARD_NO_PAD.encode(buf)
    }
}

pub async fn b64str_to_address(s: &str, url_safe: bool) -> anyhow::Result<Address> {
    let buf = if url_safe {
        general_purpose::URL_SAFE_NO_PAD.decode(s)?
    } else {
        general_purpose::STANDARD_NO_PAD.decode(s)?
    };
    Address::read_from(&mut &buf[..]).await.map_err(|e| e.into())
}

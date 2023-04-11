pub(crate) mod android;
pub(crate) mod base64_wrapper;
pub mod client;
pub mod config;
pub mod error;
pub mod server;
pub(crate) mod tcp_stream;
pub(crate) mod tls;
pub(crate) mod traffic_audit;
pub(crate) mod udprelay;
pub(crate) mod webapi;
pub(crate) mod weirduri;

use base64_wrapper::{base64_decode, base64_encode, Base64Engine};
use bytes::BytesMut;
pub use error::{Error, Result};
use socks5_impl::protocol::Address;

#[cfg(target_os = "windows")]
pub(crate) const STREAM_BUFFER_SIZE: usize = 1024 * 32;
#[cfg(not(target_os = "windows"))]
pub(crate) const STREAM_BUFFER_SIZE: usize = 1024 * 32 * 3;

pub(crate) fn addess_to_b64str(addr: &Address, url_safe: bool) -> String {
    let mut buf = BytesMut::with_capacity(1024);
    addr.write_to_buf(&mut buf);
    if url_safe {
        base64_encode(&buf, Base64Engine::UrlSafeNoPad)
    } else {
        base64_encode(&buf, Base64Engine::StandardNoPad)
    }
}

pub(crate) fn b64str_to_address(s: &str, url_safe: bool) -> Result<Address> {
    let buf = if url_safe {
        let result = base64_decode(s, Base64Engine::UrlSafeNoPad);
        if result.is_err() {
            base64_decode(s, Base64Engine::UrlSafe)?
        } else {
            result?
        }
    } else {
        let result = base64_decode(s, Base64Engine::StandardNoPad);
        if result.is_err() {
            // backward compatibility for SSRoT
            base64_decode(s, Base64Engine::Standard)?
        } else {
            result?
        }
    };
    Address::from_data(&buf).map_err(|e| e.into())
}

pub(crate) fn combine_addr_and_port(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    }
}

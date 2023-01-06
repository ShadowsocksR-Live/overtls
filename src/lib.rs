pub mod client;
pub mod cmdopt;
pub mod config;
pub mod server;
pub mod tls;
pub mod traffic_audit;
pub mod udprelay;
pub mod weirduri;

use bytes::BytesMut;
use socks5_proto::Address;

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

use base64::engine::fast_portable::{FastPortable, NO_PAD};
const URL_SAFE_NO_PAD: FastPortable = FastPortable::from(&base64::alphabet::URL_SAFE, NO_PAD);
const URL_STD_NO_PAD: FastPortable = FastPortable::from(&base64::alphabet::STANDARD, NO_PAD);

pub fn addess_to_b64str(addr: &Address, url_safe: bool) -> String {
    let mut buf = BytesMut::with_capacity(1024);
    addr.write_to_buf(&mut buf);

    let config = if url_safe { &URL_SAFE_NO_PAD } else { &URL_STD_NO_PAD };
    base64::encode_engine(&buf, config)
}

pub async fn b64str_to_address(s: &str, url_safe: bool) -> anyhow::Result<Address> {
    let config = if url_safe { &URL_SAFE_NO_PAD } else { &URL_STD_NO_PAD };
    let buf = base64::decode_engine(s, config)?;
    Address::read_from(&mut &buf[..]).await.map_err(|e| e.into())
}

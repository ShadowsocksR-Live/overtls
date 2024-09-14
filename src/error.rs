use bytes::Bytes;
use socks5_impl::protocol::Address;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("AddrParse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("tokio::sync::mpsc::error::SendError {0}")]
    MpscSend(#[from] tokio::sync::mpsc::error::SendError<()>),

    #[error("tokio::sync::broadcast::Sender::SendError {0}")]
    BroadcastSend(#[from] tokio::sync::broadcast::error::SendError<(Bytes, Address, Address)>),

    #[error("tokio::sync::mpsc::error::SendError {0}")]
    MpscSendVec(#[from] tokio::sync::mpsc::error::SendError<Vec<u8>>),

    #[error("http::header::ToStrError {0}")]
    HeaderToStr(#[from] http::header::ToStrError),

    #[error("tungstenite::error::Error {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::error::Error),

    #[error("reqwest::Error {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("rustls::pki_types::InvalidDnsNameError {0}")]
    InvalidDnsName(#[from] rustls::pki_types::InvalidDnsNameError),

    #[error("tokio_rustls::rustls::Error {0}")]
    TokioRustls(#[from] tokio_rustls::rustls::Error),

    #[error("httparse::Error {0}")]
    Httparse(#[from] httparse::Error),

    #[error("url::Url::ParseError {0}")]
    UrlParse(#[from] url::ParseError),

    #[cfg(target_os = "android")]
    #[error("jni::errors::Error {0}")]
    Jni(#[from] jni::errors::Error),

    #[cfg(unix)]
    #[error("daemonize::Error {0}")]
    Daemonize(#[from] daemonize::Error),

    #[error("std::str::Utf8Error {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("FromUtf8Error {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error("ParseIntError {0}")]
    FromParseIntError(#[from] std::num::ParseIntError),

    #[error("socks5_impl::Error {0}")]
    Socks5(#[from] socks5_impl::Error),

    #[error("std::ffi::NulError {0}")]
    Nul(#[from] std::ffi::NulError),

    #[error("BoxError {0}")]
    BoxError(#[from] BoxError),

    #[error("String error: {0}")]
    String(String),
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        }
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::String(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::String(s)
    }
}

impl From<&String> for Error {
    fn from(s: &String) -> Self {
        Error::String(s.to_string())
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Result<T, E = Error> = std::result::Result<T, E>;

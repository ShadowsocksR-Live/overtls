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
    UdpWakerSend(#[from] tokio::sync::mpsc::error::SendError<Vec<u8>>),

    #[error("http::header::ToStrError {0}")]
    HeaderToStr(#[from] http::header::ToStrError),

    #[error("tungstenite::error::Error {0}")]
    Tungstenite(#[from] tungstenite::error::Error),

    #[error("reqwest::Error {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("rustls::error::Error {0}")]
    Rustls(#[from] rustls::Error),

    #[error("tokio_rustls::rustls::client::InvalidDnsNameError {0}")]
    InvalidDnsName(#[from] tokio_rustls::rustls::client::InvalidDnsNameError),

    #[error("httparse::Error {0}")]
    Httparse(#[from] httparse::Error),

    #[error("url::Url::ParseError {0}")]
    UrlParse(#[from] url::ParseError),

    #[cfg(target_os = "android")]
    #[error("jni::errors::Error {0}")]
    Jni(#[from] jni::errors::Error),

    #[error("std::str::Utf8Error {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("&str error: {0}")]
    Str(String),

    #[error("String error: {0}")]
    String(String),

    #[error("&String error: {0}")]
    RefString(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Str(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::String(s)
    }
}

impl From<&String> for Error {
    fn from(s: &String) -> Self {
        Error::RefString(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

use base64::{engine::general_purpose, Engine as _};

/// The base64 encoding engine to use when encoding/decoding data.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Base64Engine {
    /// Base64 Standard
    Standard,
    /// Base64 StandardNoPad
    StandardNoPad,
    /// Base64 UrlSafe
    UrlSafe,
    /// Base64 UrlSafeNoPad
    UrlSafeNoPad,
}

pub(crate) fn base64_encode(bytes: &[u8], engine: Base64Engine) -> String {
    match engine {
        Base64Engine::Standard => general_purpose::STANDARD.encode(bytes),
        Base64Engine::StandardNoPad => general_purpose::STANDARD_NO_PAD.encode(bytes),
        Base64Engine::UrlSafe => general_purpose::URL_SAFE.encode(bytes),
        Base64Engine::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    }
}

pub(crate) fn base64_decode(b64str: &str, engine: Base64Engine) -> Result<Vec<u8>, base64::DecodeError> {
    match engine {
        Base64Engine::Standard => general_purpose::STANDARD.decode(b64str),
        Base64Engine::StandardNoPad => general_purpose::STANDARD_NO_PAD.decode(b64str),
        Base64Engine::UrlSafe => general_purpose::URL_SAFE.decode(b64str),
        Base64Engine::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.decode(b64str),
    }
}

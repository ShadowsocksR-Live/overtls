use tungstenite::{
    client::IntoClientRequest,
    error::{Error, Result, UrlError},
    handshake::client::{generate_key, Request},
};

pub const TARGET_ADDRESS: &str = "Target-Address";
pub const UDP: &str = "UDP";

/// A wrapper around `tungstenite::Url` that allows us to add custom headers.
/// This is useful for passing additional information to the server.
/// For example, we can pass the remote server IP to the server.
/// This is useful for servers that are behind a reverse proxy.
#[derive(Debug, Clone)]
pub struct WeirdUri<'a> {
    pub uri: &'a str,
    pub target_address: Option<String>,
    pub sec_websocket_key: String,
    pub udp: Option<String>,
}

impl<'a> WeirdUri<'a> {
    pub fn new(uri: &'a str, target_address: Option<String>, udp: Option<String>) -> Self {
        Self {
            uri,
            target_address,
            sec_websocket_key: generate_key(),
            udp,
        }
    }
}

impl<'a> IntoClientRequest for WeirdUri<'a> {
    fn into_client_request(self) -> Result<Request> {
        let uri = url::Url::parse(self.uri).map_err(|_| Error::Url(UrlError::NoPathOrQuery))?;

        let host = uri.host_str().ok_or(Error::Url(UrlError::EmptyHostName))?;
        let host = format!("{}:{}", host, uri.port().unwrap_or(80));

        let mut builder = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", self.sec_websocket_key);
        if let Some(ref target_address) = self.target_address {
            if !target_address.is_empty() {
                builder = builder.header(TARGET_ADDRESS, target_address);
            }
        }
        if let Some(ref udp) = self.udp {
            if !udp.is_empty() {
                builder = builder.header(UDP, udp);
            }
        }
        let req = builder.uri(uri.as_str()).body(())?;
        Ok(req)
    }
}

impl std::fmt::Display for WeirdUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(req) = self.clone().into_client_request() {
            write!(f, "{:?}", req)
        } else {
            write!(f, "{}", self.uri)
        }
    }
}

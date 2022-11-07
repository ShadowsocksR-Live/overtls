use tungstenite::{
    client::IntoClientRequest,
    error::{Error, Result, UrlError},
    handshake::client::{generate_key, Request},
};

const TARGET_ADDRESS_STR: &str = "Target-Address";

/// A wrapper around `tungstenite::Url` that allows us to add custom headers.
/// This is useful for passing additional information to the server.
/// For example, we can pass the remote server IP to the server.
/// This is useful for servers that are behind a reverse proxy.
#[derive(Debug, Clone)]
pub struct WeirdUri<'a> {
    pub uri: &'a str,
    pub target_address: Option<String>,
}

impl<'a> WeirdUri<'a> {
    pub fn new(uri: &'a str, target_address: Option<String>) -> Self {
        Self {
            uri,
            target_address,
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
            .header("Sec-WebSocket-Key", generate_key());
        if let Some(ref target_address) = self.target_address {
            if !target_address.is_empty() {
                builder = builder.header(TARGET_ADDRESS_STR, target_address);
            }
        }
        let req = builder.uri(uri.as_str()).body(())?;
        Ok(req)
    }
}

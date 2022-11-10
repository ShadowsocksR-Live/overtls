use log::*;
use std::io::Write;
use tungstenite::{
    client::IntoClientRequest,
    error::{Error, Result, UrlError},
    handshake::client::{generate_key, Request},
};

pub const TARGET_ADDRESS: &str = "Target-Address";

/// A wrapper around `tungstenite::Url` that allows us to add custom headers.
/// This is useful for passing additional information to the server.
/// For example, we can pass the remote server IP to the server.
/// This is useful for servers that are behind a reverse proxy.
#[derive(Debug, Clone)]
pub struct WeirdUri<'a> {
    pub uri: &'a str,
    pub target_address: Option<String>,
    pub sec_websocket_key: String,
}

impl<'a> WeirdUri<'a> {
    pub fn new(uri: &'a str, target_address: Option<String>) -> Self {
        Self {
            uri,
            target_address,
            sec_websocket_key: generate_key(),
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
        let req = builder.uri(uri.as_str()).body(())?;
        Ok(req)
    }
}

impl std::fmt::Display for WeirdUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let req = self.clone().into_client_request().unwrap();
        write!(f, "{:?}", req)
    }
}

impl WeirdUri<'_> {
    /// Verifies and generates a client WebSocket request from the original request and extracts a WebSocket key from it.
    pub fn generate_request(&self) -> anyhow::Result<(Vec<u8>, String)> {
        let mut request: Request = self.clone().into_client_request()?;

        let mut req = Vec::new();
        write!(
            req,
            "GET {path} {version:?}\r\n",
            path = request
                .uri()
                .path_and_query()
                .ok_or(Error::Url(UrlError::NoPathOrQuery))?
                .as_str(),
            version = request.version()
        )?;

        // Headers that must be present in a correct request.
        const KEY_HEADERNAME: &str = "Sec-WebSocket-Key";
        const WEBSOCKET_HEADERS: [&str; 5] = ["Host", "Connection", "Upgrade", "Sec-WebSocket-Version", KEY_HEADERNAME];

        // We must extract a WebSocket key from a properly formed request or fail if it's not present.
        let key = request
            .headers()
            .get(KEY_HEADERNAME)
            .ok_or_else(|| anyhow::anyhow!("Missing header: {}", KEY_HEADERNAME))?
            .to_str()?
            .to_owned();

        // We must check that all necessary headers for a valid request are present. Note that we have to
        // deal with the fact that some apps seem to have a case-sensitive check for headers which is not
        // correct and should not considered the correct behavior, but it seems like some apps ignore it.
        // `http` by default writes all headers in lower-case which is fine (and does not violate the RFC)
        // but some servers seem to be poorely written and ignore RFC.
        //
        // See similar problem in `hyper`: https://github.com/hyperium/hyper/issues/1492
        let headers = request.headers_mut();
        for &header in &WEBSOCKET_HEADERS {
            let value = headers
                .remove(header)
                .ok_or_else(|| anyhow::anyhow!("Missing header: {}", header))?;
            write!(req, "{header}: {value}\r\n", header = header, value = value.to_str()?)?;
        }

        // Now we must ensure that the headers that we've written once are not anymore present in the map.
        // If they do, then the request is invalid (some headers are duplicated there for some reason).
        let insensitive: Vec<String> = WEBSOCKET_HEADERS.iter().map(|h| h.to_ascii_lowercase()).collect();
        for (k, v) in headers {
            let mut name = k.as_str();

            // We have already written the necessary headers once (above) and removed them from the map.
            // If we encounter them again, then the request is considered invalid and error is returned.
            // Note that we can't use `.contains()`, since `&str` does not coerce to `&String` in Rust.
            if insensitive.iter().any(|x| x == name) {
                return Err(anyhow::anyhow!("Duplicate header: {}", name));
            }

            // Relates to the issue of some servers treating headers in a case-sensitive way, please see:
            // https://github.com/snapview/tungstenite-rs/pull/119 (original fix of the problem)
            if name == "sec-websocket-protocol" {
                name = "Sec-WebSocket-Protocol";
            }

            if name == "origin" {
                name = "Origin";
            }

            writeln!(req, "{}: {}\r", name, v.to_str()?)?;
        }

        writeln!(req, "\r")?;
        trace!("Request: {:?}", String::from_utf8_lossy(&req));

        assert_eq!(key, self.sec_websocket_key);

        Ok((req, key))
    }
}

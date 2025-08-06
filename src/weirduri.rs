use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    error::{Error, Result, UrlError},
    handshake::client::{Request, generate_key},
};

pub(crate) const TARGET_ADDRESS: &str = "Target-Address";
pub(crate) const UDP_TUNNEL: &str = "UDP-Tunnel";
pub(crate) const CLIENT_ID: &str = "Client-Id";

/// A wrapper around `tungstenite::Url` that allows us to add custom headers.
/// This is useful for passing additional information to the server.
/// For example, we can pass the remote server IP to the server.
/// This is useful for servers that are behind a reverse proxy.
#[derive(Debug, Clone)]
pub(crate) struct WeirdUri {
    pub(crate) uri: String,
    pub(crate) target_address: Option<String>,
    pub(crate) sec_websocket_key: String,
    pub(crate) udp_tunnel: Option<bool>,
    pub(crate) client_id: Option<String>,
}

impl WeirdUri {
    pub(crate) fn new(uri: &str, target_address: Option<String>, udp_tunnel: Option<bool>, client_id: Option<String>) -> Self {
        Self {
            uri: uri.to_owned(),
            target_address,
            sec_websocket_key: generate_key(),
            udp_tunnel,
            client_id,
        }
    }
}

fn combine_addr_and_port(addr: &url::Host<&str>, port: Option<u16>) -> String {
    match port {
        None => addr.to_string(),
        Some(port) => match addr {
            url::Host::Domain(domain) => format!("{domain}:{port}"),
            url::Host::Ipv4(ip) => format!("{ip}:{port}"),
            url::Host::Ipv6(ip) => format!("[{ip}]:{port}"),
        },
    }
}

impl IntoClientRequest for WeirdUri {
    fn into_client_request(self) -> Result<Request> {
        Request::try_from(self) // self.try_into()
    }
}

impl TryFrom<WeirdUri> for Request {
    type Error = Error;
    fn try_from(value: WeirdUri) -> Result<Self> {
        let uri = url::Url::parse(&value.uri).map_err(|_| Error::Url(UrlError::NoPathOrQuery))?;

        let host = uri.host().ok_or(Error::from(UrlError::EmptyHostName))?;
        let host = combine_addr_and_port(&host, uri.port());

        let mut builder = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", value.sec_websocket_key);
        if let Some(target_address) = &value.target_address
            && !target_address.is_empty()
        {
            builder = builder.header(TARGET_ADDRESS, target_address);
        }
        if let Some(udp_tunnel) = value.udp_tunnel
            && udp_tunnel
        {
            builder = builder.header(UDP_TUNNEL, udp_tunnel.to_string());
        }
        if let Some(client_id) = &value.client_id
            && !client_id.is_empty()
        {
            builder = builder.header(CLIENT_ID, client_id);
        }
        let req = builder.uri(uri.as_str()).body(())?;
        Ok(req)
    }
}

impl std::fmt::Display for WeirdUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(req) = self.clone().into_client_request() {
            write!(f, "{req:?}")
        } else {
            write!(f, "{}", self.uri)
        }
    }
}

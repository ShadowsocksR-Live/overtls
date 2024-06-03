use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

pub(crate) const TEST_TIMEOUT_SECS: u64 = 10;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(
        rename(deserialize = "server_settings", serialize = "server_settings"),
        skip_serializing_if = "Option::is_none"
    )]
    pub server: Option<Server>,
    #[serde(
        rename(deserialize = "client_settings", serialize = "client_settings"),
        skip_serializing_if = "Option::is_none"
    )]
    pub client: Option<Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub tunnel_path: TunnelPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_timeout_secs: Option<u64>,
    #[serde(skip)]
    pub is_server: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TunnelPath {
    Single(String),
    Multiple(Vec<String>),
}

impl std::fmt::Display for TunnelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelPath::Single(s) => write!(f, "{}", s),
            TunnelPath::Multiple(v) => {
                let mut s = String::new();
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(item);
                }
                write!(f, "{}", s)
            }
        }
    }
}

impl Default for TunnelPath {
    fn default() -> Self {
        TunnelPath::Single("/tunnel/".to_string())
    }
}

impl TunnelPath {
    pub fn is_empty(&self) -> bool {
        match self {
            TunnelPath::Single(s) => s.is_empty(),
            TunnelPath::Multiple(v) => v.is_empty(),
        }
    }

    pub fn standardize(&mut self) {
        if self.is_empty() {
            *self = TunnelPath::default();
        }
        match self {
            TunnelPath::Single(s) => {
                *s = format!("/{}/", s.trim().trim_matches('/'));
            }
            TunnelPath::Multiple(v) => {
                v.iter_mut().for_each(|s| {
                    *s = s.trim().trim_matches('/').to_string();
                    if !s.is_empty() {
                        *s = format!("/{}/", s);
                    }
                });
                v.retain(|s| !s.is_empty());
            }
        }
    }

    pub fn extract(&self) -> Vec<&str> {
        match self {
            TunnelPath::Single(s) => vec![s],
            TunnelPath::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Server {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manage_clients: Option<ManageClients>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certfile: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_addr: Option<String>,
    pub listen_host: String,
    pub listen_port: u16,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ManageClients {
    pub enable: Option<bool>,
    pub webapi_url: Option<String>,
    pub webapi_token: Option<String>,
    pub node_id: Option<usize>,
    #[serde(rename(deserialize = "api_update_time", serialize = "api_update_time"))]
    pub api_update_interval_secs: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Client {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub server_host: String,
    pub server_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cafile: Option<String>,
    pub listen_host: String,
    pub listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_password: Option<String>,
    #[serde(skip)]
    pub cache_dns: bool,
    #[serde(skip)]
    pub(crate) server_ip_addr: Option<SocketAddr>,
}

impl Client {
    pub fn certificate_content(&self) -> Option<String> {
        self.cafile.as_ref().and_then(|cert| Self::_certificate_content(cert))
    }

    fn _certificate_content(cert: &str) -> Option<String> {
        const BEGIN_CERT: &str = "-----BEGIN CERTIFICATE-----";
        if PathBuf::from(cert).exists() {
            std::fs::read_to_string(cert)
                .ok()
                .filter(|s| !s.is_empty() && s.starts_with(BEGIN_CERT) && s.len() > 100)
        } else if !cert.is_empty() && cert.starts_with(BEGIN_CERT) && cert.len() > 100 {
            Some(cert.to_string())
        } else {
            None
        }
    }

    pub fn export_certificate(&self, path: &str) -> Result<()> {
        match self.certificate_content() {
            Some(cert) => std::fs::write(path, cert).map_err(|e| e.into()),
            None => Err(Error::from("certificate not exists")),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Config {
            remarks: None,
            method: None,
            password: None,
            tunnel_path: TunnelPath::default(),
            server: None,
            client: None,
            test_timeout_secs: Some(TEST_TIMEOUT_SECS),
            is_server: false,
        }
    }

    pub fn certificate_content(&self) -> Option<String> {
        self.client.as_ref().and_then(|c| c.certificate_content())
    }

    pub fn export_certificate(&self, path: &str) -> Result<()> {
        self.client.as_ref().ok_or(Error::from("no client"))?.export_certificate(path)
    }

    pub fn manage_clients(&self) -> bool {
        let f = |s: &Server| {
            let f2 = |c: &ManageClients| c.enable.unwrap_or(false);
            s.manage_clients.as_ref().map(f2).unwrap_or(false)
        };
        self.server.as_ref().map(f).unwrap_or(false)
    }

    pub fn webapi_url(&self) -> Option<String> {
        let f = |s: &Server| s.manage_clients.as_ref().map(|c| c.webapi_url.clone()).unwrap_or(None);
        self.server.as_ref().map(f).unwrap_or(None)
    }

    pub fn webapi_token(&self) -> Option<String> {
        let f = |s: &Server| {
            let f2 = |c: &ManageClients| c.webapi_token.clone();
            s.manage_clients.as_ref().map(f2).unwrap_or(None)
        };
        self.server.as_ref().map(f).unwrap_or(None)
    }

    pub fn node_id(&self) -> Option<usize> {
        let f = |s: &Server| s.manage_clients.as_ref().map(|c| c.node_id).unwrap_or(None);
        self.server.as_ref().map(f).unwrap_or(None)
    }

    pub fn api_update_interval_secs(&self) -> Option<u64> {
        let f = |s: &Server| {
            let f2 = |c: &ManageClients| c.api_update_interval_secs;
            s.manage_clients.as_ref().map(f2).unwrap_or(None)
        };
        self.server.as_ref().map(f).unwrap_or(None)
    }

    pub fn exist_server(&self) -> bool {
        self.server.is_some()
    }

    pub fn exist_client(&self) -> bool {
        self.client.is_some()
    }

    pub fn forward_addr(&self) -> Option<String> {
        if self.is_server {
            let f = |s: &Server| s.forward_addr.clone();
            let default = Some(format!("http://{}:80", Ipv4Addr::LOCALHOST));
            self.server.as_ref().map(f).unwrap_or(default)
        } else {
            None
        }
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        let unspec = std::net::IpAddr::from(Ipv4Addr::UNSPECIFIED);
        if self.is_server {
            let f = |s: &Server| SocketAddr::new(s.listen_host.parse().unwrap_or(unspec), s.listen_port);
            self.server.as_ref().map(f).ok_or_else(|| "Server listen address is not set".into())
        } else {
            let f = |c: &Client| SocketAddr::new(c.listen_host.parse().unwrap_or(unspec), c.listen_port);
            self.client.as_ref().map(f).ok_or_else(|| "Client listen address is not set".into())
        }
    }

    pub fn set_listen_addr(&mut self, addr: std::net::SocketAddr) {
        if self.is_server {
            if let Some(s) = &mut self.server {
                s.listen_host = addr.ip().to_string();
                s.listen_port = addr.port();
            }
        } else if let Some(c) = &mut self.client {
            c.listen_host = addr.ip().to_string();
            c.listen_port = addr.port();
        }
    }

    pub fn disable_tls(&self) -> bool {
        if self.is_server {
            if let Some(s) = &self.server {
                return s.disable_tls.unwrap_or(false);
            }
        } else if let Some(c) = &self.client {
            return c.disable_tls.unwrap_or(false);
        }
        false
    }

    pub fn cache_dns(&self) -> bool {
        self.client.as_ref().map_or(false, |c| c.cache_dns)
    }

    pub fn set_cache_dns(&mut self, cache_dns: bool) {
        if let Some(c) = &mut self.client {
            c.cache_dns = cache_dns;
        }
    }

    pub fn check_correctness(&mut self, is_server: bool) -> Result<()> {
        self.is_server = is_server;
        if self.is_server {
            if self.server.is_none() {
                return Err("Configuration needs server settings".into());
            }
            self.client = None;
        } else {
            if self.client.is_none() {
                return Err("Configuration needs client settings".into());
            }
            self.server = None;
        }

        if self.tunnel_path.is_empty() {
            self.tunnel_path = TunnelPath::default();
        } else {
            self.tunnel_path.standardize();
        }

        if let Some(server) = &mut self.server {
            if server.listen_host.is_empty() {
                server.listen_host = Ipv4Addr::UNSPECIFIED.to_string();
            }
            if server.listen_port == 0 {
                server.listen_port = 443;
            }
        }
        if let Some(client) = &mut self.client {
            let server_host = client.server_host.clone();
            let server_host = match (server_host.is_empty(), client.server_domain.clone()) {
                (true, Some(domain)) => match domain.is_empty() {
                    true => return Err(Error::from("We need server host in client settings")),
                    false => domain,
                },
                (true, None) => return Err(Error::from("We need server host in client settings")),
                (false, _) => server_host,
            };
            if client.server_host.is_empty() {
                client.server_host.clone_from(&server_host);
            }
            if client.server_domain.is_none() || client.server_domain.as_ref().unwrap_or(&"".to_string()).is_empty() {
                client.server_domain = Some(server_host.clone());
            }

            if client.server_port == 0 {
                client.server_port = 443;
            }

            if !self.is_server {
                let mut addr = (server_host, client.server_port).to_socket_addrs()?;
                let addr = addr.next().ok_or("address not available")?;
                {
                    let timeout = std::time::Duration::from_secs(self.test_timeout_secs.unwrap_or(TEST_TIMEOUT_SECS));
                    crate::tcp_stream::std_create(addr, Some(timeout))?;
                }
                if client.listen_host.is_empty() {
                    client.listen_host = if addr.is_ipv4() {
                        Ipv4Addr::LOCALHOST.to_string()
                    } else {
                        Ipv6Addr::LOCALHOST.to_string()
                    };
                }
                client.server_ip_addr = Some(addr);
            }
        }
        Ok(())
    }

    /// load from overtls config file
    pub fn from_config_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let f = std::fs::File::open(&path)?;
        let config: Config = serde_json::from_reader(f)?;
        Ok(config)
    }

    /// load from `ssr://...` style url
    pub fn from_ssr_url(url: &str) -> Result<Self> {
        let engine = crate::Base64Engine::UrlSafeNoPad;
        let url = url.trim_start_matches("ssr://");
        let url = crate::base64_decode(url, engine)?;
        let url = String::from_utf8(url)?;
        // split string by `/?`
        let mut parts = url.split("/?");

        // split first part by `:` and collect to vector
        let mut parts0 = parts.next().ok_or("url is invalid")?.split(':').collect::<Vec<&str>>();
        // check if parts length is less than 6
        if parts0.len() < 6 {
            return Err("url is invalid".into());
        }
        let host = parts0.remove(0);
        let port = parts0.remove(0);
        let protocol = parts0.remove(0);
        let method = parts0.remove(0); // none is default
        let obfs = parts0.remove(0);
        let password = String::from_utf8(crate::base64_decode(parts0.remove(0), engine)?)?;

        if method != "none" {
            return Err("method is not none".into());
        }
        if obfs != "plain" {
            return Err("obfs is not plain".into());
        }
        if protocol != "origin" {
            return Err("protocol is not origin".into());
        }
        let port = port.parse::<u16>()?;

        // split second part by `&` and collect to vector
        let parts1 = parts.next().ok_or("url is invalid")?.split('&').collect::<Vec<&str>>();
        // for each element in parts1, split by `=` and collect to a hashmap
        let mut map = std::collections::HashMap::new();
        for part in parts1 {
            let mut kv = part.split('=');
            let k = kv.next().ok_or("url is invalid")?;
            let v = kv.next().ok_or("url is invalid")?;
            map.insert(k, v);
        }

        let ot_enable = map.get("ot_enable").map_or("0".to_string(), |r| r.to_string());
        if ot_enable != "1" {
            return Err("ot_enable is not 1".into());
        }
        let remarks = map.get("remarks").and_then(|r| match crate::base64_decode(r, engine) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(string) => Some(string),
                Err(_) => None,
            },
            Err(_) => None,
        });
        let ot_domain = map.get("ot_domain").and_then(|r| match crate::base64_decode(r, engine) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(string) => Some(string),
                Err(_) => None,
            },
            Err(_) => None,
        });
        let ot_path = map.get("ot_path").ok_or("ot_path is not set")?;
        let ot_path = String::from_utf8(crate::base64_decode(ot_path, engine)?)?;

        let ot_cert = map
            .get("ot_cert")
            .and_then(|r| crate::base64_decode(r, engine).ok())
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .filter(|s| !s.is_empty());

        let client = Client {
            server_host: host.to_string(),
            server_port: port,
            server_domain: ot_domain,
            cafile: ot_cert,
            ..Client::default()
        };

        let mut config = Config::new();
        config.password = Some(password);
        config.method = Some(method.to_string());
        config.remarks = remarks;
        config.tunnel_path = TunnelPath::Single(ot_path);
        config.client = Some(client);

        Ok(config)
    }

    pub fn generate_ssr_url(&self) -> Result<String> {
        let client = self.client.as_ref().ok_or(Error::from("client is not set"))?;
        let engine = crate::Base64Engine::UrlSafeNoPad;
        let method = self.method.as_ref().map_or("none".to_string(), |m| m.clone());
        let password = self.password.as_ref().map_or("password".to_string(), |p| p.clone());
        let password = crate::base64_encode(password.as_bytes(), engine);
        let remarks = self.remarks.as_ref().map_or("remarks".to_string(), |r| r.clone());
        let remarks = crate::base64_encode(remarks.as_bytes(), engine);
        let domain = client.server_domain.as_ref().map_or("".to_string(), |d| d.clone());
        let domain = crate::base64_encode(domain.as_bytes(), engine);
        let err = "tunnel_path is not set";
        let tunnel_path = crate::base64_encode(self.tunnel_path.extract().first().ok_or(err)?.as_bytes(), engine);
        let host = &client.server_host;
        let port = client.server_port;

        let mut url = format!("{host}:{port}:origin:{method}:plain:{password}/?remarks={remarks}&ot_enable=1");
        url.push_str(&format!("&ot_domain={domain}&ot_path={tunnel_path}"));

        if let Some(ref ca) = client.certificate_content() {
            let ca = crate::base64_encode(ca.as_bytes(), engine);
            url.push_str(&format!("&ot_cert={}", ca));
        }

        Ok(format!("ssr://{}", crate::base64_encode(url.as_bytes(), engine)))
    }
}

pub(crate) fn generate_ssr_url<P>(path: P) -> Result<String>
where
    P: AsRef<std::path::Path>,
{
    let config = Config::from_config_file(path)?;
    if config.certificate_content().is_some() {
        log::warn!("Certificate content exists!");
    }
    config.generate_ssr_url()
}

#[test]
fn test_config() {
    let mut config = Config::new();
    config.tunnel_path = TunnelPath::Single("/tunnel/".to_string());
    config.remarks = Some("remarks".to_string());
    config.method = Some("none".to_string());
    config.password = Some("password".to_string());

    let client = Client {
        server_host: "baidu.com".to_string(),
        server_port: 443,
        listen_host: "127.0.0.1".to_string(),
        listen_port: 0,
        // server_domain: Some("baidu.com".to_string()),
        ..Client::default()
    };
    config.client = Some(client);

    config.check_correctness(false).unwrap();

    let qrcode = config.generate_ssr_url().unwrap();
    println!("{:?}", qrcode);

    let config = Config::from_ssr_url(&qrcode).unwrap();
    println!("{:?}", config);
}

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(rename(deserialize = "server_settings", serialize = "server_settings"))]
    pub server: Option<Server>,
    #[serde(rename(deserialize = "client_settings", serialize = "client_settings"))]
    pub client: Option<Client>,
    pub remarks: Option<String>,
    pub method: Option<String>,
    pub password: Option<String>,
    pub tunnel_path: String,
    #[serde(skip)]
    pub test_timeout_secs: u64,
    #[serde(skip)]
    pub is_server: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Server {
    pub disable_tls: Option<bool>,
    pub manage_clients: Option<ManageClients>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
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
    pub disable_tls: Option<bool>,
    pub client_id: Option<String>,
    pub server_host: String,
    pub server_port: u16,
    pub server_domain: Option<String>,
    pub cafile: Option<PathBuf>,
    pub listen_host: String,
    pub listen_port: u16,
    pub listen_user: Option<String>,
    pub listen_password: Option<String>,
    #[serde(skip)]
    pub cache_dns: bool,
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
            tunnel_path: "/tunnel/".to_string(),
            server: None,
            client: None,
            test_timeout_secs: 5,
            is_server: false,
        }
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
            self.client = None;
        } else {
            self.server = None;
        }
        if let (None, None) = (&self.server, &self.client) {
            return Err("Need server or client settings".into());
        }

        if self.test_timeout_secs == 0 {
            self.test_timeout_secs = 5;
        }
        if self.tunnel_path.is_empty() {
            self.tunnel_path = "/tunnel/".to_string();
        } else {
            self.tunnel_path = format!("/{}/", self.tunnel_path.trim().trim_matches('/'));
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
            if client.server_host.is_empty() {
                return Err(Error::from("We need server_host in client settings"));
            }
            if client.server_port == 0 {
                client.server_port = 443;
            }
            if client.server_domain.is_none() || client.server_domain.as_ref().unwrap_or(&"".to_string()).is_empty() {
                client.server_domain = Some(client.server_host.clone());
            }

            if !self.is_server {
                let mut addr = (client.server_host.clone(), client.server_port).to_socket_addrs()?;
                let addr = addr.next().ok_or("address not exist")?;
                #[cfg(not(target_os = "android"))]
                {
                    let timeout = std::time::Duration::from_secs(self.test_timeout_secs);
                    std::net::TcpStream::connect_timeout(&addr, timeout)?;
                }
                if client.listen_host.is_empty() {
                    client.listen_host = if addr.is_ipv4() {
                        Ipv4Addr::LOCALHOST.to_string()
                    } else {
                        Ipv6Addr::LOCALHOST.to_string()
                    };
                }
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

    pub fn generate_ssr_qrcode(&self) -> Result<String> {
        let client = self.client.as_ref().ok_or(Error::from("client is not set"))?;
        let engine = crate::Base64Engine::UrlSafeNoPad;
        let method = self.method.as_ref().map_or("none".to_string(), |m| m.clone());
        let password = self.password.as_ref().map_or("password".to_string(), |p| p.clone());
        let password = crate::base64_encode(password.as_bytes(), engine);
        let remarks = self.remarks.as_ref().map_or("remarks".to_string(), |r| r.clone());
        let remarks = crate::base64_encode(remarks.as_bytes(), engine);
        let domain = client.server_domain.as_ref().map_or("".to_string(), |d| d.clone());
        let domain = crate::base64_encode(domain.as_bytes(), engine);
        let tunnel_path = crate::base64_encode(self.tunnel_path.as_bytes(), engine);
        let host = &client.server_host;
        let port = client.server_port;

        let url = format!(
            "{host}:{port}:origin:{method}:plain:{password}/?remarks={remarks}&ot_enable=1&ot_domain={domain}&ot_path={tunnel_path}"
        );
        Ok(format!("ssr://{}", crate::base64_encode(url.as_bytes(), engine)))
    }
}

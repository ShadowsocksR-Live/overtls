#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    pub method: String,
    pub password: String,
    pub tunnel_path: String,
    #[serde(rename(deserialize = "server_settings", serialize = "server_settings"))]
    pub server: Option<Server>,
    #[serde(rename(deserialize = "client_settings", serialize = "client_settings"))]
    pub client: Option<Client>,
    #[serde(skip)]
    pub test_timeout_secs: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Server {
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub listen_host: String,
    pub listen_port: u16,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Client {
    pub server_host: String,
    pub server_port: u16,
    pub server_domain: Option<String>,
    pub cafile: Option<PathBuf>,
    pub listen_host: String,
    pub listen_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Config {
            method: "none".to_string(),
            password: "password".to_string(),
            tunnel_path: "/tunnel/".to_string(),
            server: None,
            client: None,
            test_timeout_secs: 5,
        }
    }

    pub fn exist_server(&self) -> bool {
        self.server.is_some()
    }

    pub fn exist_client(&self) -> bool {
        self.client.is_some()
    }

    pub fn check_correctness(&mut self) -> anyhow::Result<()> {
        if self.test_timeout_secs == 0 {
            self.test_timeout_secs = 5;
        }
        if self.method.is_empty() {
            self.method = "none".to_string();
        }
        if self.password.is_empty() {
            self.password = "password".to_string();
        }
        if self.tunnel_path.is_empty() {
            self.tunnel_path = "/tunnel/".to_string();
        }
        if !self.exist_server() && !self.exist_client() {
            return Err(anyhow::anyhow!("Need server or client settings"));
        }
        if self.exist_server() {
            let server = self.server.as_mut();
            let server = server.ok_or_else(|| anyhow::anyhow!("server settings"))?;

            if server.listen_host.is_empty() {
                server.listen_host = "0.0.0.0".to_string();
            }
            if server.listen_port == 0 {
                server.listen_port = 443;
            }
        }
        if self.exist_client() {
            let client = self.client.as_mut();
            let client = client.ok_or_else(|| anyhow::anyhow!("client settings"))?;
            if client.server_host.is_empty() {
                return Err(anyhow::anyhow!("We need server_host in client settings"));
            }
            if client.server_port == 0 {
                client.server_port = 443;
            }
            if client.server_domain.is_none() || client.server_domain.as_ref().unwrap().is_empty() {
                client.server_domain = Some(client.server_host.clone());
            }
            if client.listen_host.is_empty() {
                client.listen_host = "127.0.0.1".to_string();
            }
            if client.listen_port == 0 {
                client.listen_port = 1080;
            }

            let addr = format!("{}:{}", client.server_host, client.server_port);
            let mut addr = addr.to_socket_addrs()?;
            let addr = addr.next().ok_or_else(|| anyhow::anyhow!("address"))?;
            let timeout = std::time::Duration::from_secs(self.test_timeout_secs);
            let _ = TcpStream::connect_timeout(&addr, timeout)?;
            client.server_host = addr.ip().to_string();
        }
        Ok(())
    }
}

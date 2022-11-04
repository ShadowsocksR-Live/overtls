#![allow(dead_code)]

use serde::{Deserialize, Serialize};
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
    pub verbose: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Server {
    pub certfile: PathBuf,
    pub keyfile: PathBuf,
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

impl Config {
    pub fn new() -> Self {
        Config {
            method: "none".to_string(),
            password: "password".to_string(),
            tunnel_path: "/tunnel".to_string(),
            server: None,
            client: None,
            verbose: false,
        }
    }

    pub fn is_server(&self) -> bool {
        self.server.is_some()
    }

    pub fn is_client(&self) -> bool {
        self.client.is_some()
    }

    pub fn check_correctness(&mut self) -> anyhow::Result<()> {
        if self.method.is_empty() {
            self.method = "none".to_string();
        }
        if self.password.is_empty() {
            self.password = "password".to_string();
        }
        if self.tunnel_path.is_empty() {
            self.tunnel_path = "/tunnel".to_string();
        }
        if !self.is_server() && !self.is_client() {
            return Err(anyhow::anyhow!("Need server or client settings"));
        }
        if self.is_server() {
            let server = self.server.as_mut();
            let server = server.ok_or_else(|| anyhow::anyhow!("server settings"))?;

            let certfile = server.certfile.to_str();
            let certfile = certfile.ok_or_else(|| anyhow::anyhow!("certfile"))?;
            if certfile.is_empty() {
                return Err(anyhow::anyhow!("We need certfile in server settings"));
            }

            let keyfile = server.keyfile.to_str();
            let keyfile = keyfile.ok_or_else(|| anyhow::anyhow!("keyfile"))?;
            if keyfile.is_empty() {
                return Err(anyhow::anyhow!("We need keyfile in server settings"));
            }
            if server.listen_host.is_empty() {
                server.listen_host = "0.0.0.0".to_string();
            }
            if server.listen_port == 0 {
                server.listen_port = 443;
            }
        }
        if self.is_client() {
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
        }
        Ok(())
    }
}

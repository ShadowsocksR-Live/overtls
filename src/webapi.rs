use crate::config::Config;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WebApi {
    pub config: Config,
    pub client: reqwest::Client,
}

impl WebApi {
    pub fn new(config: &Config) -> Self {
        let client = reqwest::Client::new();
        let config = config.clone();
        Self { config, client }
    }

    pub async fn get_api(&self, uri: &str, params: &str) -> anyhow::Result<String> {
        let webapi_url = self.config.webapi_url().ok_or_else(|| anyhow::anyhow!(""))?;
        let webapi_token = self.config.webapi_token().ok_or_else(|| anyhow::anyhow!(""))?;
        let mut url = format!("{webapi_url}/mod_mu/{uri}?key={webapi_token}");
        if !params.is_empty() {
            url = format!("{url}&{params}");
        }
        let response = self.client.get(&url).send().await?;
        if response.status() != 200 {
            anyhow::bail!("Server error with status code: {}", response.status());
        }
        let json = response.json::<HashMap<String, String>>().await?;
        if json.len() != 2 {
            anyhow::bail!("Wrong data: {:?}", json);
        }
        if json.get("ret").ok_or_else(|| anyhow::anyhow!(""))? == "0" {
            anyhow::bail!("Wrong data: {:?}", json);
        }
        Ok(json.get("data").ok_or_else(|| anyhow::anyhow!(""))?.to_string())
    }

    pub async fn post_api(&self, uri: &str, params: &str, json: &str) -> anyhow::Result<String> {
        let webapi_url = self.config.webapi_url().ok_or_else(|| anyhow::anyhow!(""))?;
        let webapi_token = self.config.webapi_token().ok_or_else(|| anyhow::anyhow!(""))?;
        let mut url = format!("{webapi_url}/mod_mu/{uri}?key={webapi_token}");
        if !params.is_empty() {
            url = format!("{url}&{params}");
        }
        let response = self.client.post(&url).json(json).send().await?;
        if response.status() != 200 {
            anyhow::bail!("Server error with status code: {}", response.status());
        }
        let json = response.json::<HashMap<String, String>>().await?;
        if json.len() != 2 {
            anyhow::bail!("Wrong data: {:?}", json);
        }
        if json.get("ret").ok_or_else(|| anyhow::anyhow!(""))? == "0" {
            anyhow::bail!("Wrong data: {:?}", json);
        }
        Ok(json.get("data").ok_or_else(|| anyhow::anyhow!(""))?.to_string())
    }
}

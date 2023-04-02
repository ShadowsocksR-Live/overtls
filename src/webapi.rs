#![allow(dead_code)]

use crate::{
    config::Config,
    error::{Error, Result},
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(crate) struct WebApi {
    pub(crate) config: Config,
    pub(crate) client: reqwest::Client,
}

impl WebApi {
    pub(crate) fn new(config: &Config) -> Self {
        let client = reqwest::Client::new();
        let config = config.clone();
        Self { config, client }
    }

    pub(crate) async fn get_api(&self, uri: &str, params: &str) -> Result<String> {
        let webapi_url = self.config.webapi_url().ok_or_else(|| Error::from(""))?;
        let webapi_token = self.config.webapi_token().ok_or_else(|| Error::from(""))?;
        let mut url = format!("{webapi_url}/mod_mu/{uri}?key={webapi_token}");
        if !params.is_empty() {
            url = format!("{url}&{params}");
        }
        let response = self.client.get(&url).send().await?;
        if response.status() != 200 {
            return Err(Error::from(format!("{}", response.status())));
        }
        let json = response.json::<HashMap<String, String>>().await?;
        if json.len() != 2 {
            return Err(Error::from(format!("Wrong data: {:?}", json)));
        }
        if json.get("ret").ok_or_else(|| Error::from(""))? == "0" {
            return Err(Error::from(format!("Wrong data: {:?}", json)));
        }
        Ok(json.get("data").ok_or_else(|| Error::from(""))?.to_string())
    }

    pub(crate) async fn post_api(&self, uri: &str, params: &str, json: &str) -> Result<String> {
        let webapi_url = self.config.webapi_url().ok_or_else(|| Error::from(""))?;
        let webapi_token = self.config.webapi_token().ok_or_else(|| Error::from(""))?;
        let mut url = format!("{webapi_url}/mod_mu/{uri}?key={webapi_token}");
        if !params.is_empty() {
            url = format!("{url}&{params}");
        }
        let response = self.client.post(&url).json(json).send().await?;
        if response.status() != 200 {
            return Err(Error::from(format!("{}", response.status())));
        }
        let json = response.json::<HashMap<String, String>>().await?;
        if json.len() != 2 {
            return Err(Error::from(format!("Wrong data: {:?}", json)));
        }
        if json.get("ret").ok_or_else(|| Error::from(""))? == "0" {
            return Err(Error::from(format!("Wrong data: {:?}", json)));
        }
        Ok(json.get("data").ok_or_else(|| Error::from(""))?.to_string())
    }
}

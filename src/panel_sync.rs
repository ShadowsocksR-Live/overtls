use crate::{
    error::{Error, Result},
    traffic_audit::TrafficAuditPtr,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct PanelSyncConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webapi_url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webapi_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(deserialize = "api_update_time", serialize = "api_update_time"))]
    pub api_update_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct SyncUser {
    client_id: Uuid,
    #[serde(default = "default_true")]
    enable: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub(crate) struct PanelSyncClient {
    config: PanelSyncConfig,
    client: reqwest::Client,
    reported_traffic: HashMap<Uuid, (u64, u64)>,
}

impl PanelSyncClient {
    pub(crate) fn new(config: &PanelSyncConfig) -> Self {
        Self {
            config: config.clone(),
            client: reqwest::Client::new(),
            reported_traffic: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self, traffic_audit: TrafficAuditPtr, quit: crate::CancellationToken) -> Result<()> {
        let interval_secs = self.config.api_update_interval_secs.unwrap_or(60).max(10);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = quit.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.sync_once(&traffic_audit).await {
                        log::warn!("panel sync failed: {e}");
                    }
                    if let Err(e) = self.report_traffic_once(&traffic_audit).await {
                        log::warn!("panel traffic report failed: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    async fn sync_once(&mut self, traffic_audit: &TrafficAuditPtr) -> Result<()> {
        let users = self.fetch_sync_payload().await?;

        let existing_clients = traffic_audit.lock().await.get_client_list();
        let mut seen_clients = HashSet::new();

        log::trace!("syncing users from panel: {:?}", users);

        for user in users {
            let client_id = user.client_id;

            seen_clients.insert(client_id);
            let mut audit = traffic_audit.lock().await;
            audit.add_client(&client_id);
            audit.set_enable_of(&client_id, user.enable);
        }

        for client_id in existing_clients {
            if !seen_clients.contains(&client_id) {
                traffic_audit.lock().await.remove_client(&client_id);
                self.reported_traffic.remove(&client_id);
            }
        }

        Ok(())
    }

    async fn report_traffic_once(&mut self, traffic_audit: &TrafficAuditPtr) -> Result<()> {
        let client_ids = traffic_audit.lock().await.get_client_list();
        let mut payload = Vec::new();
        let mut current_traffic = HashMap::new();

        for client_id in client_ids {
            let client_id_clone = client_id;
            let (upstream, downstream) = {
                let audit = traffic_audit.lock().await;
                let upstream = audit.get_upstream_traffic_of(&client_id);
                let downstream = audit.get_downstream_traffic_of(&client_id);
                (upstream, downstream)
            };

            let last_reported = self.reported_traffic.get(&client_id).copied().unwrap_or((0, 0));
            let delta_upstream = upstream.saturating_sub(last_reported.0);
            let delta_downstream = downstream.saturating_sub(last_reported.1);

            if delta_upstream == 0 && delta_downstream == 0 {
                continue;
            }

            current_traffic.insert(client_id_clone, (upstream, downstream));

            let mut record = serde_json::Map::new();
            record.insert("client_id".to_string(), serde_json::json!(client_id_clone));
            record.insert("u".to_string(), serde_json::json!(delta_upstream));
            record.insert("d".to_string(), serde_json::json!(delta_downstream));

            payload.push(serde_json::Value::Object(record));
        }

        if payload.is_empty() {
            return Ok(());
        }

        let body = serde_json::json!({
            "data": payload,
        });

        let node_id = self.config.node_id.ok_or_else(|| Error::from("panel sync node_id not set"))?;
        // url like: {webapi_url}/mod_mu/users/traffic?key={webapi_token}&node_id={node_id}
        let url = self.build_url("users/traffic", &[("node_id", node_id.to_string())])?;
        let response = self.client.post(url).json(&body).send().await?;
        let r: serde_json::Value = self.parse_payload(response).await?;

        log::trace!("reported traffic post {body:?} response: {r:?}");

        for (client_id, &(upstream, downstream)) in &current_traffic {
            self.reported_traffic.insert(*client_id, (upstream, downstream));
        }

        Ok(())
    }

    async fn fetch_sync_payload(&self) -> Result<Vec<SyncUser>> {
        let node_id = self.config.node_id.ok_or_else(|| Error::from("panel sync node_id not set"))?;
        // url like: {webapi_url}/mod_mu/users?key={webapi_token}&node_id={node_id}
        let url = self.build_url("users", &[("node_id", node_id.to_string())])?;
        let response = self.client.get(url).send().await?;
        let users = self.parse_payload(response).await?;
        Ok(users)
    }

    async fn parse_payload<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> Result<T> {
        if response.status() != 200 {
            return Err(Error::from(format!("{}", response.status())));
        }

        let value = response.json::<serde_json::Value>().await?;
        if value.get("ret").and_then(|v| v.as_i64()).unwrap_or_default() == 0 {
            return Err(Error::from(format!("Wrong data: {value:?}")));
        }

        let data = value.get("data").cloned().unwrap_or(value);
        Ok(serde_json::from_value(data)?)
    }

    /// build url like: {webapi_url}/mod_mu/{action}?key={webapi_token}&{params}
    fn build_url(&self, action: &str, params: &[(&str, String)]) -> std::io::Result<String> {
        let base = self
            .config
            .webapi_url
            .as_ref()
            .ok_or_else(|| std::io::Error::other("webapi_url not set"))?
            .as_str()
            .trim_end_matches('/')
            .to_string();
        let token = self.config.webapi_token.clone().unwrap_or_default();
        let mut url = base;
        url.push_str("/mod_mu/");
        url.push_str(action);
        url.push_str("?key=");
        url.push_str(&token);
        for (key, value) in params {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        }
        Ok(url)
    }
}

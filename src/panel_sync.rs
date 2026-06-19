use crate::{
    config::Config,
    error::{Error, Result},
    traffic_audit::TrafficAuditPtr,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Deserialize)]
struct SyncUser {
    client_id: String,
    #[serde(default = "default_true")]
    enable: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SyncPayload {
    #[serde(default)]
    users: Vec<SyncUser>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub(crate) struct PanelSyncClient {
    config: Config,
    client: reqwest::Client,
    reported_traffic: HashMap<String, (u64, u64)>,
}

impl PanelSyncClient {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
            client: reqwest::Client::new(),
            reported_traffic: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self, traffic_audit: TrafficAuditPtr, quit: crate::CancellationToken) -> Result<()> {
        let interval_secs = self.config.api_update_interval_secs().unwrap_or(60).max(10);
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
        let payload = self.fetch_sync_payload().await?;

        let existing_clients = traffic_audit.lock().await.get_client_list();
        let mut seen_clients = HashSet::new();

        for user in payload.users {
            seen_clients.insert(user.client_id.clone());
            let mut audit = traffic_audit.lock().await;
            audit.add_client(&user.client_id);
            audit.set_enable_of(&user.client_id, user.enable);
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

        for client_id in client_ids {
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

            payload.push((client_id, delta_upstream, delta_downstream, upstream, downstream));
        }

        if payload.is_empty() {
            return Ok(());
        }

        let body = serde_json::json!({
            "data": payload.iter().map(|(client_id, delta_upstream, delta_downstream, _, _)| {
                serde_json::json!({
                    "client_id": client_id,
                    "u": delta_upstream,
                    "d": delta_downstream,
                })
            }).collect::<Vec<_>>()
        });

        let node_id = self.config.node_id().ok_or_else(|| Error::from("panel sync node_id not set"))?;
        // url like: {webapi_url}/node/api/v1/user/traffic?key={webapi_token}&node_id={node_id}
        let url = self.build_url("user/traffic", &[("node_id", node_id.to_string())]);
        let response = self.client.post(url).json(&body).send().await?;
        let _: serde_json::Value = self.parse_payload(response).await?;

        for (client_id, _, _, upstream, downstream) in payload {
            self.reported_traffic.insert(client_id, (upstream, downstream));
        }

        Ok(())
    }

    async fn fetch_sync_payload(&self) -> Result<SyncPayload> {
        let node_id = self.config.node_id().ok_or_else(|| Error::from("panel sync node_id not set"))?;
        // url like: {webapi_url}/node/api/v1/getUsers?key={webapi_token}&node_id={node_id}
        let url = self.build_url("getUsers", &[("node_id", node_id.to_string())]);
        let response = self.client.get(url).send().await?;
        let payload = self.parse_payload(response).await?;
        Ok(payload)
    }

    async fn parse_payload<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> Result<T> {
        if response.status() != 200 {
            return Err(Error::from(format!("{}", response.status())));
        }

        let value = response.json::<serde_json::Value>().await?;
        if value.get("ret").and_then(|v| v.as_i64()).unwrap_or(1) == 0 {
            return Err(Error::from(format!("Wrong data: {value:?}")));
        }

        let data = value.get("data").cloned().unwrap_or(value);
        Ok(serde_json::from_value(data)?)
    }

    /// build url like: {webapi_url}/node/api/v1/{action}?key={webapi_token}&{params}
    fn build_url(&self, action: &str, params: &[(&str, String)]) -> String {
        let base = self.config.webapi_url().unwrap_or_default().trim_end_matches('/').to_string();
        let token = self.config.webapi_token().unwrap_or_default();
        let mut url = format!("{base}/node/api/v1/{action}?key={token}");
        for (key, value) in params {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        }
        url
    }
}

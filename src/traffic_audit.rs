use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientNode {
    enable: bool,
    upstream_traffic: u64,
    downstream_traffic: u64,
}

impl Default for ClientNode {
    fn default() -> Self {
        Self {
            enable: true,
            upstream_traffic: 0,
            downstream_traffic: 0,
        }
    }
}

impl ClientNode {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_upstream_traffic(&mut self, traffic: u64) {
        self.upstream_traffic += traffic;
    }

    pub fn add_downstream_traffic(&mut self, traffic: u64) {
        self.downstream_traffic += traffic;
    }

    pub fn get_upstream_traffic(&self) -> u64 {
        self.upstream_traffic
    }

    pub fn get_downstream_traffic(&self) -> u64 {
        self.downstream_traffic
    }

    pub fn get_total_traffic(&self) -> u64 {
        self.upstream_traffic + self.downstream_traffic
    }

    pub fn set_enable(&mut self, enable: bool) {
        self.enable = enable;
    }

    pub fn get_enable(&self) -> bool {
        self.enable
    }

    pub fn reset(&mut self) {
        self.upstream_traffic = 0;
        self.downstream_traffic = 0;
    }

    pub fn reset_upstream_traffic(&mut self) {
        self.upstream_traffic = 0;
    }

    pub fn reset_downstream_traffic(&mut self) {
        self.downstream_traffic = 0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficAudit {
    client_map: HashMap<String, ClientNode>,
}

impl TrafficAudit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_client(&mut self, client_id: String) {
        self.client_map.insert(client_id, ClientNode::new());
    }

    pub fn remove_client(&mut self, client_id: &str) {
        self.client_map.remove(client_id);
    }

    pub fn get_client_list(&self) -> Vec<String> {
        self.client_map.keys().map(|s| s.to_string()).collect()
    }

    pub fn contain_client(&self, client_id: &str) -> bool {
        self.client_map.contains_key(client_id)
    }

    pub fn add_upstream_traffic_of(&mut self, client_id: &str, traffic: u64) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.add_upstream_traffic(traffic);
        }
    }

    pub fn add_downstream_traffic_of(&mut self, client_id: &str, traffic: u64) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.add_downstream_traffic(traffic);
        }
    }

    pub fn get_upstream_traffic_of(&self, client_id: &str) -> u64 {
        if let Some(client_node) = self.client_map.get(client_id) {
            client_node.get_upstream_traffic()
        } else {
            0
        }
    }

    pub fn get_downstream_traffic_of(&self, client_id: &str) -> u64 {
        if let Some(client_node) = self.client_map.get(client_id) {
            client_node.get_downstream_traffic()
        } else {
            0
        }
    }

    pub fn get_traffic_of(&self, client_id: &str) -> u64 {
        if let Some(client_node) = self.client_map.get(client_id) {
            client_node.get_total_traffic()
        } else {
            0
        }
    }

    pub fn set_enable_of(&mut self, client_id: &str, enable: bool) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.set_enable(enable);
        }
    }

    pub fn get_enable_of(&self, client_id: &str) -> bool {
        if let Some(client_node) = self.client_map.get(client_id) {
            client_node.get_enable()
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        for (_, client_node) in self.client_map.iter_mut() {
            client_node.reset();
        }
    }

    pub fn reset_of(&mut self, client_id: &str) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.reset();
        }
    }

    pub fn reset_upstream_traffic(&mut self) {
        for (_, client_node) in self.client_map.iter_mut() {
            client_node.reset_upstream_traffic();
        }
    }

    pub fn reset_downstream_traffic(&mut self) {
        for (_, client_node) in self.client_map.iter_mut() {
            client_node.reset_downstream_traffic();
        }
    }

    pub fn reset_upstream_traffic_of(&mut self, client_id: &str) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.reset_upstream_traffic();
        }
    }

    pub fn reset_downstream_traffic_of(&mut self, client_id: &str) {
        if let Some(client_node) = self.client_map.get_mut(client_id) {
            client_node.reset_downstream_traffic();
        }
    }
}

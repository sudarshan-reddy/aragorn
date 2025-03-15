use anyhow::Result;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::dissector::Dissector;
use crate::metrics;
use crate::packet_router::Metrics;

use super::resp_parser::{parse_resp, RespValue};

pub struct RedisDissector {
    port: u16,
    key_map: Arc<Mutex<HashMap<u32, RespValue>>>,
}

impl RedisDissector {
    pub fn new(port: u16) -> Self {
        RedisDissector {
            port,
            key_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Dissector for RedisDissector {
    async fn port(&self) -> u16 {
        self.port
    }

    async fn process(&self, buf: Vec<u8>, metrics_opt: Option<Metrics>) -> Result<()> {
        // Return if none and unpack the metrics
        if metrics_opt.is_none() {
            return Ok(());
        }
        // We already know that metrics is not None
        let metrics = metrics_opt.unwrap();

        let resp = parse_resp(&buf).map_err(|_| anyhow::anyhow!("Failed to parse packet"))?;
        let input = resp.1;

        let mut store = self.key_map.lock().await;
        store
            .entry(metrics.identifier)
            .or_insert_with(|| input.clone());

        if let Some(latency) = metrics.latency {
            let is_error = input.to_string().contains("ERR");

            // Get the stored value and its key
            let stored_value = store
                .get(&metrics.identifier)
                .ok_or_else(|| anyhow::anyhow!("Failed to get value from store"))?;

            // Get the key from the stored value
            let key = if let Some(key) = &stored_value.key {
                key.clone()
            } else {
                "unknown".to_string()
            };

            // clean up the store
            store.remove(&metrics.identifier);

            // Record metrics directly
            metrics::record_metrics(&key, is_error, latency.as_millis());

            // Also log to console for visibility
            println!("Key: {}, Latency: {}ms", key, latency.as_millis());
        }

        Ok(())
    }
}

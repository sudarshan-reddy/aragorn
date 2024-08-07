use anyhow::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::tun::{Metrics, Plugin};

use super::resp_parser::{parse_resp, RespValue};

pub struct RespHandler {
    port: u16,
    key_map: Arc<Mutex<HashMap<u32, RespValue>>>,
}

impl RespHandler {
    pub fn new(port: u16) -> Self {
        RespHandler {
            port,
            key_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Plugin<RespValue> for RespHandler {
    async fn port(&self) -> u16 {
        self.port
    }

    async fn parse_packet(&self, buf: Vec<u8>) -> Result<RespValue> {
        let resp = parse_resp(&buf).map_err(|_| anyhow::anyhow!("Failed to parse packet"))?;
        Ok(resp.1)
    }

    async fn process(&self, input: RespValue, metrics: Option<Metrics>) -> Result<()> {
        // Return if none and unpack the metrics
        if metrics.is_none() {
            return Ok(());
        }
        // We already know that metrics is not None
        let metrics = metrics.unwrap();

        let mut store = self.key_map.lock().await;
        if !store.contains_key(&metrics.identifier) {
            // Check if the identifier exists and save it in the store
            store.insert(metrics.identifier, input.clone());
        }

        if let Some(latency) = metrics.latency {
            let status = if input.to_string().contains("ERR") {
                "ERR"
            } else {
                "OK"
            };
            // Print the latency and the key
            let stored_value = store
                .get(&metrics.identifier)
                .ok_or_else(|| anyhow::anyhow!("Failed to get value from store"))?;
            println!(
                "Key: {}, Latency: {}ms, Status: {}",
                stored_value.key.as_ref().unwrap(),
                latency.as_millis(),
                status,
            );
            // clean up the store
            store.remove(&metrics.identifier);
        }

        Ok(())
    }
}

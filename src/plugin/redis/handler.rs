use anyhow::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    plugin::{Metrics, Plugin},
    post_processor::{ProcessedResult, PrometheusResult},
};

use super::resp_parser::{parse_resp, RespValue};

#[derive(Debug, Clone)]
pub struct RedisResult {
    pub key: String,
    pub is_error: bool,
    pub latency: u128,
}

impl From<RedisResult> for ProcessedResult {
    fn from(res: RedisResult) -> ProcessedResult {
        ProcessedResult::Prometheus(PrometheusResult {
            label: res.key,
            is_error: res.is_error,
            latency: res.latency,
        })
    }
}

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

impl Plugin<RedisResult> for RespHandler {
    async fn port(&self) -> u16 {
        self.port
    }

    async fn process(&self, buf: Vec<u8>, metrics: Option<Metrics>) -> Result<Option<RedisResult>> {
        // Return if none and unpack the metrics
        if metrics.is_none() {
            return Ok(None);
        }
        // We already know that metrics is not None
        let metrics = metrics.unwrap();

        let resp = parse_resp(&buf).map_err(|_| anyhow::anyhow!("Failed to parse packet"))?;
        let input = resp.1;

        let mut store = self.key_map.lock().await;
        store
            .entry(metrics.identifier)
            .or_insert_with(|| input.clone());

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
            let key = stored_value.key.as_ref().unwrap().clone();
            // clean up the store
            store.remove(&metrics.identifier);
            return Ok(Some(RedisResult {
                key: key.clone(),
                is_error: status == "ERR",
                latency: latency.as_millis(),
            }));
        }

        Ok(None)
    }
}

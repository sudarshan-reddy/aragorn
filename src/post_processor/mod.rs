pub mod prometheus;

use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub enum ProcessedResult {
    Prometheus(PrometheusResult),
}

#[derive(Debug, Clone)]
pub struct PrometheusResult {
    pub label: String,
    pub is_error: bool,
    pub latency: u128,
}

/// PostProcessor trait that defines the interface for a post processor.
/// A post processor is a module that can process the result of a plugin.
/// The post processor can be used to implement different types of post processors like a Prometheus post processor.
#[async_trait]
pub trait PostProcessor: Send + Sync {
    async fn post_process(&self, input: ProcessedResult) -> Result<()>;
}

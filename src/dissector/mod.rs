pub mod redis;
// Future modules to add:
// pub mod postgres;
// pub mod opensearch;

use anyhow::Result;
use async_trait::async_trait;

use crate::packet_router::Metrics;

/// The Dissector trait defines the interface for protocol-specific dissectors.
/// Each dissector is responsible for parsing traffic for a specific protocol and
/// extracting relevant metrics.
#[async_trait]
pub trait Dissector: Send + Sync {
    /// The port this dissector is listening on
    async fn port(&self) -> u16;

    /// Process incoming packet data and extract metrics
    async fn process(&self, data: Vec<u8>, metrics: Option<Metrics>) -> Result<()>;
}

pub mod redis;
pub mod tlsdecrypt;

use anyhow::Result;

#[derive(Debug)]
pub struct Metrics {
    pub identifier: u32,
    pub latency: Option<std::time::Duration>,
}

/// Plugin trait that defines the interface for a plugin.
/// A plugin is a module that can parse a packet, process it and send the result to a handler.
/// The plugin can be used to implement different types of handlers like a Redis handler, a HTTP handler etc.
pub trait Plugin<R>: Send + Sync {
    async fn port(&self) -> u16;
    async fn process(&self, input: Vec<u8>, metrics: Option<Metrics>) -> Result<Option<R>>;
}

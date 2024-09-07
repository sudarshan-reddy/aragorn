use anyhow::Result;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{watch, Mutex};
use tokio::time::Duration;
use tracing::error;

use crate::plugin::{Metrics, Plugin};
use crate::post_processor::{PostProcessor, ProcessedResult};

pub trait PacketReader {
    async fn read_packet(&mut self) -> Option<Vec<u8>>;
}

pub struct Observer {
    syn_packets: Arc<Mutex<HashMap<u32, Instant>>>,
    ttl: Duration,
    cleanup_interval: Duration,

    post_processors: Vec<Arc<Mutex<dyn PostProcessor>>>,

    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
}

pub struct ObsConfig {
    pub ttl: Duration,
    pub cleanup_interval: Duration,
}

impl Default for ObsConfig {
    fn default() -> Self {
        ObsConfig {
            ttl: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(1),
        }
    }
}

impl Observer {
    /// Create a new Observer instance.
    /// Default TTL is 5 seconds.
    /// Default cleanup interval is 1 second.
    pub fn new(cfg: ObsConfig) -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);
        Observer {
            syn_packets: Arc::new(Mutex::new(HashMap::new())),
            post_processors: vec![],
            ttl: cfg.ttl,
            cleanup_interval: cfg.cleanup_interval,
            stop_tx,
            stop_rx,
        }
    }

    pub fn add_post_processor(&mut self, post_processor: Arc<Mutex<dyn PostProcessor>>) {
        self.post_processors.push(post_processor);
    }

    pub fn start_cleanup(&self) {
        let syn_packets = self.syn_packets.clone();
        let ttl = self.ttl;
        let cleanup_interval = self.cleanup_interval;
        let cleanup_fn = async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                let mut syn_packets = syn_packets.lock().await;
                let now = Instant::now();
                syn_packets.retain(|_, v| now.duration_since(*v) < ttl);
            }
        };
        tokio::spawn(cleanup_fn);
    }

    pub async fn capture_packets<H, R>(
        &self,
        mut reader: impl PacketReader,
        // TODO: These two should be paired and we need to expose a register method to have
        // more of these pairs and not take them as inputs here.
        handler: Arc<Mutex<H>>,
    ) -> Result<()>
    where
        R: Send + 'static + Into<ProcessedResult>,
        H: Plugin<R>,
    {
        let mut stop_rx = self.stop_rx.clone();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                Some(packet) =  reader.read_packet()  => {
                    let res = self.handle_packet(&handler, packet).await;
                    match res {
                        Ok(x) => {
                            if let Some(result) = x {
                                let result = &result.into();
                                for post_processor in &self.post_processors {
                                    post_processor.lock().await.post_process(result.clone()).await?;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_packet<H, R>(
        &self,
        handler: &Arc<Mutex<H>>,
        packet: Vec<u8>,
    ) -> Result<Option<R>>
    where
        R: Send + 'static,
        H: Plugin<R>,
    {
        // TODO: This isnt the most reliable way to measure time.
        // Ideally we should be using the timestamp from the packet header/kernel.
        // But this isnt easy enough. One way to do this is to set SO_TIMESTAMP on the socket
        // and then read the timestamp from the packet header. For the purpose of the
        // POC and simplicity, we are using this method temporarily. Moreover, this also
        // doesn't work if we are playing back a pcap file.
        let timestamp = Instant::now();
        if let Some(ethernet_packet) = EthernetPacket::new(&packet) {
            #[allow(clippy::single_match)]
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        return self
                            .handle_ipv4_packet(handler, ipv4_packet, timestamp)
                            .await;
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    async fn handle_ipv4_packet<H, R>(
        &self,
        handler: &Arc<Mutex<H>>,
        ipv4_packet: Ipv4Packet<'_>,
        timestamp: Instant,
    ) -> Result<Option<R>>
    where
        R: Send + 'static,
        H: Plugin<R>,
    {
        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                self.handle_tcp_packet(handler, ipv4_packet, timestamp)
                    .await
            }
            _ => Ok(None),
        }
    }

    async fn handle_tcp_packet<H, R>(
        &self,
        handler: &Arc<Mutex<H>>,
        ipv4_packet: Ipv4Packet<'_>,
        timestamp: Instant,
    ) -> Result<Option<R>>
    where
        R: Send + 'static,
        H: Plugin<R>,
    {
        let tcp_packet = TcpPacket::new(ipv4_packet.payload())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse TCP packet from IPv4 payload"))?;
        let port = handler.lock().await.port().await;
        let dst_port = tcp_packet.get_destination();
        let src_port = tcp_packet.get_source();
        if dst_port != port && src_port != port {
            return Ok(None); // Skip if the port does not match
        }

        let metrics = self.get_metrics(&tcp_packet, timestamp, port).await;

        let payload = tcp_packet.payload();
        if payload.is_empty() {
            return Ok(None); // Skip if payload is empty
        }

        handler
            .lock()
            .await
            .process(payload.to_vec(), metrics)
            .await
    }

    async fn get_metrics(
        &self,
        tcp_packet: &TcpPacket<'_>,
        timestamp: Instant,
        port: u16,
    ) -> Option<Metrics> {
        let dst_port = tcp_packet.get_destination();
        let src_port = tcp_packet.get_source();
        let ack_flag = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::ACK != 0;

        if !ack_flag {
            return None; // Skip if the packet is not an ACK
        }

        if dst_port == port {
            let mut syn_packets = self.syn_packets.lock().await;
            let identifier = tcp_packet.get_acknowledgement();
            syn_packets.insert(identifier, timestamp);
            return Some(Metrics {
                identifier,
                latency: None,
            });
        }
        if src_port == port {
            let mut syn_packets = self.syn_packets.lock().await;
            if let Some(time) = syn_packets.remove(&tcp_packet.get_sequence()) {
                let elapsed = time.elapsed();
                return Some(Metrics {
                    identifier: tcp_packet.get_sequence(),
                    latency: Some(elapsed),
                });
            }
        }
        None
    }

    pub fn stop(&self) {
        self.stop_tx.send(true).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::post_processor::PrometheusResult;

    use super::*;

    // Mock the PacketReader trait
    struct MockPacketReader {
        packets: Vec<Vec<u8>>,
    }

    impl PacketReader for MockPacketReader {
        async fn read_packet(&mut self) -> Option<Vec<u8>> {
            self.packets.pop()
        }
    }

    #[tokio::test]
    async fn test_get_metrics() {
        let obs = Observer::new(ObsConfig::default());
        let tcp_packet = TcpPacket::new(&[0; 20]).unwrap();
        let timestamp = Instant::now();
        let port = 1234;
        let metrics = obs.get_metrics(&tcp_packet, timestamp, port).await;
        assert!(metrics.is_none());
    }

    struct MockPlugin;

    impl MockPlugin {
        fn new() -> Self {
            MockPlugin
        }
    }

    impl Plugin<MockResult> for MockPlugin {
        async fn port(&self) -> u16 {
            1234
        }

        async fn process(
            &self,
            _input: Vec<u8>,
            _metrics: Option<Metrics>,
        ) -> Result<Option<MockResult>> {
            Ok(None)
        }
    }

    struct MockResult;

    impl From<MockResult> for ProcessedResult {
        fn from(_res: MockResult) -> ProcessedResult {
            ProcessedResult::Prometheus(PrometheusResult {
                label: "test".to_string(),
                is_error: false,
                latency: 0,
            })
        }
    }

    #[tokio::test]
    async fn test_capture_packets() {
        let reader = MockPacketReader {
            // TODO: send a fake tcp packet
            packets: vec![vec![
                0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]],
        };
        let plugin = Arc::new(Mutex::new(MockPlugin::new()));
        let obs = Arc::new(Mutex::new(Observer::new(ObsConfig::default())));

        let stop_tx = obs.lock().await.stop_tx.clone();
        // Clone the Arc and receiver to pass into the spawned task
        let obs_clone = Arc::clone(&obs);

        // Start the packet capture in a separate task
        let capture_task =
            tokio::spawn(
                async move { obs_clone.lock().await.capture_packets(reader, plugin).await },
            );

        // Run the capture for a short duration and then signal stop
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = stop_tx.send(true);

        // Wait for the capture task to complete
        let res = capture_task.await;

        // Assert that the result is Ok
        assert!(res.is_ok());

        // Look at whats in the syn_packets hashmap
        let obs = obs.lock().await;
        let syn_packets = obs.syn_packets.lock().await;
        assert_eq!(syn_packets.len(), 0);
    }
}

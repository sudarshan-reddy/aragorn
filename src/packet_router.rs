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

use crate::dissector::Dissector;

// Packet reader trait
#[allow(async_fn_in_trait)]
pub trait PacketReader {
    async fn read_packet(&mut self) -> Option<Vec<u8>>;
}

pub struct PacketRouter {
    syn_packets: Arc<Mutex<HashMap<u32, Instant>>>,
    ttl: Duration,
    cleanup_interval: Duration,

    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
}

pub struct RouterConfig {
    pub ttl: Duration,
    pub cleanup_interval: Duration,
}

impl Default for RouterConfig {
    fn default() -> Self {
        RouterConfig {
            ttl: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(1),
        }
    }
}

// Metric information for tracking request timing
#[derive(Debug)]
pub struct Metrics {
    pub identifier: u32,
    pub latency: Option<std::time::Duration>,
}

impl PacketRouter {
    /// Create a new PacketRouter instance.
    /// Default TTL is 5 seconds.
    /// Default cleanup interval is 1 second.
    pub fn new(cfg: RouterConfig) -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);
        PacketRouter {
            syn_packets: Arc::new(Mutex::new(HashMap::new())),
            ttl: cfg.ttl,
            cleanup_interval: cfg.cleanup_interval,
            stop_tx,
            stop_rx,
        }
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

    pub async fn capture_packets(
        &self,
        mut reader: impl PacketReader,
        dissector: Arc<Mutex<dyn Dissector + 'static>>,
    ) -> Result<()> {
        let mut stop_rx = self.stop_rx.clone();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                Some(packet) = reader.read_packet() => {
                    let res = self.handle_packet(&dissector, packet).await;
                    if let Err(e) = res {
                        error!("Error: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_packet(
        &self,
        dissector: &Arc<Mutex<dyn Dissector + 'static>>,
        packet: Vec<u8>,
    ) -> Result<()> {
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
                            .handle_ipv4_packet(dissector, ipv4_packet, timestamp)
                            .await;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_ipv4_packet(
        &self,
        dissector: &Arc<Mutex<dyn Dissector + 'static>>,
        ipv4_packet: Ipv4Packet<'_>,
        timestamp: Instant,
    ) -> Result<()> {
        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                self.handle_tcp_packet(dissector, ipv4_packet, timestamp)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn handle_tcp_packet(
        &self,
        dissector: &Arc<Mutex<dyn Dissector + 'static>>,
        ipv4_packet: Ipv4Packet<'_>,
        timestamp: Instant,
    ) -> Result<()> {
        let tcp_packet = TcpPacket::new(ipv4_packet.payload())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse TCP packet from IPv4 payload"))?;

        let port = dissector.lock().await.port().await;
        let dst_port = tcp_packet.get_destination();
        let src_port = tcp_packet.get_source();

        if dst_port != port && src_port != port {
            return Ok(()); // Skip if the port does not match
        }

        let metrics = self.get_metrics(&tcp_packet, timestamp, port).await;

        let payload = tcp_packet.payload();
        if payload.is_empty() {
            return Ok(()); // Skip if payload is empty
        }

        dissector
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

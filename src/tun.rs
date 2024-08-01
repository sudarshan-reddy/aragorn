use anyhow::Result;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub trait Handler<T>: Send + Sync {
    async fn port(&self) -> u16;
    async fn parse_packet(&self, buf: Vec<u8>) -> Result<T>;
    async fn process(&self, input: T, metrics: Option<Metrics>) -> Result<()>;
}

pub struct Metrics {
    pub identifier: u32,
    pub latency: Option<std::time::Duration>,
}

pub struct Observer {
    // IMMEDIATE TODO: Need to find a way to set a TTL here since we dont want to store all SYN packets that we never receive an ACK for.
    // This isn't very simple because we have a few edge cases:
    // 1. We might have a rogue SYN packet that we dont want to track anyway.
    // 2. A legitimate SYN packet might timeout and we might not receive an ACK for it. We need to
    //    record/observe this.
    //
    // TODO (for later): This should also be an LRU perhaps so we dont grow indiscriminately.
    syn_packets: Arc<Mutex<HashMap<u32, Instant>>>,
}

impl Observer {
    pub fn new() -> Self {
        Observer {
            syn_packets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn capture_packets<T>(
        &self,
        interface_name: &str,
        handler: Arc<Mutex<impl Handler<T>>>,
    ) -> Result<()>
    where
        T: Send + 'static,
    {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Device not found"))?;

        let (_, mut rx) = match datalink::channel(&interface, Default::default())? {
            Ethernet(tx, rx) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Unhandled channel type")),
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    // TODO: This isnt the most reliable way to measure time.
                    // Ideally we should be using the timestamp from the packet header/kernel.
                    // But this isnt easy enough. One way to do this is to set SO_TIMESTAMP on the socket
                    // and then read the timestamp from the packet header. For the purpose of the
                    // POC and simplicity, we are using this method temporarily.
                    let timestamp = Instant::now();
                    if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                        if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                                match ipv4_packet.get_next_level_protocol() {
                                    IpNextHeaderProtocols::Tcp => {
                                        let res = self
                                            .handle_tcp_packet(&handler, ipv4_packet, timestamp)
                                            .await;
                                        if res.is_err() {
                                            eprintln!("Failed to handle TCP packet: {:?}", res);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("An error occurred while reading: {}", e);
                }
            }
        }
    }

    async fn handle_tcp_packet<T>(
        &self,
        handler: &Arc<Mutex<impl Handler<T>>>,
        ipv4_packet: Ipv4Packet<'_>,
        timestamp: Instant,
    ) -> Result<()>
    where
        T: Send + 'static,
    {
        let tcp_packet = TcpPacket::new(ipv4_packet.payload())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse TCP packet from IPv4 payload"))?;
        let port = handler.lock().await.port().await;
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

        let parsed_packet = handler.lock().await.parse_packet(payload.to_vec()).await?;
        handler.lock().await.process(parsed_packet, metrics).await
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

        //println!(
        //    "TCP Packet: {} -> {} Flags: SYN: {}, ACK: {}, seq: {}, ack: {}",
        //    tcp_packet.get_source(),
        //    tcp_packet.get_destination(),
        //    syn_flag,
        //    ack_flag,
        //    tcp_packet.get_sequence(),
        //    tcp_packet.get_acknowledgement(),
        //);

        if !ack_flag {
            return None; // Skip if the packet is not an ACK
        }

        // The redis port is the dst port. So this is traffic going from our machine to redis.
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
            // We match the seq number when src_port == port because this is traffic coming from redis.
            if let Some(time) = syn_packets.remove(&tcp_packet.get_sequence()) {
                let elapsed = time.elapsed();
                return Some(Metrics {
                    identifier: tcp_packet.get_sequence(),
                    latency: Some(elapsed),
                });
            }
        }
        return None;
    }
}

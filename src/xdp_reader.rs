use crate::packet_router::PacketReader;
use crate::probes::xdp_probe::{PacketMetadata, XdpProbe};
use anyhow::Result;
use std::mem;
use tokio_stream::StreamExt;

pub struct XdpReader {
    event_stream: Box<dyn tokio_stream::Stream<Item = Result<Vec<u8>>> + Unpin + Send>,
}

impl XdpReader {
    pub async fn new(interface: &str, target_port: u16) -> Result<Self> {
        let xdp_probe = XdpProbe::new(interface, target_port).await?;
        let event_stream = xdp_probe.stream_for_events().await?;

        Ok(Self {
            event_stream: Box::new(event_stream),
        })
    }
}

impl PacketReader for XdpReader {
    async fn read_packet(&mut self) -> Option<Vec<u8>> {
        while let Some(result) = self.event_stream.next().await {
            match result {
                Ok(data) => {
                    println!("Received data of length: {}", data.len());

                    if data.len() >= mem::size_of::<PacketMetadata>() {
                        // Safely try to interpret the data as PacketMetadata
                        if let Some(metadata) = self.try_parse_metadata(&data) {
                            println!("Packet: src_ip={}, dst_ip={}, src_port={}, dst_port={}, payload_size={}",
                                     metadata.src_ip, metadata.dst_ip,
                                     metadata.src_port, metadata.dst_port, metadata.payload_size);

                            // Extract just the payload for further processing
                            let len =
                                metadata.payload_size.min(metadata.payload.len() as u16) as usize;
                            let payload = metadata.payload[..len].to_vec();
                            return Some(payload);
                        }
                    }

                    // If can't interpret as metadata, return the raw data
                    return Some(data);
                }
                Err(e) => {
                    eprintln!("Error reading packet: {:?}", e);
                    continue;
                }
            }
        }
        None
    }
}

impl XdpReader {
    // Helper function to safely parse the metadata
    fn try_parse_metadata(&self, data: &[u8]) -> Option<PacketMetadata> {
        if data.len() < mem::size_of::<PacketMetadata>() {
            return None;
        }

        // Safer way to copy memory without raw pointer dereferencing
        let mut metadata = PacketMetadata {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            payload_size: 0,
            payload: [0; 64],
        };

        // Copy the fields
        let src_ip_bytes = &data[0..4];
        let dst_ip_bytes = &data[4..8];
        let src_port_bytes = &data[8..10];
        let dst_port_bytes = &data[10..12];
        let payload_size_bytes = &data[12..14];

        metadata.src_ip = u32::from_ne_bytes([
            src_ip_bytes[0],
            src_ip_bytes[1],
            src_ip_bytes[2],
            src_ip_bytes[3],
        ]);

        metadata.dst_ip = u32::from_ne_bytes([
            dst_ip_bytes[0],
            dst_ip_bytes[1],
            dst_ip_bytes[2],
            dst_ip_bytes[3],
        ]);

        metadata.src_port = u16::from_ne_bytes([src_port_bytes[0], src_port_bytes[1]]);

        metadata.dst_port = u16::from_ne_bytes([dst_port_bytes[0], dst_port_bytes[1]]);

        metadata.payload_size = u16::from_ne_bytes([payload_size_bytes[0], payload_size_bytes[1]]);

        // Safely copy payload data
        let payload_start = 14;
        let payload_end = std::cmp::min(payload_start + metadata.payload_size as usize, data.len());
        let payload_end = std::cmp::min(payload_end, payload_start + metadata.payload.len());

        for (i, byte) in data[payload_start..payload_end].iter().enumerate() {
            metadata.payload[i] = *byte;
        }

        Some(metadata)
    }
}

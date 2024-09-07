use anyhow::Result;
use pnet::datalink::{self, Channel::Ethernet};

use crate::tun::PacketReader;

pub struct LivePacketReader<'a> {
    rx: Box<dyn pnet::datalink::DataLinkReceiver + 'a>,
}

impl<'a> LivePacketReader<'a> {
    pub fn new(interface_name: &str) -> Result<Self> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Device not found"))?;

        let (_, rx) = match datalink::channel(&interface, Default::default())? {
            Ethernet(_, rx) => ((), rx),
            _ => return Err(anyhow::anyhow!("Unhandled channel type")),
        };

        Ok(Self { rx })
    }
}

impl<'a> PacketReader for LivePacketReader<'a> {
    async fn read_packet(&mut self) -> Option<Vec<u8>> {
        match self.rx.next() {
            Ok(packet) => Some(packet.to_vec()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    // Mock the pnet::datalink::DataLinkReceiver trait
    struct MockDataLinkReceiver {
        packets: Vec<Vec<u8>>,
        current_packet: Option<Vec<u8>>,
    }

    impl pnet::datalink::DataLinkReceiver for MockDataLinkReceiver {
        fn next(&mut self) -> io::Result<&[u8]> {
            if let Some(packet) = self.packets.pop() {
                self.current_packet = Some(packet);
                Ok(self.current_packet.as_deref().unwrap())
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "No more packets"))
            }
        }
    }

    #[tokio::test]
    async fn test_read_packet() {
        // Set up the mock data link receiver
        let mock_packets = vec![
            vec![0x01, 0x02, 0x03],
            vec![0x04, 0x05, 0x06],
            vec![0x07, 0x08, 0x09],
        ];
        let mock_receiver = MockDataLinkReceiver {
            packets: mock_packets,
            current_packet: None,
        };

        let mut packet_reader = LivePacketReader {
            rx: Box::new(mock_receiver),
        };

        assert_eq!(
            packet_reader.read_packet().await,
            Some(vec![0x07, 0x08, 0x09])
        );
        assert_eq!(
            packet_reader.read_packet().await,
            Some(vec![0x04, 0x05, 0x06])
        );
        assert_eq!(
            packet_reader.read_packet().await,
            Some(vec![0x01, 0x02, 0x03])
        );
        assert_eq!(packet_reader.read_packet().await, None);
    }
}

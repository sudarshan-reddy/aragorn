use anyhow::Result;
use aya::util::online_cpus;
use bytes::BytesMut;

use crate::probes::ssl_write_probe::SslWriteProbe;
use crate::tun::PacketReader;

pub struct TlsReader {
    ssl_write_probe: SslWriteProbe,
}

impl TlsReader {
    pub fn new() -> Result<Self> {
        let ssl_write_probe = SslWriteProbe::new()?;
        // TODO: Fix unwrap
        Ok(Self { ssl_write_probe })
    }
}

impl PacketReader for TlsReader {
    async fn read_packet(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0; 1024];
        let cpus = online_cpus().unwrap();

        for cpu in cpus {
            if let Ok((_cpu, data)) = self
                .ssl_write_probe
                .perf_map
                .lock()
                .await
                .read_events(cpu, &mut buf)
            {
                if !data.is_empty() {
                    let mut packet = BytesMut::with_capacity(data[0].len());
                    packet.extend_from_slice(&data[0]);
                    return Some(packet.to_vec());
                }
            }
        }
        None
    }
}

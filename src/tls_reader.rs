use crate::probes::ssl_write_probe::SslWriteProbe;
use crate::tun::PacketReader;
use anyhow::Result;
use futures::Stream;
use tokio_stream::StreamExt;

pub struct TlsReader {
    event_stream: Box<dyn Stream<Item = Result<Vec<u8>>> + Unpin + Send>,
}

impl TlsReader {
    pub async fn new() -> Result<Self> {
        let ssl_write_probe = SslWriteProbe::new()?;
        let event_stream = ssl_write_probe.stream_for_events().await?;
        Ok(Self {
            event_stream: Box::new(event_stream),
        })
    }
}

impl PacketReader for TlsReader {
    async fn read_packet(&mut self) -> Option<Vec<u8>> {
        while let Some(result) = self.event_stream.next().await {
            match result {
                Ok(packet) => return Some(packet),
                Err(e) => {
                    eprintln!("Error reading packet: {:?}", e);
                    continue;
                }
            }
        }
        None
    }
}

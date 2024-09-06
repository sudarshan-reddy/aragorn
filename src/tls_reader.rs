use crate::{probes::ssl_write_probe::SslWriteProbe, tun::PacketReader};
use anyhow::Result;
use aya::{maps::perf::AsyncPerfEventArray, Bpf};

pub struct TlsReader {
    pub ssl_write_probe: SslWriteProbe,
    pub perf_map: AsyncPerfEventArray<SslWriteProbe>,
}

impl TlsReader {
    pub fn new() -> Result<Self> {
        let ssl_write_probe = SslWriteProbe::new()?;
        let mut perf_map = AsyncPerfEventArray::try_from(Bpf.take_map("PERF_ARRAY").unwrap())?;
        Ok(TlsReader { ssl_write_probe })
    }
}

impl PacketReader for TlsReader {
    fn read_packet(&mut self) -> Option<Vec<u8>> {}
}

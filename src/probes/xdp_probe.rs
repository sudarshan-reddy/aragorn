use anyhow::{Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::{Array, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

// Define a struct that matches the C packet_metadata structure
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PacketMetadata {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_size: u16,
    pub payload: [u8; 64],
}

pub struct XdpProbe {
    _bpf: Ebpf, // Keep bpf alive
    events: Arc<Mutex<AsyncPerfEventArray<MapData>>>,
}

impl XdpProbe {
    pub async fn new(interface: &str, target_port: u16) -> Result<Self> {
        // Use aya::include_bytes_aligned! macro to load the BPF object file
        let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/xdp_tcp_capture.o"
        )))?;

        // Get the XDP program
        let program: &mut Xdp = bpf
            .program_mut("xdp_tcp_filter")
            .context("XDP program not found")?
            .try_into()?;

        // Load the program
        program.load()?;

        // Attempt to attach with multiple strategies
        let attach_result = program
            .attach(interface, XdpFlags::default())
            .or_else(|_| program.attach(interface, XdpFlags::SKB_MODE));

        // Attach the program with helpful context
        attach_result.context(format!(
            "Failed to attach XDP program to interface {}",
            interface
        ))?;

        // Set the target port in the map
        let target_port_map = bpf
            .map_mut("target_port")
            .context("Target port map not found")?;

        // Convert to Array and set the value
        let mut target_port_array = Array::try_from(target_port_map)?;
        target_port_array.set(0, target_port as u32, 0)?;

        // Get the perf event array
        let map_events = bpf.take_map("events").context("Events map not found")?;

        let perf_events = AsyncPerfEventArray::try_from(map_events)?;

        Ok(Self {
            _bpf: bpf,
            events: Arc::new(Mutex::new(perf_events)),
        })
    }

    pub async fn stream_for_events(&self) -> Result<impl Stream<Item = Result<Vec<u8>>>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Get the number of available CPUs
        let cpus = std::thread::available_parallelism()
            .map(|n| (0..n.get()).collect::<Vec<_>>())
            .unwrap_or_else(|_| vec![0]);

        for cpu_id in cpus {
            let events = self.events.clone();
            let tx = tx.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(256))
                    .collect::<Vec<_>>();

                // Open the perf event for this CPU
                match events.lock().await.open(cpu_id as u32, None) {
                    Ok(mut event_array) => {
                        loop {
                            // Await the read_events
                            match event_array.read_events(&mut buffers).await {
                                Ok(events) => {
                                    for i in 0..events.read {
                                        let buf = &buffers[i];
                                        if tx.send(Ok(buf.to_vec())).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx
                                        .send(Err(anyhow::anyhow!("Error reading events: {:?}", e)))
                                        .await;
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(anyhow::anyhow!(
                                "Failed to open perf event on CPU {}: {:?}",
                                cpu_id,
                                e
                            )))
                            .await;
                    }
                }
            });
        }

        Ok(ReceiverStream::new(rx))
    }
}

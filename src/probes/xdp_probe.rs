use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use aya::{
    maps::{Array, MapData},
    programs::{Xdp, XdpFlags},
    Bpf,
};
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
    _bpf: Bpf, // Keep bpf alive
    events: Arc<Mutex<AsyncPerfEventArray<MapData>>>,
}

impl XdpProbe {
    pub async fn new(interface: &str, target_port: u16) -> Result<Self> {
        let path = std::path::Path::new("target/xdp_tcp_capture.o");
        if !path.exists() {
            eprintln!(
                "Error: XDP object file does not exist at {}",
                path.display()
            );
            return Err(anyhow::anyhow!("XDP object file not found"));
        }

        // Load the XDP program
        let mut bpf = match Bpf::load_file("target/xdp_tcp_capture.o") {
            Ok(bpf) => {
                println!("Successfully loaded BPF program!");
                bpf
            }
            Err(e) => {
                eprintln!("Failed to load BPF program: {:?}", e);
                return Err(anyhow::anyhow!("Failed to load BPF program: {}", e));
            }
        };

        println!("Successfully loaded BPF program.. getting XDP program ");

        // Get the XDP program
        let program = bpf
            .program_mut("xdp_tcp_filter")
            .ok_or_else(|| anyhow::anyhow!("XDP program not found"))?;

        println!("Successfully loaded XDP program.. converting to XDP program");

        // Convert to XDP program
        let xdp_program: &mut Xdp = program.try_into()?;

        println!("Successfully converted XDP program.. attaching to interface");

        // Attach the XDP program to the interface
        // xdp_program.attach(interface, XdpFlags::default())?;
        xdp_program.attach(interface, XdpFlags::SKB_MODE)?;

        println!("Successfully attached XDP program to interface.. setting target port");

        // Set the target port in the map
        let target_port_map = bpf
            .map_mut("target_port")
            .ok_or_else(|| anyhow::anyhow!("Target port map not found"))?;

        let mut target_port_array = Array::try_from(target_port_map)?;
        target_port_array.set(0, target_port as u32, 0)?;

        // Get the perf event array - using take_map() instead of map()
        let map_events = bpf
            .take_map("events")
            .ok_or_else(|| anyhow::anyhow!("Events map not found"))?;

        let perf_events = AsyncPerfEventArray::try_from(map_events)?;

        Ok(Self {
            _bpf: bpf,
            events: Arc::new(Mutex::new(perf_events)), // Pass direct value, not reference
        })
    }

    pub async fn stream_for_events(&self) -> Result<impl Stream<Item = Result<Vec<u8>>>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let cpus = aya::util::online_cpus()?;

        for cpu_id in cpus {
            let events = self.events.clone();
            let tx = tx.clone();

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(256))
                    .collect::<Vec<_>>();

                // Open the perf event for this CPU
                match events.lock().await.open(cpu_id, None) {
                    Ok(mut event_array) => loop {
                        match event_array.read_events(&mut buffers).await {
                            Ok(events) => {
                                for i in 0..events.read {
                                    let buf = &buffers[i];
                                    println!(
                                        "CPU {}: Received event of size {}",
                                        cpu_id,
                                        buf.len()
                                    );
                                    if let Err(_) = tx.send(Ok(buf.to_vec())).await {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error reading events: {:?}", e);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to open perf event on CPU {}: {:?}", cpu_id, e);
                    }
                }
            });
        }

        Ok(ReceiverStream::new(rx))
    }
}

use anyhow::Result;
use aya::maps::{perf::AsyncPerfEventArray, MapData};
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

//#[repr(C)]
//struct SslWriteData {
//    pid: u32,
//    comm: [u8; 16], // TASK_COMM_LEN is 16 in Linux
//    len: u64,
//    buf: [u8; 4096],
//}

pub struct SslWriteProbe {
    perf_map: Arc<Mutex<AsyncPerfEventArray<MapData>>>,
}

impl SslWriteProbe {
    pub fn new() -> Result<Self> {
        let bpf_path = "target/ssl_write.o"; // We're keeping the same output name for simplicity
        println!("Loading BPF object from: {}", bpf_path);

        let mut bpf = match Bpf::load_file(bpf_path) {
            Ok(bpf) => bpf,
            Err(e) => {
                println!("Error loading BPF object: {:?}", e);
                return Err(anyhow::anyhow!("Failed to load BPF object: {}", e));
            }
        };

        // Try to get the kprobe program
        let prog = match bpf.program_mut("kprobe_open") {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!("Program 'kprobe_execve' not found"));
            }
        };

        use aya::programs::KProbe;
        let kprobe: &mut KProbe = match prog.try_into() {
            Ok(p) => p,
            Err(e) => {
                println!("Error converting program: {:?}", e);
                return Err(anyhow::anyhow!("Failed to convert program: {}", e));
            }
        };

        // Load the program
        match kprobe.load() {
            Ok(_) => println!("Successfully loaded kprobe program"),
            Err(e) => {
                println!("Error loading kprobe program: {:?}", e);
                return Err(anyhow::anyhow!("Failed to load kprobe program: {}", e));
            }
        }

        // Attach the kprobe
        match kprobe.attach("do_sys_open", 0) {
            Ok(_) => println!("Successfully attached kprobe"),
            Err(e) => {
                println!("Error attaching kprobe: {:?}", e);
                return Err(anyhow::anyhow!("Failed to attach kprobe: {}", e));
            }
        }

        // Get the perf event array
        let events_map = match bpf.take_map("events") {
            Some(m) => m,
            None => {
                return Err(anyhow::anyhow!("Map 'events' not found"));
            }
        };

        let perf_map = Arc::new(Mutex::new(
            match AsyncPerfEventArray::try_from(events_map) {
                Ok(p) => p,
                Err(e) => {
                    println!("Error creating AsyncPerfEventArray: {:?}", e);
                    return Err(anyhow::anyhow!(
                        "Failed to create AsyncPerfEventArray: {}",
                        e
                    ));
                }
            },
        ));

        Ok(Self { perf_map })
    }

    pub async fn stream_for_events(&self) -> Result<impl Stream<Item = Result<Vec<u8>>>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Get the online CPUs
        let cpus = online_cpus()?;
        println!("Monitoring events on {} CPUs", cpus.len());

        for cpu_id in cpus {
            let mut perf_map = self.perf_map.lock().await.open(cpu_id, None)?;
            let tx = tx.clone();

            println!("Started monitoring on CPU {}", cpu_id);

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                println!(
                    "Worker for CPU {} ready with {} buffers",
                    cpu_id,
                    buffers.len()
                );

                loop {
                    match perf_map.read_events(&mut buffers).await {
                        Ok(events) => {
                            println!("CPU {}: Read {} events", cpu_id, events.read);
                            for i in 0..events.read {
                                let buf = &buffers[i];
                                println!("CPU {}: Event data length: {}", cpu_id, buf.len());
                                match tx.send(Ok(buf.to_vec())).await {
                                    Ok(_) => println!("CPU {}: Successfully sent event", cpu_id),
                                    Err(e) => {
                                        println!("CPU {}: Failed to send event: {}", cpu_id, e)
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("CPU {}: Error reading events: {:?}", cpu_id, e);
                        }
                    }
                }
            });
        }

        Ok(ReceiverStream::new(rx))
    }
}

fn find_libssl() -> Option<String> {
    let possible_libssl_paths = vec![
        // This is the one that curl uses.
        "/lib/aarch64-linux-gnu/libssl.so.3",
        // This is the libssl.o I see in my arm vm
        "/usr/lib/aarch64-linux-gnu/libssl.so",
        // Probably the one for x86 machines (TODO: Verify)
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/usr/local/lib/libssl.so",
    ];

    for path in possible_libssl_paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    None
}

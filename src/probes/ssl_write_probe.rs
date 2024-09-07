use anyhow::Result;
use aya::maps::{perf::AsyncPerfEventArray, MapData};
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::env;
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
        // Attach the ssl_write.c BPF program to the SSL_write function in libssl
        let out_dir = env::var("OUT_DIR").unwrap();
        let ssl_write_path = format!("{}/ssl_write.o", out_dir);
        let mut bpf = Bpf::load_file(ssl_write_path)?;
        let prog: &mut UProbe = bpf.program_mut("uprobe__SSL_write").unwrap().try_into()?;
        let libssl_path = find_libssl().ok_or_else(|| anyhow::anyhow!("libssl not found"))?;
        prog.attach(Some("SSL_write"), 0, libssl_path, None)?;

        // Load the BPF program that will handle the events
        let perf_map = Arc::new(Mutex::new(AsyncPerfEventArray::try_from(
            bpf.take_map("events").unwrap(),
        )?));

        Ok(Self { perf_map })
    }

    pub async fn stream_for_events(&self) -> Result<impl Stream<Item = Result<Vec<u8>>>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        for cpu_id in online_cpus()? {
            let mut perf_map = self.perf_map.lock().await.open(cpu_id, None)?;
            let tx = tx.clone();
            // TODO: Can I do better and not spawn a task for each CPU?
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    // TODO: Fix this unwrap
                    let events = perf_map.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        let buf = &buffers[i];
                        tx.send(Ok(buf.to_vec())).await.unwrap();
                    }
                }
            });
        }

        Ok(ReceiverStream::new(rx))
    }
}

fn find_libssl() -> Option<String> {
    let possible_libssl_paths = vec![
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

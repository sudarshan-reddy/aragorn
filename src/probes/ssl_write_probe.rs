use anyhow::Result;
use aya::programs::UProbe;
use aya::Bpf;
use std::env;

pub struct SslWriteProbe {
    bpf: Bpf,
}

impl SslWriteProbe {
    pub fn new() -> Result<Self> {
        let out_dir = env::var("OUT_DIR").unwrap();
        let ssl_write_path = format!("{}/ssl_write.o", out_dir);
        let mut bpf = Bpf::load_file(ssl_write_path)?;
        let prog: &mut UProbe = bpf.program_mut("uprobe__SSL_write").unwrap().try_into()?;
        let libssl_path = find_libssl().ok_or_else(|| anyhow::anyhow!("libssl not found"))?;
        prog.attach(Some("SSL_write"), 0, libssl_path, None)?;
        Ok(Self { bpf })
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

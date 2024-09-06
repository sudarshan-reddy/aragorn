use std::process::Command;
use std::{env, fs};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let bpf_dir = "ebpf/";

    // List of eBPF source files to compile
    let ebpf_files = vec!["ssl_write.c"];

    for file in ebpf_files {
        let src_path = format!("{}/{}", bpf_dir, file);
        let obj_path = format!("{}/{}.o", out_dir, file.replace(".c", ""));

        // Run clang to compile the eBPF program
        let status = Command::new("clang")
            .args(&["-O2", "-target", "bpf", "-c", &src_path, "-o", &obj_path])
            .status()
            .expect("Failed to compile eBPF programs");

        assert!(status.success(), "Clang failed with exit code {}", status);
    }

    // Output environment variable to be available for Rust code
    println!("cargo:rerun-if-changed=ebpf/");
}

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let out_file = out_dir.join("xdp_tcp_capture.o");

    let bpf_source = "src/ebpf/xdp_tcp_capture.c";
    let bpf_headers = "/usr/include/bpf";

    println!("cargo:rerun-if-changed={}", bpf_source);

    // Compile the eBPF program
    let status = Command::new("clang")
        .args(&[
            "-g",
            "-O2",
            "-Wall",
            "-target",
            "bpf",
            "-I",
            bpf_headers,
            "-I",
            "/usr/include",
            "-c",
            bpf_source,
            "-o",
            out_file.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("Failed to compile BPF program");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

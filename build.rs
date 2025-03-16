use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let out_file = out_dir.join("xdp_tcp_capture.o");

    let bpf_source = "src/ebpf/xdp_tcp_capture.c";
    let bpf_headers = "/usr/include/bpf";

    println!("cargo:rerun-if-changed={}", bpf_source);

    // Create build directory if it doesn't exist
    let build_dir = PathBuf::from("build");
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Compile with debug info and kernel BTF
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

    // Copy the compiled object file to the target directory
    let dest_dir = PathBuf::from("target");
    fs::create_dir_all(&dest_dir).expect("Failed to create target directory");

    let dest_file = dest_dir.join("xdp_tcp_capture.o");
    fs::copy(&out_file, &dest_file).expect("Failed to copy compiled BPF object file");

    println!("cargo:rerun-if-changed=build.rs");
}

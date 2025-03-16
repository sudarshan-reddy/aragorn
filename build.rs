//use std::env;
//use std::fs;
//use std::path::PathBuf;
//
//fn main() {
//    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
//    let out_file = out_dir.join("ssl_write.o");
//
//    let bpf_source = "src/ebpf/ssl_write.c";
//    let bpf_headers = "/usr/include/bpf";
//
//    println!("cargo:rerun-if-changed={}", bpf_source);
//
//    // Add BTF generation with -g flag and ensure we're using the correct BPF target
//    let clang_args = format!(
//        "-I{} -O2 -g -target bpf -c {} -o {}",
//        bpf_headers,
//        bpf_source,
//        out_file.display()
//    );
//
//    if !std::process::Command::new("clang")
//        .args(clang_args.split_whitespace())
//        .status()
//        .expect("failed to execute clang")
//        .success()
//    {
//        panic!("failed to compile BPF program");
//    }
//
//    // Copy the compiled object file to a standard location in the project
//    let dest_dir = PathBuf::from("target");
//    fs::create_dir_all(&dest_dir).expect("Failed to create target directory");
//
//    let dest_file = dest_dir.join("ssl_write.o");
//    fs::copy(&out_file, &dest_file).expect("Failed to copy compiled BPF object file");
//
//    println!("cargo:rerun-if-changed=build.rs");
//}

// build.rs (modified)
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let out_file = out_dir.join("ssl_write.o");

    let bpf_source = "src/ebpf/simple_kprobe.c";
    let bpf_headers = "/usr/include/bpf";

    println!("cargo:rerun-if-changed={}", bpf_source);

    // Compile with debug info and kernel BTF
    let clang_args = format!(
        "-I{} -g -O2 -target bpf -c {} -o {}",
        bpf_headers,
        bpf_source,
        out_file.display()
    );

    if !std::process::Command::new("clang")
        .args(clang_args.split_whitespace())
        .status()
        .expect("failed to execute clang")
        .success()
    {
        panic!("failed to compile BPF program");
    }

    // Copy the compiled object file
    let dest_dir = PathBuf::from("target");
    fs::create_dir_all(&dest_dir).expect("Failed to create target directory");

    let dest_file = dest_dir.join("ssl_write.o");
    fs::copy(&out_file, &dest_file).expect("Failed to copy compiled BPF object file");

    println!("cargo:rerun-if-changed=build.rs");
}

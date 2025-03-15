use std::path::PathBuf;

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    out.push("ssl_write.o");

    let bpf_source = "src/ebpf/ssl_write.c";
    let bpf_headers = "/usr/include/bpf";

    println!("cargo:rerun-if-changed={}", bpf_source);

    let clang_args = format!(
        "-I{} -O2 -target bpf -c {} -o {}",
        bpf_headers,
        bpf_source,
        out.display()
    );

    if !std::process::Command::new("clang")
        .args(clang_args.split_whitespace())
        .status()
        .expect("failed to execute clang")
        .success()
    {
        panic!("failed to compile BPF program");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

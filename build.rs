//! Build script: compiles the eBPF program and makes cargo embed it.
//!
//! The userspace binary carries the kernel side program as a byte array, so it
//! can be copied around as a single file (see `include_bytes_aligned!` in
//! `src/capture.rs`).
//!
//! The actual cross build - `cargo build --target bpfel-unknown-none
//! -Z build-std=core`, run under nightly - is performed by `aya-build`. Set
//! `AYA_BUILD_SKIP=1` to skip it, which is what `cargo check` and `cargo test`
//! do on machines without a BPF toolchain; the embedded object is then empty
//! and the binary refuses to start.

use std::{env, fs, path::PathBuf};

/// Package and binary name of the kernel side crate.
const EBPF_CRATE: &str = "ebpf-http-sniffer-ebpf";

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={EBPF_CRATE}");
    println!("cargo:rerun-if-changed=ebpf-http-sniffer-common");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo always sets OUT_DIR"));

    if skip_requested() {
        // Keep `include_bytes_aligned!` resolvable while not building anything.
        fs::write(out_dir.join(EBPF_CRATE), b"")?;
        println!(
            "cargo:warning=AYA_BUILD_SKIP is set: the eBPF program was not built and the embedded object is empty"
        );
        return Ok(());
    }

    aya_build::build_ebpf(
        [aya_build::Package {
            name: EBPF_CRATE,
            root_dir: EBPF_CRATE,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}

fn skip_requested() -> bool {
    env::var("AYA_BUILD_SKIP").is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

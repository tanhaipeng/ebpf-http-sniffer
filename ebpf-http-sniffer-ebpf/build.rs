//! Build script for the kernel side program.
//!
//! This crate is not built by cargo directly: the userspace `build.rs` invokes
//! `aya-build`, which rebuilds it for `bpfel-unknown-none` with
//! `-Z build-std=core` and copies the resulting ELF into `OUT_DIR`.
//!
//! All this script does is keep cargo's cache honest and complain early when
//! the BPF linker is missing, instead of failing later with a wall of linker
//! errors.

use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    match find_in_path("bpf-linker") {
        Some(path) => {
            // Rebuild when the linker that produces the ELF changes.
            println!("cargo:rerun-if-changed={}", path.display());
        }
        None => println!(
            "cargo:warning=bpf-linker not found in PATH: install it (`cargo install bpf-linker`, \
             or a prebuilt release from https://github.com/aya-rs/bpf-linker/releases) to link the eBPF program"
        ),
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

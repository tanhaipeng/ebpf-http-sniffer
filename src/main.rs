//! `http-sniff`: capture plaintext HTTP/1.x requests and responses on Linux
//! with eBPF.
//!
//! The kernel side program (`ebpf-http-sniffer-ebpf`) copies the TCP payload of
//! segments to and from the watched ports into a ring buffer; this binary loads
//! it, reassembles the byte streams per connection and parses HTTP/1.x out of
//! them. See `README.md` for the design and the build requirements.

mod capture;
mod cli;
mod output;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Args::parse();
    let default_level = if args.verbose { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level))
        .format_timestamp_millis()
        .init();

    capture::run(args).await
}

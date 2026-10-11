//! Command line interface.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Ports that are watched unless the user says otherwise.
pub const DEFAULT_PORTS: &str = "80,8080,8000";

#[derive(Debug, Parser)]
#[command(
    name = "http-sniff",
    version,
    about = "Capture plaintext HTTP/1.x requests and responses with eBPF",
    long_about = "Attaches a TC eBPF program to the selected interfaces, copies the TCP payload of \
                  segments travelling to or from the watched ports, and reassembles them into HTTP \
                  requests and responses.\n\n\
                  Needs root (or CAP_BPF + CAP_NET_ADMIN). TLS traffic is not decrypted: only \
                  plaintext HTTP becomes visible."
)]
pub struct Args {
    /// TCP ports to watch (comma separated).
    #[arg(short, long, value_delimiter = ',', default_value = DEFAULT_PORTS)]
    pub port: Vec<u16>,

    /// Interfaces to attach to, comma separated; "all" means every interface
    /// listed in /sys/class/net.
    #[arg(short, long, value_delimiter = ',', default_value = "all")]
    pub iface: Vec<String>,

    /// Load this eBPF object instead of the embedded one.
    #[arg(long, value_name = "PATH")]
    pub ebpf_object: Option<PathBuf>,

    /// Do not print message bodies.
    #[arg(long)]
    pub no_body: bool,

    /// Do not print headers.
    #[arg(long)]
    pub no_headers: bool,

    /// Print at most this many bytes of each body.
    #[arg(long, value_name = "BYTES", default_value_t = 512)]
    pub body_limit: usize,

    /// Print one JSON object per message instead of the human readable format.
    #[arg(long)]
    pub json: bool,

    /// When to colourise the output.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    /// Log every captured segment, not just the parsed messages.
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl Args {
    /// True when ANSI escapes should be used.
    pub fn use_color(&self) -> bool {
        match self.color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => std::io::IsTerminal::is_terminal(&std::io::stdout()),
        }
    }
}

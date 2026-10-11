//! Rendering of captured messages.

use std::time::{SystemTime, UNIX_EPOCH};

use ebpf_http_sniffer_common::flow::{FlowMessage, FlowTable};
use serde_json::json;

use crate::cli::Args;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";

/// Counters read back from the eBPF program when the capture stops.
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelStats {
    pub packets: u64,
    pub matched: u64,
    pub drops: u64,
    pub bytes: u64,
}

/// Counters kept by the userspace side.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub requests: u64,
    pub responses: u64,
    pub incomplete: u64,
}

pub struct Printer {
    json: bool,
    color: bool,
    show_headers: bool,
    show_body: bool,
    body_limit: usize,
    pub counts: Counts,
}

impl Printer {
    pub fn new(args: &Args) -> Self {
        Self {
            json: args.json,
            color: args.use_color(),
            show_headers: !args.no_headers,
            show_body: !args.no_body,
            body_limit: args.body_limit,
            counts: Counts::default(),
        }
    }

    /// Print and clear everything the flow table produced.
    pub fn print_all(&mut self, messages: &mut Vec<FlowMessage>) {
        for message in messages.drain(..) {
            if message.is_request() {
                self.counts.requests += 1;
            } else {
                self.counts.responses += 1;
            }
            if !message.message.body_complete {
                self.counts.incomplete += 1;
            }
            if self.json {
                self.print_json(&message);
            } else {
                self.print_human(&message);
            }
        }
    }

    fn print_human(&self, flow_message: &FlowMessage) {
        let message = &flow_message.message;
        let time = format_time(SystemTime::now());
        let dim = self.style(DIM);
        let reset = self.style(RESET);
        let bold = self.style(BOLD);

        let (arrow, colour) = if message.is_request() {
            ("\u{2192}", GREEN)
        } else {
            ("\u{2190}", CYAN)
        };
        let mut flags = String::new();
        if !message.body_complete {
            flags.push_str(&self.paint(" [incomplete]", YELLOW));
        }
        if message.truncated {
            flags.push_str(&self.paint(" [truncated]", YELLOW));
        }
        let lost = if message.skipped_bytes > 0 {
            format!(" [{} bytes skipped]", message.skipped_bytes)
        } else {
            String::new()
        };
        let (from, to) = if message.is_request() {
            (flow_message.client(), flow_message.server())
        } else {
            (flow_message.server(), flow_message.client())
        };

        println!(
            "{dim}[{time}]{reset} {} {bold}{}{reset} {dim}{} \u{2192} {}{reset}{lost}{flags}",
            self.paint(arrow, colour),
            message.start_line(),
            from.to_string_with_port(),
            to.to_string_with_port(),
        );

        if self.show_headers {
            for (name, value) in &message.headers {
                println!("    {dim}{name}{reset}: {value}");
            }
        }
        if self.show_body && !message.body.is_empty() {
            let (preview, shown, truncated) = self.preview(&message.body);
            let suffix = if truncated {
                format!(" \u{2026} (+{} bytes)", message.body.len() - shown)
            } else {
                String::new()
            };
            println!("    {dim}body{reset}: {preview}{suffix}");
        }
        println!();
    }

    fn print_json(&self, flow_message: &FlowMessage) {
        let message = &flow_message.message;
        let record = json!({
            "timestamp": format_time(SystemTime::now()),
            "direction": if message.is_request() { "request" } else { "response" },
            "method": message.method,
            "target": message.target,
            "version": message.version,
            "status": message.status,
            "reason": message.reason,
            "client": flow_message.client().to_string_with_port(),
            "server": flow_message.server().to_string_with_port(),
            "headers": message
                .headers
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect::<Vec<_>>(),
            "body": String::from_utf8_lossy(&message.body),
            "body_bytes": message.body.len(),
            "body_complete": message.body_complete,
            "truncated": message.truncated,
            "skipped_bytes": message.skipped_bytes,
        });
        println!("{record}");
    }

    /// Byte preview, escaped so that binary bodies cannot wreck the terminal.
    ///
    /// Returns the rendered text, how many body bytes it covers and whether
    /// more bytes were dropped.
    fn preview(&self, body: &[u8]) -> (String, usize, bool) {
        let limit = self.body_limit.min(body.len());
        (escape(&body[..limit]), limit, limit < body.len())
    }

    pub fn print_stats(&self, flows: &FlowTable, kernel: Option<KernelStats>) {
        let counts = self.counts;
        eprintln!();
        eprintln!(
            "{}",
            self.paint("\u{2500}\u{2500} summary \u{2500}\u{2500}", DIM)
        );
        eprintln!(
            "  messages   {} requests, {} responses, {} without a complete body",
            counts.requests, counts.responses, counts.incomplete
        );
        eprintln!(
            "  flows      {} tracked, {} evicted, {} stream resets",
            flows.flow_count(),
            flows.evicted_flows(),
            flows.dropped_segments()
        );
        match kernel {
            Some(stats) => eprintln!(
                "  kernel     {} packets inspected, {} segments captured, {} ring buffer drops, {} bytes copied",
                stats.packets, stats.matched, stats.drops, stats.bytes
            ),
            None => eprintln!("  kernel     statistics unavailable"),
        }
    }

    fn paint(&self, text: &str, code: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// The escape sequence, or nothing when colour is disabled.
    fn style(&self, code: &'static str) -> &'static str {
        if self.color {
            code
        } else {
            ""
        }
    }
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
}

/// `12:34:56.789` in local time.
fn format_time(time: SystemTime) -> String {
    let Ok(since_epoch) = time.duration_since(UNIX_EPOCH) else {
        return "??:??:??.???".to_string();
    };
    let seconds = since_epoch.as_secs() as libc::time_t;
    let millis = since_epoch.subsec_millis();
    let mut broken_down: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: both pointers are valid for the duration of the call; localtime_r
    // writes into `broken_down`.
    let ok = unsafe { libc::localtime_r(&seconds, &mut broken_down) };
    if ok.is_null() {
        return format!("{seconds}.{millis:03}");
    }
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        broken_down.tm_hour, broken_down.tm_min, broken_down.tm_sec, millis
    )
}

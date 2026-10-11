//! Loading, attaching and draining the eBPF program.

use std::{
    fs,
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use aya::{
    maps::{HashMap as BpfHashMap, PerCpuArray, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use ebpf_http_sniffer_common::{
    flow::{FlowConfig, FlowMessage, FlowTable},
    parse_event,
};
use tokio::io::unix::AsyncFd;

use crate::{
    cli::Args,
    output::{KernelStats, Printer},
};

/// Program and map names inside the eBPF object.
const PROGRAM: &str = "http_sniffer";
const MAP_EVENTS: &str = "EVENTS";
const MAP_PORTS: &str = "PORTS";
const MAP_STATS: &str = "STATS";

/// Must match `MAX_PORTS` in the kernel side program.
const PORT_CAPACITY: usize = 64;

/// How often timeouts are evaluated and pending messages are flushed.
const TICK: Duration = Duration::from_millis(100);

/// The eBPF object, embedded at compile time by `build.rs`.
const EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-http-sniffer-ebpf"));

pub async fn run(args: Args) -> Result<()> {
    raise_memlock_limit();

    let object = read_object(&args)?;
    let mut ebpf = Ebpf::load(&object).context("the eBPF object could not be loaded")?;

    let interfaces = resolve_interfaces(&args.iface)?;
    set_watched_ports(&mut ebpf, &args.port)?;
    // Keep the links alive for as long as the capture runs: dropping them
    // detaches the filters.
    let _links = attach(&mut ebpf, &interfaces)?;

    let events = ebpf
        .take_map(MAP_EVENTS)
        .context("the eBPF object has no EVENTS map")?;
    let mut ring =
        AsyncFd::new(RingBuf::try_from(events)?).context("EVENTS is not a ring buffer")?;

    log::info!(
        "watching {} on {}",
        args.port
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        interfaces.join(", ")
    );

    let mut printer = Printer::new(&args);
    let mut flows = FlowTable::new(FlowConfig::default());
    let mut messages: Vec<FlowMessage> = Vec::new();
    let started = Instant::now();
    let mut ticker = tokio::time::interval(TICK);

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to listen for Ctrl-C")?;
                break;
            }
            _ = ticker.tick() => {
                flows.tick(elapsed_ms(&started), &mut messages);
                printer.print_all(&mut messages);
            }
            guard = ring.readable_mut() => {
                let mut guard = guard.context("the ring buffer became unusable")?;
                let ring = guard.get_inner_mut();
                while let Some(record) = ring.next() {
                    let Some((header, payload)) = parse_event(&record) else {
                        log::debug!("dropping a malformed ring buffer record ({} bytes)", record.len());
                        continue;
                    };
                    if args.verbose {
                        log::debug!(
                            "segment v{} port {} -> {} seq {} len {} captured {} flags {:#04x}",
                            header.ip_version,
                            header.src_port,
                            header.dst_port,
                            header.seq,
                            header.payload_len,
                            header.captured_len,
                            header.tcp_flags,
                        );
                    }
                    flows.push_segment(elapsed_ms(&started), &header, payload, &mut messages);
                }
                guard.clear_ready();
                printer.print_all(&mut messages);
            }
        }
    }

    flows.flush_all(&mut messages);
    printer.print_all(&mut messages);
    printer.print_stats(&flows, kernel_stats(&mut ebpf));
    Ok(())
}

/// The eBPF object either comes from the embedded copy or from a file.
fn read_object(args: &Args) -> Result<Vec<u8>> {
    if let Some(path) = &args.ebpf_object {
        return fs::read(path).with_context(|| format!("could not read {}", path.display()));
    }
    if EBPF_OBJECT.is_empty() {
        bail!(
            "this binary does not contain the eBPF program (it was built with AYA_BUILD_SKIP); \
             rebuild it on a machine with the BPF toolchain, or pass --ebpf-object"
        );
    }
    Ok(EBPF_OBJECT.to_vec())
}

fn resolve_interfaces(requested: &[String]) -> Result<Vec<String>> {
    let mut available: Vec<String> = fs::read_dir("/sys/class/net")
        .context("could not list /sys/class/net")?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    available.sort();
    if available.is_empty() {
        bail!("no network interfaces found in /sys/class/net");
    }

    if requested.iter().any(|name| name == "all" || name == "*") {
        return Ok(available);
    }
    for name in requested {
        if !available.contains(name) {
            bail!(
                "interface {name} does not exist (available: {})",
                available.join(", ")
            );
        }
    }
    let mut selected = requested.to_vec();
    selected.sort();
    selected.dedup();
    Ok(selected)
}

/// Fill the `PORTS` map: the kernel program only copies segments whose source
/// or destination port is in it.
fn set_watched_ports(ebpf: &mut Ebpf, ports: &[u16]) -> Result<()> {
    if ports.is_empty() {
        bail!("at least one port must be watched");
    }
    if ports.len() > PORT_CAPACITY {
        bail!("at most {PORT_CAPACITY} ports can be watched at once");
    }
    let map = ebpf
        .map_mut(MAP_PORTS)
        .context("the eBPF object has no PORTS map")?;
    let mut watched: BpfHashMap<_, u16, u8> = BpfHashMap::try_from(map)?;
    for port in ports {
        watched
            .insert(port, 1u8, 0)
            .with_context(|| format!("could not watch port {port}"))?;
    }
    Ok(())
}

/// Attach the classifier to both directions of every interface.
///
/// A request leaves the client (egress) and reaches the server (ingress), so
/// both hooks are needed to see requests and responses of clients *and*
/// servers, including loopback traffic.
fn attach(
    ebpf: &mut Ebpf,
    interfaces: &[String],
) -> Result<Vec<aya::programs::tc::SchedClassifierLinkId>> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(PROGRAM)
        .with_context(|| format!("the eBPF object has no {PROGRAM} program"))?
        .try_into()
        .context("the program is not a TC classifier")?;
    program
        .load()
        .context("the kernel rejected the eBPF program (needs CAP_BPF/CAP_NET_ADMIN)")?;

    let mut links = Vec::new();
    for interface in interfaces {
        // The clsact qdisc has to exist before a filter can be attached to it;
        // adding it twice is harmless.
        let _ = tc::qdisc_add_clsact(interface);
        for attach_type in [TcAttachType::Egress, TcAttachType::Ingress] {
            match program.attach(interface, attach_type) {
                Ok(link) => {
                    log::debug!("attached to {interface} ({attach_type:?})");
                    links.push(link);
                }
                Err(err) => log::warn!("could not attach to {interface} ({attach_type:?}): {err}"),
            }
        }
    }
    if links.is_empty() {
        bail!("could not attach to any interface: eBPF needs root or CAP_BPF + CAP_NET_ADMIN");
    }
    Ok(links)
}

/// Sum the per-CPU counters maintained by the kernel side program.
fn kernel_stats(ebpf: &mut Ebpf) -> Option<KernelStats> {
    let map = ebpf.take_map(MAP_STATS)?;
    let counters: PerCpuArray<_, u64> = PerCpuArray::try_from(map).ok()?;
    let total = |index: u32| -> u64 {
        counters
            .get(&index, 0)
            .map(|values| values.iter().copied().sum())
            .unwrap_or(0)
    };
    Some(KernelStats {
        packets: total(0),
        matched: total(1),
        drops: total(2),
        bytes: total(3),
    })
}

fn elapsed_ms(started: &Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Kernels before 5.11 account BPF memory against `RLIMIT_MEMLOCK`.
fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `setrlimit` only reads the structure it is given.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if result != 0 {
        log::debug!("could not raise RLIMIT_MEMLOCK; only needed on older kernels");
    }
}

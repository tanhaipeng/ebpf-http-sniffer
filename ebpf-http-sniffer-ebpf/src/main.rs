//! Kernel side of the plaintext HTTP sniffer.
//!
//! A TC classifier that copies the TCP payload of segments travelling to or
//! from a watched port into a ring buffer. It deliberately parses the packet
//! from raw bytes (Ethernet/IP/TCP headers are stable protocol layouts) instead
//! of touching kernel structures, so the program needs no BTF, no `vmlinux.h`
//! and no per-kernel-version offsets.
//!
//! Everything above L4 - stream reassembly, HTTP framing - runs in userspace,
//! see the `ebpf-http-sniffer-common` and `ebpf-http-sniffer` crates.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use ebpf_http_sniffer_common::{
    parse_packet, tcp_flags, Direction, L4Packet, PacketEvent, MAX_PAYLOAD,
};

/// Ring buffer size. Must be a power of two, and should be a multiple of the
/// page size: 1 MiB holds roughly 1000 events.
const RING_SIZE_BYTES: u32 = 1 << 20;

/// Number of ports the userspace side may watch.
const MAX_PORTS: u32 = 64;

/// Bytes loaded to parse the L2-L4 headers. Ethernet with two VLAN tags (22) +
/// IPv6 with extension headers + TCP with maximum options fits comfortably.
const HEADER_WINDOW: usize = 128;

/// Payload staging area.
///
/// A whole segment does not fit on the 512 byte BPF stack, so the payload is
/// loaded into a per-CPU array instead: one `bpf_skb_load_bytes` call (which
/// also handles non-linear skbs) followed by one copy into the ring buffer.
#[repr(C)]
pub struct PayloadScratch {
    pub bytes: [u8; MAX_PAYLOAD],
}

/// Segments copied towards userspace, as [`PacketEvent`] records.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_SIZE_BYTES, 0);

/// Watched TCP ports. Filled in by the userspace loader before the program is
/// attached; a segment is captured when either its source or its destination
/// port is present.
#[map]
static PORTS: HashMap<u16, u8> = HashMap::with_max_entries(MAX_PORTS, 0);

/// Per-CPU staging area for the payload copy, see [`PayloadScratch`].
#[map]
static SCRATCH: PerCpuArray<PayloadScratch> = PerCpuArray::with_max_entries(1, 0);

/// Diagnostics, accumulated per CPU.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

const STAT_PACKETS: u32 = 0;
const STAT_MATCHED: u32 = 1;
const STAT_DROPS: u32 = 2;
const STAT_BYTES: u32 = 3;

#[inline(always)]
fn bump(index: u32) {
    add(index, 1);
}

#[inline(always)]
fn add(index: u32, value: u64) {
    if let Some(counter) = STATS.get_ptr_mut(index) {
        // Every CPU owns its slot, so a plain read-modify-write is race free.
        unsafe { *counter += value };
    }
}

#[classifier]
pub fn http_sniffer(ctx: TcContext) -> i32 {
    match try_http_sniffer(&ctx) {
        Ok(action) => action,
        Err(action) => action,
    }
}

fn try_http_sniffer(ctx: &TcContext) -> Result<i32, i32> {
    bump(STAT_PACKETS);

    let frame_len = ctx.len() as usize;
    if frame_len == 0 {
        return Ok(TC_ACT_PIPE);
    }

    let mut header = [0u8; HEADER_WINDOW];
    let loaded = match ctx.load_bytes(0, &mut header) {
        Ok(loaded) => loaded,
        Err(_) => return Ok(TC_ACT_PIPE),
    };
    let Some(packet) = parse_packet(&header[..loaded], frame_len) else {
        return Ok(TC_ACT_PIPE);
    };

    // Keep segments that are sent to a watched port (requests) or sent from one
    // (responses).
    let to_watched = PORTS.get_ptr(&packet.dst_port).is_some();
    let from_watched = PORTS.get_ptr(&packet.src_port).is_some();
    let direction = match (to_watched, from_watched) {
        (true, _) => Direction::ToServer,
        (false, true) => Direction::FromServer,
        (false, false) => return Ok(TC_ACT_PIPE),
    };
    bump(STAT_MATCHED);

    // Control segments carry no payload but tell the reassembler where a stream
    // starts (SYN) and ends (FIN/RST).
    let control = packet.has_flag(tcp_flags::SYN | tcp_flags::FIN | tcp_flags::RST);
    if packet.payload_len == 0 && !control {
        return Ok(TC_ACT_PIPE);
    }

    let copy_len = packet.payload_len.min(MAX_PAYLOAD);
    let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) else {
        bump(STAT_DROPS);
        return Ok(TC_ACT_PIPE);
    };
    // SAFETY: the reservation is exactly `size_of::<PacketEvent>()` bytes and
    // comes back 8 byte aligned. The ring buffer is not visible to userspace
    // until `submit`, so writing through the pointer is exclusive, and the
    // memory is uninitialised, which is why the pointer is taken from
    // `MaybeUninit` rather than by dereferencing the entry.
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).header.seq = packet.seq;
        (*event).header.ack = packet.ack;
        (*event).header.payload_len = packet.payload_len as u32;
        (*event).header.captured_len = 0;
        (*event).header.src_port = packet.src_port;
        (*event).header.dst_port = packet.dst_port;
        (*event).header.ip_version = packet.ip_version;
        (*event).header.direction = direction.as_u8();
        (*event).header.tcp_flags = packet.tcp_flags;
        (*event).header.src_addr = packet.src_addr;
        (*event).header.dst_addr = packet.dst_addr;
    }

    let copied = if copy_len == 0 {
        // Control segment: nothing to copy, but it is still reported.
        0
    } else {
        copy_payload(ctx, &packet, copy_len, event)
    };
    unsafe { (*event).header.captured_len = copied as u32 };

    if copied == 0 && !control {
        entry.discard(0);
        return Ok(TC_ACT_PIPE);
    }
    add(STAT_BYTES, copied as u64);
    entry.submit(0);
    Ok(TC_ACT_PIPE)
}

/// Copy up to `copy_len` payload bytes into the ring buffer reservation.
///
/// The payload is read through `bpf_skb_load_bytes`, which handles non-linear
/// skbs, into the per-CPU staging area and from there into the event.
#[inline(always)]
fn copy_payload(
    ctx: &TcContext,
    packet: &L4Packet,
    copy_len: usize,
    event: *mut PacketEvent,
) -> usize {
    let Some(scratch) = SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the per-CPU slot is only ever touched by the CPU currently
    // running this program, and `copy_len <= MAX_PAYLOAD` because the caller
    // clamps it, so the slice stays inside the scratch buffer.
    let destination =
        unsafe { core::slice::from_raw_parts_mut((*scratch).bytes.as_mut_ptr(), copy_len) };
    let loaded = match ctx.load_bytes(packet.payload_offset, destination) {
        Ok(loaded) => loaded,
        Err(_) => return 0,
    };
    if loaded == 0 {
        return 0;
    }
    // SAFETY: `loaded <= copy_len <= MAX_PAYLOAD` and the event payload array is
    // exactly `MAX_PAYLOAD` bytes; the reservation is exclusively owned.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (*scratch).bytes.as_ptr(),
            (*event).payload.as_mut_ptr(),
            loaded,
        );
    }
    loaded
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

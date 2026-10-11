//! Types shared by the eBPF program and its userspace loader.
//!
//! The kernel side is compiled for `bpfel-unknown-none` with `-Z build-std=core`,
//! so everything that is always compiled here must work without `std` *and*
//! without `alloc`. The two `alloc`-using modules ([`http`] and [`flow`]) are
//! therefore gated behind the `user` feature, which only the userspace crate
//! (and `cargo test`) enables.
#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "user"))]
extern crate alloc;

#[cfg(any(test, feature = "user"))]
pub mod flow;
#[cfg(any(test, feature = "user"))]
pub mod http;
pub mod packet;

pub use packet::{parse_packet, L4Packet};

/// Bytes of TCP payload carried by a single ring buffer event.
///
/// A single HTTP request head is almost always smaller than this, and the
/// userspace reassembler stitches together anything that was split across
/// packets (or truncated here).
pub const MAX_PAYLOAD: usize = 1024;

/// TCP control bits, as found in [`EventHeader::tcp_flags`].
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// Direction of a packet relative to the watched (server) port.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Neither the source nor the destination port is watched.
    Unknown = 0,
    /// Destination port is the watched one: traffic towards the server, i.e.
    /// the direction HTTP requests travel in.
    ToServer = 1,
    /// Source port is the watched one: traffic from the server, i.e. the
    /// direction HTTP responses travel in.
    FromServer = 2,
}

impl Direction {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::ToServer,
            2 => Self::FromServer,
            _ => Self::Unknown,
        }
    }

    /// True for payloads sent from the HTTP client to the HTTP server.
    pub const fn is_to_server(self) -> bool {
        matches!(self, Self::ToServer)
    }
}

/// Fixed size header of a ring buffer event.
///
/// Kept separate from the payload so the userspace side can describe an event
/// without copying up to [`MAX_PAYLOAD`] bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventHeader {
    /// TCP sequence number of the first payload byte.
    pub seq: u32,
    /// TCP acknowledgement number.
    pub ack: u32,
    /// Length of the TCP payload as advertised by the IP header.
    pub payload_len: u32,
    /// Bytes actually stored in [`PacketEvent::payload`].
    pub captured_len: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// 4 or 6.
    pub ip_version: u8,
    pub direction: u8,
    pub tcp_flags: u8,
    _reserved: u8,
    /// IPv4 addresses live in the first four bytes, IPv6 uses all sixteen.
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

/// A ring buffer record: one TCP segment's worth of payload plus its metadata.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    pub header: EventHeader,
    pub payload: [u8; MAX_PAYLOAD],
}

impl EventHeader {
    /// Size of the fixed header, i.e. the offset of the payload bytes inside a
    /// [`PacketEvent`] as seen by the userspace side.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Slice the payload out of a raw ring buffer record.
    pub fn payload<'a>(&self, record: &'a [u8]) -> &'a [u8] {
        if record.len() < Self::SIZE {
            return &[];
        }
        let len = (self.captured_len as usize).min(MAX_PAYLOAD);
        let end = Self::SIZE.saturating_add(len).min(record.len());
        &record[Self::SIZE..end]
    }

    pub const fn direction(&self) -> Direction {
        Direction::from_u8(self.direction)
    }

    /// True when the segment carried less payload than the packet advertised,
    /// i.e. [`MAX_PAYLOAD`] was reached (or the packet was cut short).
    pub const fn is_truncated(&self) -> bool {
        self.captured_len < self.payload_len
    }

    pub const fn flag(&self, flag: u8) -> bool {
        self.tcp_flags & flag != 0
    }

    /// True for the segments that open and close a connection, which carry no
    /// payload but tell the reassembler where a stream starts and ends.
    pub const fn is_control(&self) -> bool {
        self.flag(tcp_flags::SYN) || self.flag(tcp_flags::FIN) || self.flag(tcp_flags::RST)
    }
}

impl PacketEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// The payload must live at a fixed, well known offset inside the record: the
/// userspace side reads it back with a single unaligned load.
const _: () = assert!(core::mem::offset_of!(PacketEvent, payload) == EventHeader::SIZE);
const _: () = assert!(PacketEvent::SIZE == EventHeader::SIZE + MAX_PAYLOAD);

/// Decode a raw ring buffer record.
///
/// The ring buffer only guarantees 8 byte alignment for the reservation, so the
/// header is read with an unaligned load.
pub fn parse_event(record: &[u8]) -> Option<(EventHeader, &[u8])> {
    if record.len() < EventHeader::SIZE {
        return None;
    }
    // SAFETY: `record` is at least `EventHeader::SIZE` bytes long and
    // `read_unaligned` does not require any alignment.
    let header = unsafe { core::ptr::read_unaligned(record.as_ptr().cast::<EventHeader>()) };
    let payload = header.payload(record);
    Some((header, payload))
}

impl Default for EventHeader {
    fn default() -> Self {
        Self {
            seq: 0,
            ack: 0,
            payload_len: 0,
            captured_len: 0,
            src_port: 0,
            dst_port: 0,
            ip_version: 4,
            direction: Direction::Unknown.as_u8(),
            tcp_flags: 0,
            _reserved: 0,
            src_addr: [0; 16],
            dst_addr: [0; 16],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_record_round_trip() {
        let mut event = PacketEvent {
            header: EventHeader {
                seq: 0xdead_beef,
                ack: 0x1234_5678,
                payload_len: 7,
                captured_len: 7,
                src_port: 45678,
                dst_port: 80,
                ip_version: 4,
                direction: Direction::ToServer.as_u8(),
                tcp_flags: 0x18,
                ..Default::default()
            },
            payload: [0; MAX_PAYLOAD],
        };
        event.payload[..7].copy_from_slice(b"GET / H");

        // What the ring buffer hands to userspace: `PacketEvent::SIZE` bytes.
        let record = unsafe {
            core::slice::from_raw_parts(
                (&event as *const PacketEvent).cast::<u8>(),
                PacketEvent::SIZE,
            )
        };

        let (header, payload) = parse_event(record).expect("record decodes");
        assert_eq!(header.seq, 0xdead_beef);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.direction(), Direction::ToServer);
        assert_eq!(payload, b"GET / H");
        assert!(!header.is_truncated());
    }

    #[test]
    fn truncated_event_is_detected() {
        let header = EventHeader {
            payload_len: 4096,
            captured_len: (MAX_PAYLOAD as u32) - 1,
            ..Default::default()
        };
        assert!(header.is_truncated());
    }

    #[test]
    fn short_record_is_rejected() {
        assert!(parse_event(&[0u8; 4]).is_none());
    }
}

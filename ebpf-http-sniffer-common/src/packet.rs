//! Layer 2 to layer 4 parsing.
//!
//! Deliberately free of any kernel data structure: everything here works on the
//! raw packet bytes that a TC classifier can read with `bpf_skb_load_bytes`, so
//! there is no dependency on `vmlinux.h`, BTF or struct offsets that shift
//! between kernel versions.
//!
//! The entry point is [`parse_packet`], which answers exactly one question:
//! *"is this a TCP segment, and if so where does its payload start and how long
//! is it?"* Everything above that (stream reassembly, HTTP framing) happens in
//! userspace, see [`crate::flow`] and [`crate::http`].

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;
pub const ETH_P_8021Q_LEGACY: u16 = 0x9100;
pub const ETH_HDR_LEN: usize = 14;
pub const VLAN_TAG_LEN: usize = 4;
pub const IPPROTO_TCP: u8 = 6;
pub const TCP_HDR_MIN: usize = 20;
pub const IPV4_HDR_MIN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
/// Upper bound on IPv6 extension headers we are willing to walk.
const MAX_IPV6_EXT: usize = 4;
/// Upper bound on VLAN tags we are willing to walk.
const MAX_VLAN_TAGS: usize = 2;

/// A parsed TCP segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L4Packet {
    /// 4 or 6.
    pub ip_version: u8,
    /// IPv4 addresses are stored in the first four bytes.
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub tcp_flags: u8,
    /// Offset of the TCP payload inside the buffer that was parsed.
    pub payload_offset: usize,
    /// Length of the TCP payload, clamped to the bytes that really exist in the
    /// frame (so it can never point past the end of the packet).
    pub payload_len: usize,
}

impl L4Packet {
    /// True when no payload bytes are present (pure ACK, SYN, FIN...).
    pub const fn is_empty(&self) -> bool {
        self.payload_len == 0
    }

    pub const fn has_flag(&self, flag: u8) -> bool {
        self.tcp_flags & flag != 0
    }
}

#[inline]
fn be16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Parse a frame and return its TCP segment, if it carries one.
///
/// `buf` must contain everything from the start of the link layer header up to
/// at least the TCP header, but it does *not* have to contain the whole frame:
/// a TC program typically only loads the first ~128 bytes. `frame_len` is the
/// real length of the frame (`skb->len` on the kernel side, `buf.len()` when
/// parsing a complete packet); it is used to clamp lengths so that the returned
/// [`L4Packet::payload_len`] never exceeds the real payload.
pub fn parse_packet(buf: &[u8], frame_len: usize) -> Option<L4Packet> {
    // Ethernet framing is what TC sees on ethernet-like devices (including
    // `lo`). Devices without a link layer header (tun, ipip, ...) start right
    // at the IP header, so fall back to parsing the buffer as a bare IP packet.
    if let Some((offset, ethertype)) = ethernet_l2(buf) {
        if let Some(packet) = parse_l3(buf, offset, ethertype, frame_len) {
            return Some(packet);
        }
    }
    let ethertype = raw_ip_ethertype(buf)?;
    parse_l3(buf, 0, ethertype, frame_len)
}

/// Detect an Ethernet II header, skipping up to two VLAN tags.
fn ethernet_l2(buf: &[u8]) -> Option<(usize, u16)> {
    if buf.len() < ETH_HDR_LEN {
        return None;
    }
    let mut offset = ETH_HDR_LEN - 2;
    let mut ethertype = be16(buf, offset)?;
    offset += 2;
    for _ in 0..MAX_VLAN_TAGS {
        if !matches!(ethertype, ETH_P_8021Q | ETH_P_8021AD | ETH_P_8021Q_LEGACY) {
            break;
        }
        // VLAN header: 2 bytes TCI, 2 bytes encapsulated ethertype.
        ethertype = be16(buf, offset + 2)?;
        offset += VLAN_TAG_LEN;
    }
    Some((offset, ethertype))
}

fn raw_ip_ethertype(buf: &[u8]) -> Option<u16> {
    match buf.first()? >> 4 {
        4 => Some(ETH_P_IP),
        6 => Some(ETH_P_IPV6),
        _ => None,
    }
}

fn parse_l3(buf: &[u8], offset: usize, ethertype: u16, frame_len: usize) -> Option<L4Packet> {
    match ethertype {
        ETH_P_IP => parse_ipv4(buf, offset, frame_len),
        ETH_P_IPV6 => parse_ipv6(buf, offset, frame_len),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8], offset: usize, frame_len: usize) -> Option<L4Packet> {
    let header = buf.get(offset..offset + IPV4_HDR_MIN)?;
    if header[0] >> 4 != 4 {
        return None;
    }
    let ihl = (header[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_MIN || buf.len() < offset + ihl {
        return None;
    }
    if header[9] != IPPROTO_TCP {
        return None;
    }
    // Fragmented datagrams are skipped: only the first fragment carries the TCP
    // header and reassembling IP fragments is out of scope.
    let fragment = u16::from_be_bytes([header[6], header[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let l4_offset = offset + ihl;
    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    // `total_len` is authoritative, but some offload paths leave it at zero or
    // smaller than the header; fall back to the frame length in that case.
    let l4_len = if total_len > ihl {
        total_len - ihl
    } else {
        frame_len.saturating_sub(l4_offset)
    };

    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&header[12..16]);
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&header[16..20]);

    parse_tcp(buf, l4_offset, l4_len, frame_len, 4, src_addr, dst_addr)
}

fn parse_ipv6(buf: &[u8], offset: usize, frame_len: usize) -> Option<L4Packet> {
    let header = buf.get(offset..offset + IPV6_HDR_LEN)?;
    if header[0] >> 4 != 6 {
        return None;
    }
    let mut next_header = header[6];
    let mut cursor = offset + IPV6_HDR_LEN;
    let payload_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let mut l4_len = if payload_len > 0 {
        payload_len
    } else {
        frame_len.saturating_sub(cursor)
    };

    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&header[8..24]);
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&header[24..40]);

    for _ in 0..MAX_IPV6_EXT {
        // Hop-by-hop (0), routing (43), fragment (44), destination options (60)
        // and authentication header (51) all chain to the next header.
        if !matches!(next_header, 0 | 43 | 44 | 51 | 60) {
            break;
        }
        // Fragmented IPv6 packets are skipped for the same reason as IPv4 ones.
        if next_header == 44 {
            return None;
        }
        let ext = buf.get(cursor..cursor + 2)?;
        let ext_len = if next_header == 51 {
            // AH lengths are counted in 4 byte units, excluding the first 8.
            (ext[1] as usize + 2) * 4
        } else {
            // The other extension headers count 8 byte units, excluding the
            // first 8 bytes.
            (ext[1] as usize + 1) * 8
        };
        next_header = ext[0];
        cursor = cursor.checked_add(ext_len)?;
        l4_len = l4_len.saturating_sub(ext_len);
    }

    if next_header != IPPROTO_TCP {
        return None;
    }
    parse_tcp(buf, cursor, l4_len, frame_len, 6, src_addr, dst_addr)
}

#[allow(clippy::too_many_arguments)]
fn parse_tcp(
    buf: &[u8],
    offset: usize,
    l4_len: usize,
    frame_len: usize,
    ip_version: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
) -> Option<L4Packet> {
    let header = buf.get(offset..offset + TCP_HDR_MIN)?;
    let data_offset = (header[12] >> 4) as usize * 4;
    if data_offset < TCP_HDR_MIN {
        return None;
    }

    let payload_offset = offset.checked_add(data_offset)?;
    // Bytes of this frame that follow the TCP header.
    let frame_tail = frame_len.saturating_sub(payload_offset);
    let payload_len = l4_len.saturating_sub(data_offset).min(frame_tail);

    Some(L4Packet {
        ip_version,
        src_addr,
        dst_addr,
        src_port: u16::from_be_bytes([header[0], header[1]]),
        dst_port: u16::from_be_bytes([header[2], header[3]]),
        seq: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        ack: u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
        tcp_flags: header[13],
        payload_offset,
        payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";

    struct FrameBuilder {
        bytes: Vec<u8>,
        /// Offset of the IP header, remembered so the length fields can be
        /// patched once the whole frame is known.
        ip_offset: Option<(usize, bool)>,
    }

    impl FrameBuilder {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                ip_offset: None,
            }
        }

        fn eth(mut self, ethertype: u16) -> Self {
            self.bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
            self.bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
            self.bytes.extend_from_slice(&ethertype.to_be_bytes());
            self
        }

        fn vlan(mut self, vlan_id: u16, ethertype: u16) -> Self {
            self.bytes.extend_from_slice(&vlan_id.to_be_bytes());
            self.bytes.extend_from_slice(&ethertype.to_be_bytes());
            self
        }

        fn ipv4(mut self, src: [u8; 4], dst: [u8; 4], protocol: u8, options: usize) -> Self {
            self.ip_offset = Some((self.bytes.len(), false));
            let ihl = 5 + options / 4;
            self.bytes.push((4 << 4) | ihl as u8);
            self.bytes.push(0);
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // total length, patched later
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // id
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment
            self.bytes.push(64);
            self.bytes.push(protocol);
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // checksum
            self.bytes.extend_from_slice(&src);
            self.bytes.extend_from_slice(&dst);
            self.bytes.extend(std::iter::repeat_n(0u8, options));
            self
        }

        fn ipv6(mut self, next_header: u8) -> Self {
            self.ip_offset = Some((self.bytes.len(), true));
            self.bytes.push(6 << 4);
            self.bytes.extend_from_slice(&[0, 0, 0]);
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // payload length, patched later
            self.bytes.push(next_header);
            self.bytes.push(64);
            self.bytes
                .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            self.bytes
                .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            self
        }

        fn hop_by_hop(mut self, next_header: u8) -> Self {
            self.bytes.push(next_header);
            self.bytes.push(0); // 8 bytes total
            self.bytes.extend_from_slice(&[0u8; 6]);
            self
        }

        fn tcp(mut self, src_port: u16, dst_port: u16, seq: u32, options: usize) -> Self {
            let data_offset = 5 + options / 4;
            self.bytes.extend_from_slice(&src_port.to_be_bytes());
            self.bytes.extend_from_slice(&dst_port.to_be_bytes());
            self.bytes.extend_from_slice(&seq.to_be_bytes());
            self.bytes.extend_from_slice(&1u32.to_be_bytes()); // ack
            self.bytes.push((data_offset as u8) << 4);
            self.bytes.push(0x18); // PSH|ACK
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // window
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // checksum
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // urgent
            self.bytes.extend(std::iter::repeat_n(0u8, options));
            self
        }

        fn payload(mut self) -> Self {
            self.bytes.extend_from_slice(PAYLOAD);
            self
        }

        fn build(self) -> Vec<u8> {
            let mut bytes = self.bytes;
            // Patch the IP length fields now that the whole frame is known
            // (including TCP options and IPv6 extension headers).
            if let Some((offset, is_v6)) = self.ip_offset {
                let l3_len = bytes.len() - offset;
                if is_v6 {
                    let payload_len = (l3_len - IPV6_HDR_LEN) as u16;
                    bytes[offset + 4..offset + 6].copy_from_slice(&payload_len.to_be_bytes());
                } else {
                    bytes[offset + 2..offset + 4].copy_from_slice(&(l3_len as u16).to_be_bytes());
                }
            }
            bytes
        }
    }

    fn parse(bytes: &[u8]) -> L4Packet {
        parse_packet(bytes, bytes.len()).expect("packet parses")
    }

    #[test]
    fn ipv4_tcp_is_parsed() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0)
            .tcp(45678, 80, 0x1122_3344, 0)
            .payload()
            .build();
        let packet = parse(&frame);
        assert_eq!(packet.ip_version, 4);
        assert_eq!(packet.src_port, 45678);
        assert_eq!(packet.dst_port, 80);
        assert_eq!(packet.seq, 0x1122_3344);
        assert_eq!(&packet.src_addr[..4], &[10, 0, 0, 1]);
        assert_eq!(&packet.dst_addr[..4], &[10, 0, 0, 2]);
        assert_eq!(packet.payload_len, PAYLOAD.len());
        assert_eq!(
            &frame[packet.payload_offset..][..packet.payload_len],
            PAYLOAD
        );
    }

    #[test]
    fn vlan_tagged_frame_is_parsed() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_8021Q)
            .vlan(100, ETH_P_IP)
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], IPPROTO_TCP, 0)
            .tcp(50000, 8080, 1, 0)
            .payload()
            .build();
        let packet = parse(&frame);
        assert_eq!(packet.dst_port, 8080);
        assert_eq!(packet.payload_len, PAYLOAD.len());
    }

    #[test]
    fn qinq_double_tagged_frame_is_parsed() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_8021AD)
            .vlan(100, ETH_P_8021Q)
            .vlan(200, ETH_P_IP)
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], IPPROTO_TCP, 0)
            .tcp(50000, 80, 1, 0)
            .payload()
            .build();
        assert_eq!(parse(&frame).dst_port, 80);
    }

    #[test]
    fn ipv4_options_and_tcp_options_shift_the_payload() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 1, 1, 1], [10, 1, 1, 2], IPPROTO_TCP, 8)
            .tcp(1234, 80, 7, 12)
            .payload()
            .build();
        let packet = parse(&frame);
        assert_eq!(packet.payload_len, PAYLOAD.len());
        assert_eq!(
            &frame[packet.payload_offset..][..packet.payload_len],
            PAYLOAD
        );
    }

    #[test]
    fn ipv6_tcp_is_parsed() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IPV6)
            .ipv6(IPPROTO_TCP)
            .tcp(40000, 80, 42, 0)
            .payload()
            .build();
        let packet = parse(&frame);
        assert_eq!(packet.ip_version, 6);
        assert_eq!(packet.src_addr[15], 1);
        assert_eq!(packet.dst_addr[15], 2);
        assert_eq!(packet.payload_len, PAYLOAD.len());
    }

    #[test]
    fn ipv6_extension_header_is_walked() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IPV6)
            .ipv6(0)
            .hop_by_hop(IPPROTO_TCP)
            .tcp(40000, 8080, 42, 0)
            .payload()
            .build();
        let packet = parse(&frame);
        assert_eq!(packet.dst_port, 8080);
        assert_eq!(packet.payload_len, PAYLOAD.len());
    }

    #[test]
    fn bare_ip_packet_without_link_layer_is_parsed() {
        let mut builder = FrameBuilder::new();
        builder = builder
            .ipv4([10, 9, 9, 1], [10, 9, 9, 2], IPPROTO_TCP, 0)
            .tcp(5555, 80, 3, 0)
            .payload();
        let frame = builder.build();
        assert_eq!(parse(&frame).dst_port, 80);
    }

    #[test]
    fn udp_and_fragments_are_skipped() {
        let udp = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, 0)
            .tcp(1, 80, 1, 0)
            .payload()
            .build();
        assert!(parse_packet(&udp, udp.len()).is_none());

        let mut fragmented = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0)
            .tcp(1, 80, 1, 0)
            .payload()
            .build();
        // Set the "more fragments" bit in the IPv4 flags field.
        fragmented[ETH_HDR_LEN + 6] = 0x20;
        assert!(parse_packet(&fragmented, fragmented.len()).is_none());
    }

    #[test]
    fn truncated_header_is_rejected() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0)
            .tcp(1, 80, 1, 0)
            .payload()
            .build();
        // Only the ethernet + partial IP header are available.
        assert!(parse_packet(&frame[..ETH_HDR_LEN + 10], frame.len()).is_none());
    }

    #[test]
    fn payload_length_is_clamped_to_the_frame() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0)
            .tcp(1, 80, 1, 0)
            .payload()
            .build();
        // Pretend the frame is shorter than the IP header claims: the parser is
        // fed only the headers, exactly like a TC program loading 128 bytes.
        let header_only = &frame[..ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN];
        let packet = parse_packet(header_only, frame.len()).expect("headers parse");
        assert_eq!(packet.payload_len, PAYLOAD.len());
        // ... but never more than the frame can hold.
        let short_frame_len = packet.payload_offset + 4;
        let packet = parse_packet(header_only, short_frame_len).expect("headers parse");
        assert_eq!(packet.payload_len, 4);
    }

    #[test]
    fn syn_without_payload_reports_zero_length() {
        let frame = FrameBuilder::new()
            .eth(ETH_P_IP)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0)
            .tcp(1, 80, 1, 0)
            .build();
        let packet = parse(&frame);
        assert!(packet.is_empty());
    }
}

//! Per-connection TCP reassembly and flow tracking.
//!
//! The eBPF program sees individual TCP segments: they can be captured
//! mid-stream, arrive out of order, be duplicated by retransmissions and be
//! truncated by [`crate::MAX_PAYLOAD`]. This module turns that into an ordered
//! byte stream per direction, feeds it to the HTTP parser and reports finished
//! messages.
//!
//! Two mechanisms keep the stream aligned:
//!
//! * `SYN` segments (also reported by the eBPF program, although they carry no
//!   payload) pin the start of a direction, so a connection captured from its
//!   first packet is always exactly aligned.
//! * When capture starts mid-connection there is no such anchor, so the first
//!   segment of a direction is buffered briefly ("warm up") until either a
//!   segment that looks like the start of an HTTP message arrives - at which
//!   point everything buffered is flushed in sequence number order - or the
//!   warm-up deadline expires. Without this, a single reordered first segment
//!   would misalign the whole stream.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    http::{self, Http1Parser, HttpMessage, Limits},
    tcp_flags, EventHeader,
};

/// One end of a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// 4 or 6; part of the ordering so IPv4 and IPv6 never compare equal.
    pub ip_version: u8,
    /// IPv4 addresses live in the first four bytes.
    pub addr: [u8; 16],
    pub port: u16,
}

impl Endpoint {
    pub const fn new(ip_version: u8, addr: [u8; 16], port: u16) -> Self {
        Self {
            ip_version,
            addr,
            port,
        }
    }

    pub fn ip(&self) -> IpAddr {
        if self.ip_version == 6 {
            IpAddr::V6(Ipv6Addr::from(self.addr))
        } else {
            IpAddr::V4(Ipv4Addr::new(
                self.addr[0],
                self.addr[1],
                self.addr[2],
                self.addr[3],
            ))
        }
    }

    /// `10.0.0.1:52344` or `[2001:db8::1]:52344`.
    pub fn to_string_with_port(&self) -> String {
        match self.ip() {
            IpAddr::V4(addr) => alloc::format!("{addr}:{}", self.port),
            IpAddr::V6(addr) => alloc::format!("[{addr}]:{}", self.port),
        }
    }
}

/// Connection identity, independent of which direction a packet travels in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl FlowKey {
    /// Canonical key: both directions of a connection map to the same value.
    pub fn new(from: Endpoint, to: Endpoint) -> Self {
        if from <= to {
            Self { a: from, b: to }
        } else {
            Self { a: to, b: from }
        }
    }

    /// Index of the half that carries traffic from `from` to the other end.
    pub fn half_of(&self, from: &Endpoint) -> usize {
        usize::from(*from != self.a)
    }

    /// The endpoint that sends on the given half.
    pub fn sender_of(&self, half: usize) -> Endpoint {
        if half == 0 {
            self.a
        } else {
            self.b
        }
    }

    /// The endpoint that receives on the given half.
    pub fn receiver_of(&self, half: usize) -> Endpoint {
        if half == 0 {
            self.b
        } else {
            self.a
        }
    }
}

/// A parsed HTTP message together with the connection it belongs to.
#[derive(Clone, Debug)]
pub struct FlowMessage {
    pub key: FlowKey,
    /// Endpoint that sent the message.
    pub sender: Endpoint,
    /// Endpoint the message is addressed to.
    pub receiver: Endpoint,
    /// True when the sender sits on a watched (server) port, i.e. the direction
    /// the eBPF program classified the packet with.
    pub from_server_port: bool,
    pub message: HttpMessage,
}

impl FlowMessage {
    pub fn is_request(&self) -> bool {
        self.message.is_request()
    }

    /// The HTTP client: the sender of a request, the receiver of a response.
    pub fn client(&self) -> Endpoint {
        if self.is_request() {
            self.sender
        } else {
            self.receiver
        }
    }

    /// The HTTP server: the receiver of a request, the sender of a response.
    pub fn server(&self) -> Endpoint {
        if self.is_request() {
            self.receiver
        } else {
            self.sender
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FlowConfig {
    pub http: Limits,
    /// Flush a flow's in-flight message after this much silence.
    pub idle_timeout_ms: u64,
    /// After this long without progress, skip the hole in front of buffered
    /// out-of-order segments so parsing can continue.
    pub gap_timeout_ms: u64,
    /// How long the first segment of a direction is buffered while waiting for
    /// a segment that clearly starts an HTTP message.
    pub warmup_ms: u64,
    /// Maximum number of tracked connections.
    pub max_flows: usize,
    /// Maximum number of buffered out-of-order segments per direction.
    pub max_pending_segments: usize,
    /// Maximum number of buffered out-of-order bytes per direction.
    pub max_pending_bytes: usize,
    /// A hole larger than this is treated as a stream reset rather than
    /// buffered.
    pub max_gap_bytes: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            http: Limits::default(),
            idle_timeout_ms: 2_000,
            gap_timeout_ms: 500,
            warmup_ms: 50,
            max_flows: 4096,
            max_pending_segments: 64,
            max_pending_bytes: 256 * 1024,
            max_gap_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug)]
struct Half {
    /// Sequence number of the next byte to hand to the parser; `None` until the
    /// first segment of this direction is seen.
    next_seq: Option<u32>,
    /// Segments held back, keyed by sequence number.
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    parser: Http1Parser,
    /// Last time this direction made progress; drives the gap timeout.
    last_progress_ms: u64,
    /// While warming up, segments are buffered instead of being fed to the
    /// parser straight away.
    warmup_deadline_ms: Option<u64>,
    /// True when the sender of this half sits on a watched port.
    from_server_port: bool,
    fin_seen: bool,
}

impl Half {
    fn new(limits: Limits, now_ms: u64) -> Self {
        Self {
            next_seq: None,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            parser: Http1Parser::new(limits),
            last_progress_ms: now_ms,
            warmup_deadline_ms: None,
            from_server_port: false,
            fin_seen: false,
        }
    }

    /// True while the first bytes of this direction have not been fed yet.
    fn is_warming_up(&self) -> bool {
        self.warmup_deadline_ms.is_some()
    }

    fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if let Some(next) = self.next_seq.as_mut() {
            *next = next.wrapping_add(data.len() as u32);
        }
        self.parser.push(data);
    }

    /// Feed one segment; completed messages are appended to `messages`.
    ///
    /// Returns true when the stream had to be resynchronised, i.e. captured
    /// bytes were skipped.
    fn push_segment(
        &mut self,
        config: &FlowConfig,
        now_ms: u64,
        header: &EventHeader,
        data: &[u8],
        messages: &mut Vec<HttpMessage>,
    ) -> bool {
        // A SYN pins the start of the stream, so everything that follows can be
        // placed exactly.
        if header.flag(tcp_flags::SYN) && !header.flag(tcp_flags::ACK) {
            self.reset(header.seq.wrapping_add(1), now_ms);
        }
        if header.flag(tcp_flags::FIN) {
            self.fin_seen = true;
        }
        if data.is_empty() {
            self.collect(messages);
            return false;
        }

        if self.is_warming_up() {
            let buffered = self.buffer(config, header.seq, data);
            self.last_progress_ms = now_ms;
            // Flush as soon as the buffered bytes clearly contain the start of
            // an HTTP message: at that point the alignment is known and waiting
            // longer cannot change the order in which bytes must be fed.
            let anchored = self.buffered_view_is_anchored();
            if !buffered || anchored || self.pending.len() > config.max_pending_segments {
                self.flush_warmup(messages);
            }
            self.collect(messages);
            return false;
        }

        let Some(next) = self.next_seq else {
            // First segment of this direction. If it clearly starts an HTTP
            // message there is nothing to align, otherwise buffer it briefly in
            // case an earlier segment shows up.
            if http::starts_with_message(data) {
                self.next_seq = Some(header.seq);
                self.append(data);
                self.last_progress_ms = now_ms;
            } else {
                self.warmup_deadline_ms = Some(now_ms.saturating_add(config.warmup_ms));
                self.buffer(config, header.seq, data);
                self.last_progress_ms = now_ms;
            }
            self.collect(messages);
            return false;
        };

        let mut dropped = false;
        let diff = wrapping_distance(header.seq, next);
        if diff == 0 {
            self.append(data);
            self.last_progress_ms = now_ms;
            self.drain_pending(now_ms);
        } else if diff < 0 {
            // Retransmission or overlap: keep only the bytes we have not seen.
            let skip = diff.unsigned_abs() as usize;
            if skip < data.len() {
                self.append(&data[skip..]);
                self.last_progress_ms = now_ms;
                self.drain_pending(now_ms);
            }
        } else {
            let gap = diff as usize;
            if gap > config.max_gap_bytes
                || self.pending.len() >= config.max_pending_segments
                || self.pending_bytes + data.len() > config.max_pending_bytes
            {
                // Too large to be a reordering: treat it as a fresh stream.
                dropped = true;
                self.reset_stream(header.seq, data, now_ms);
            } else {
                self.pending
                    .entry(header.seq)
                    .or_insert_with(|| data.to_vec());
                self.pending_bytes += data.len();
            }
        }
        self.collect(messages);
        dropped
    }

    /// Force the stream to restart at `seq` from a SYN. Anything in flight
    /// belongs to the previous incarnation of this 4-tuple and is dropped.
    fn reset(&mut self, seq: u32, now_ms: u64) {
        self.parser.flush();
        let _ = self.parser.take_messages();
        self.pending.clear();
        self.pending_bytes = 0;
        self.warmup_deadline_ms = None;
        self.next_seq = Some(seq);
        self.last_progress_ms = now_ms;
        self.fin_seen = false;
    }

    /// Buffer a segment while warming up. Returns false when it was dropped.
    fn buffer(&mut self, config: &FlowConfig, seq: u32, data: &[u8]) -> bool {
        if self.pending_bytes + data.len() > config.max_pending_bytes {
            return false;
        }
        self.pending.entry(seq).or_insert_with(|| data.to_vec());
        self.pending_bytes += data.len();
        true
    }

    /// Concatenation of every buffered segment, in sequence order.
    ///
    /// Holes and overlaps make this unsuitable for feeding the parser; it is
    /// only used to look for a message start, which decides when warm-up can
    /// end.
    fn buffered_scan(&self) -> Vec<u8> {
        let mut scan = Vec::new();
        for data in self.pending.values() {
            scan.extend_from_slice(data);
        }
        scan
    }

    /// True when the buffered bytes start with a plausible HTTP message, which
    /// means the ordering of the buffered segments is settled.
    fn buffered_view_is_anchored(&self) -> bool {
        http::contains_message_start(&self.buffered_scan())
    }

    /// Feed everything buffered during warm-up to the parser, in sequence
    /// number order, reporting any hole in between.
    fn flush_warmup(&mut self, messages: &mut Vec<HttpMessage>) {
        self.warmup_deadline_ms = None;
        let Some((&lowest, _)) = self.pending.iter().next() else {
            return;
        };
        self.next_seq = Some(lowest);
        self.pending_bytes = 0;
        for (seq, data) in core::mem::take(&mut self.pending) {
            let next = self.next_seq.unwrap_or(seq);
            let diff = wrapping_distance(seq, next);
            if diff > 0 {
                // A hole: tell the parser so it resynchronises.
                self.parser.notify_gap();
                self.collect(messages);
                self.next_seq = Some(seq);
            }
            let skip = if diff < 0 {
                diff.unsigned_abs() as usize
            } else {
                0
            };
            if skip < data.len() {
                self.append(&data[skip..]);
            }
        }
    }

    /// Called from [`FlowTable::tick`]: flush a warm-up that never resolved.
    fn tick_warmup(&mut self, now_ms: u64, messages: &mut Vec<HttpMessage>) {
        if let Some(deadline) = self.warmup_deadline_ms {
            if now_ms >= deadline {
                self.flush_warmup(messages);
                self.collect(messages);
            }
        }
    }

    fn collect(&mut self, messages: &mut Vec<HttpMessage>) {
        messages.append(&mut self.parser.take_messages());
    }

    /// Skip forward to `seq`, discarding buffered segments that can never be
    /// completed, and mark the parser's in-flight message as incomplete.
    fn reset_stream(&mut self, seq: u32, data: &[u8], now_ms: u64) {
        self.parser.notify_gap();
        self.pending.clear();
        self.pending_bytes = 0;
        self.next_seq = Some(seq);
        self.append(data);
        self.last_progress_ms = now_ms;
    }

    /// After a hole was given up on, jump to the oldest buffered segment.
    fn skip_gap(&mut self, messages: &mut Vec<HttpMessage>) {
        let Some((&seq, _)) = self.pending.iter().next() else {
            return;
        };
        self.parser.notify_gap();
        self.collect(messages);
        let dropped: Vec<u32> = self.pending.range(..seq).map(|(key, _)| *key).collect();
        for key in dropped {
            if let Some(data) = self.pending.remove(&key) {
                self.pending_bytes = self.pending_bytes.saturating_sub(data.len());
            }
        }
        self.next_seq = Some(seq);
        self.drain_pending(0);
    }

    /// Append buffered segments that became contiguous.
    fn drain_pending(&mut self, now_ms: u64) {
        loop {
            let Some(next) = self.next_seq else { return };
            let Some((&seq, _)) = self.pending.iter().next() else {
                return;
            };
            let diff = wrapping_distance(seq, next);
            if diff > 0 {
                return;
            }
            let Some(data) = self.pending.remove(&seq) else {
                return;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(data.len());
            let skip = diff.unsigned_abs() as usize;
            if skip < data.len() {
                self.append(&data[skip..]);
                if now_ms > 0 {
                    self.last_progress_ms = now_ms;
                }
            }
        }
    }

    fn flush(&mut self, messages: &mut Vec<HttpMessage>) {
        self.parser.flush();
        self.collect(messages);
    }

    fn expect_bodyless_response(&mut self) {
        self.parser.expect_bodyless_response();
    }
}

#[derive(Debug)]
struct Flow {
    halves: [Half; 2],
    last_seen_ms: u64,
}

impl Flow {
    fn new(limits: Limits, now_ms: u64) -> Self {
        Self {
            halves: [Half::new(limits, now_ms), Half::new(limits, now_ms)],
            last_seen_ms: now_ms,
        }
    }

    fn is_closed(&self) -> bool {
        self.halves[0].fin_seen && self.halves[1].fin_seen
    }
}

/// Tracks connections and turns captured segments into HTTP messages.
#[derive(Debug)]
pub struct FlowTable {
    flows: BTreeMap<FlowKey, Flow>,
    config: FlowConfig,
    evicted: u64,
    dropped_segments: u64,
}

impl FlowTable {
    pub fn new(config: FlowConfig) -> Self {
        Self {
            flows: BTreeMap::new(),
            config,
            evicted: 0,
            dropped_segments: 0,
        }
    }

    pub fn config(&self) -> &FlowConfig {
        &self.config
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn evicted_flows(&self) -> u64 {
        self.evicted
    }

    /// Segments that arrived with a hole too large to be a reordering.
    pub fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    /// Feed one captured segment.
    ///
    /// Segments without payload are still meaningful when they carry `SYN`,
    /// `FIN` or `RST`.
    pub fn push_segment(
        &mut self,
        now_ms: u64,
        header: &EventHeader,
        payload: &[u8],
        out: &mut Vec<FlowMessage>,
    ) {
        if payload.is_empty() && !header.is_control() {
            return;
        }
        let sender = Endpoint::new(header.ip_version, header.src_addr, header.src_port);
        let receiver = Endpoint::new(header.ip_version, header.dst_addr, header.dst_port);
        let key = FlowKey::new(sender, receiver);
        let half = key.half_of(&sender);

        if !self.flows.contains_key(&key) && self.flows.len() >= self.config.max_flows {
            self.evict_oldest(out);
        }

        let config = self.config;
        let mut dropped = false;
        let flow = self
            .flows
            .entry(key)
            .or_insert_with(|| Flow::new(config.http, now_ms));
        flow.last_seen_ms = now_ms;
        flow.halves[half].from_server_port =
            header.direction == crate::Direction::FromServer.as_u8();

        let mut messages = Vec::new();
        if flow.halves[half].push_segment(&config, now_ms, header, payload, &mut messages) {
            dropped = true;
        }

        // A HEAD request means the response in the other direction has no body.
        let other = 1 - half;
        for message in &messages {
            if message.is_request() && message.method.as_deref() == Some("HEAD") {
                flow.halves[other].expect_bodyless_response();
            }
        }
        let from_server_port = flow.halves[half].from_server_port;
        for message in messages {
            out.push(FlowMessage {
                key,
                sender,
                receiver,
                from_server_port,
                message,
            });
        }

        let closed_by_reset = header.flag(tcp_flags::RST);
        if closed_by_reset || flow.is_closed() {
            self.remove_flow(&key, out);
        }
        if dropped {
            self.dropped_segments += 1;
        }
    }

    /// Periodic maintenance: resolve warm-up and gap timeouts, flush and evict
    /// connections that went quiet.
    pub fn tick(&mut self, now_ms: u64, out: &mut Vec<FlowMessage>) {
        let config = self.config;
        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        let mut expired = Vec::new();
        for key in keys {
            let Some(flow) = self.flows.get_mut(&key) else {
                continue;
            };
            for half in 0..2 {
                let mut messages = Vec::new();
                flow.halves[half].tick_warmup(now_ms, &mut messages);
                let stalled = now_ms.saturating_sub(flow.halves[half].last_progress_ms)
                    > config.gap_timeout_ms
                    && !flow.halves[half].is_warming_up();
                if stalled && !flow.halves[half].pending.is_empty() {
                    flow.halves[half].skip_gap(&mut messages);
                }
                let from_server_port = flow.halves[half].from_server_port;
                for message in messages {
                    out.push(FlowMessage {
                        key,
                        sender: key.sender_of(half),
                        receiver: key.receiver_of(half),
                        from_server_port,
                        message,
                    });
                }
            }
            if now_ms.saturating_sub(flow.last_seen_ms) > config.idle_timeout_ms {
                expired.push(key);
            }
        }
        for key in expired {
            self.remove_flow(&key, out);
        }
    }

    /// Flush and drop every flow, e.g. on shutdown.
    pub fn flush_all(&mut self, out: &mut Vec<FlowMessage>) {
        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        for key in keys {
            self.remove_flow(&key, out);
        }
    }

    fn evict_oldest(&mut self, out: &mut Vec<FlowMessage>) {
        let Some(key) = self
            .flows
            .iter()
            .min_by_key(|(_, flow)| flow.last_seen_ms)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.evicted += 1;
        self.remove_flow(&key, out);
    }

    fn remove_flow(&mut self, key: &FlowKey, out: &mut Vec<FlowMessage>) {
        let Some(mut flow) = self.flows.remove(key) else {
            return;
        };
        for half in 0..2 {
            let mut messages = Vec::new();
            flow.halves[half].flush(&mut messages);
            let from_server_port = flow.halves[half].from_server_port;
            for message in messages {
                out.push(FlowMessage {
                    key: *key,
                    sender: key.sender_of(half),
                    receiver: key.receiver_of(half),
                    from_server_port,
                    message,
                });
            }
        }
    }
}

/// Signed distance between two sequence numbers, correct across the 32 bit
/// wrap-around as long as the real distance is below 2^31 (always true for a
/// TCP window).
fn wrapping_distance(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Direction;

    const CLIENT: [u8; 16] = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const SERVER: [u8; 16] = [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const CLIENT_PORT: u16 = 52344;
    const SERVER_PORT: u16 = 80;

    fn header(seq: u32, from_client: bool, payload_len: usize, flags: u8) -> EventHeader {
        let (src_addr, dst_addr, src_port, dst_port, direction) = if from_client {
            (
                CLIENT,
                SERVER,
                CLIENT_PORT,
                SERVER_PORT,
                Direction::ToServer,
            )
        } else {
            (
                SERVER,
                CLIENT,
                SERVER_PORT,
                CLIENT_PORT,
                Direction::FromServer,
            )
        };
        EventHeader {
            seq,
            payload_len: payload_len as u32,
            captured_len: payload_len as u32,
            src_port,
            dst_port,
            ip_version: 4,
            direction: direction.as_u8(),
            tcp_flags: flags,
            src_addr,
            dst_addr,
            ..Default::default()
        }
    }

    fn client_header(seq: u32, payload_len: usize) -> EventHeader {
        header(seq, true, payload_len, tcp_flags::PSH | tcp_flags::ACK)
    }

    fn server_header(seq: u32, payload_len: usize) -> EventHeader {
        header(seq, false, payload_len, tcp_flags::PSH | tcp_flags::ACK)
    }

    fn table() -> FlowTable {
        FlowTable::new(FlowConfig::default())
    }

    fn push(
        table: &mut FlowTable,
        now_ms: u64,
        header: &EventHeader,
        data: &[u8],
    ) -> Vec<FlowMessage> {
        let mut out = Vec::new();
        table.push_segment(now_ms, header, data, &mut out);
        out
    }

    fn push_client(table: &mut FlowTable, now_ms: u64, seq: u32, data: &[u8]) -> Vec<FlowMessage> {
        let header = client_header(seq, data.len());
        push(table, now_ms, &header, data)
    }

    fn push_server(table: &mut FlowTable, now_ms: u64, seq: u32, data: &[u8]) -> Vec<FlowMessage> {
        let header = server_header(seq, data.len());
        push(table, now_ms, &header, data)
    }

    #[test]
    fn request_split_across_segments_is_reassembled() {
        let mut table = table();
        let mut messages = Vec::new();
        messages.extend(push_client(
            &mut table,
            1000,
            1000,
            b"GET /split HTTP/1.1\r\nHo",
        ));
        assert!(messages.is_empty());
        messages.extend(push_client(&mut table, 1001, 1023, b"st: example.com\r\n"));
        assert!(messages.is_empty());
        messages.extend(push_client(&mut table, 1002, 1040, b"\r\n"));
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.message.target.as_deref(), Some("/split"));
        assert_eq!(message.message.header("host"), Some("example.com"));
        assert_eq!(message.client().port, CLIENT_PORT);
        assert_eq!(message.server().port, SERVER_PORT);
        assert!(!message.from_server_port);
    }

    #[test]
    fn out_of_order_segments_are_reordered() {
        let mut table = table();
        let head = b"POST /o HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
        let body = b"0123456789";
        let seq = 500;
        // Two body segments arrive before the head.
        assert!(push_client(&mut table, 1, seq + head.len() as u32, &body[..5]).is_empty());
        assert!(push_client(&mut table, 2, seq + head.len() as u32 + 5, &body[5..]).is_empty());
        let messages = push_client(&mut table, 3, seq, head);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.method.as_deref(), Some("POST"));
        assert_eq!(messages[0].message.body, body);
        assert!(messages[0].message.body_complete);
    }

    #[test]
    fn out_of_order_then_complete_yields_one_message() {
        let mut table = table();
        let head = b"POST /o HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        let seq = 700;
        // Body first, then the head: still exactly one complete message.
        assert!(push_client(&mut table, 1, seq + head.len() as u32, b"hello").is_empty());
        let messages = push_client(&mut table, 2, seq, head);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.body, b"hello");
        assert!(messages[0].message.body_complete);
    }

    #[test]
    fn retransmission_is_deduplicated() {
        let mut table = table();
        let request = b"GET /dup HTTP/1.1\r\nHost: h\r\n\r\n";
        let messages = push_client(&mut table, 1, 100, request);
        assert_eq!(messages.len(), 1);
        // The exact same segment again must not produce a second message.
        assert!(push_client(&mut table, 2, 100, request).is_empty());
    }

    #[test]
    fn overlapping_retransmission_keeps_the_tail() {
        let mut table = table();
        let request = b"GET /overlap HTTP/1.1\r\nHost: h\r\n\r\n";
        let split = 10;
        assert!(push_client(&mut table, 1, 1_000, &request[..split]).is_empty());
        // Retransmit the first bytes plus the rest in one segment.
        let messages = push_client(&mut table, 2, 1_005, &request[5..]);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.target.as_deref(), Some("/overlap"));
    }

    #[test]
    fn mid_stream_capture_resynchronises() {
        let mut table = table();
        // Start in the middle of a response body.
        assert!(
            push_client(&mut table, 1, 42, b"garbage from the middle of a body\r\n").is_empty()
        );
        let messages = push_client(
            &mut table,
            2,
            78,
            b"GET /after-garbage HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].message.target.as_deref(),
            Some("/after-garbage")
        );
    }

    #[test]
    fn syn_pins_the_stream_start() {
        let mut table = table();
        let sequence = 900_000;
        // SYN carries no payload but tells us the stream starts at seq + 1.
        let syn = header(sequence, true, 0, tcp_flags::SYN);
        assert!(push(&mut table, 1, &syn, &[]).is_empty());
        let request = b"GET /syn HTTP/1.1\r\nHost: h\r\n\r\n";
        let messages = push_client(&mut table, 2, sequence + 1, request);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.target.as_deref(), Some("/syn"));
    }

    #[test]
    fn fin_from_both_sides_closes_the_flow() {
        let mut table = table();
        push_client(&mut table, 1, 1, b"GET /f HTTP/1.1\r\nHost: h\r\n\r\n");
        push_server(
            &mut table,
            2,
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        );
        assert_eq!(table.flow_count(), 1);
        let fin = header(50, true, 0, tcp_flags::FIN | tcp_flags::ACK);
        assert!(push(&mut table, 3, &fin, &[]).is_empty());
        assert_eq!(table.flow_count(), 1, "one FIN is not a closed connection");
        let fin = header(60, false, 0, tcp_flags::FIN | tcp_flags::ACK);
        assert!(push(&mut table, 4, &fin, &[]).is_empty());
        assert_eq!(table.flow_count(), 0);
    }

    #[test]
    fn reset_closes_the_flow_immediately() {
        let mut table = table();
        push_client(&mut table, 1, 1, b"GET /r HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(table.flow_count(), 1);
        let rst = header(50, true, 0, tcp_flags::RST);
        push(&mut table, 2, &rst, &[]);
        assert_eq!(table.flow_count(), 0);
    }

    #[test]
    fn both_directions_share_one_flow() {
        let mut table = table();
        let request = b"GET /both HTTP/1.1\r\nHost: h\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut messages = push_client(&mut table, 1, 10, request);
        messages.extend(push_server(&mut table, 2, 90, response));
        assert_eq!(messages.len(), 2);
        assert_eq!(table.flow_count(), 1);

        let request = &messages[0];
        assert!(request.is_request());
        assert_eq!(request.client().port, CLIENT_PORT);
        assert_eq!(request.server().port, SERVER_PORT);

        let response = &messages[1];
        assert!(!response.is_request());
        assert_eq!(response.message.status, Some(200));
        assert_eq!(response.client().port, CLIENT_PORT);
        assert_eq!(response.server().port, SERVER_PORT);
        assert!(response.from_server_port);
        assert_eq!(response.message.body, b"ok");
    }

    #[test]
    fn head_response_carries_no_body() {
        let mut table = table();
        let head_request = b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
        let mut messages = push_client(&mut table, 1, 10, head_request);
        messages.extend(push_server(&mut table, 2, 500, response));
        assert_eq!(messages.len(), 2);
        assert!(messages[1].message.body.is_empty());
        assert!(messages[1].message.body_complete);
        assert!(!messages[1].message.truncated);
    }

    #[test]
    fn gap_timeout_moves_past_a_lost_segment() {
        let mut config = FlowConfig::default();
        config.gap_timeout_ms = 100;
        let mut table = FlowTable::new(config);
        let head = b"POST /gap HTTP/1.1\r\nContent-Length: 20\r\n\r\n";
        assert!(push_client(&mut table, 1_000, 10, head).is_empty());
        // The segment after the hole arrives, but the hole never fills.
        assert!(push_client(
            &mut table,
            1_001,
            10 + head.len() as u32 + 5,
            b"tail-of-body"
        )
        .is_empty());
        let mut out = Vec::new();
        table.tick(1_050, &mut out);
        assert!(out.is_empty(), "the gap timeout has not elapsed yet");
        table.tick(1_200, &mut out);
        assert_eq!(out.len(), 1);
        assert!(!out[0].message.body_complete, "the hole is reported");
    }

    #[test]
    fn warmup_deadline_flushes_buffered_segments() {
        let mut config = FlowConfig::default();
        config.warmup_ms = 50;
        let mut table = FlowTable::new(config);
        // A lone body fragment that never becomes a message start.
        assert!(push_client(&mut table, 1_000, 10, b"body without a head\r\n").is_empty());
        let mut out = Vec::new();
        table.tick(1_020, &mut out);
        assert!(out.is_empty(), "still warming up");
        table.tick(1_060, &mut out);
        // Nothing parseable came out, but the bytes were consumed and the
        // stream is now anchored.
        assert!(out.is_empty());
        let messages = push_client(
            &mut table,
            1_100,
            31,
            b"\r\nGET /late HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.target.as_deref(), Some("/late"));
    }

    #[test]
    fn idle_flow_is_flushed_and_evicted() {
        let mut config = FlowConfig::default();
        config.idle_timeout_ms = 500;
        let mut table = FlowTable::new(config);
        push_server(
            &mut table,
            1_000,
            10,
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nonly-a-bit",
        );
        assert_eq!(table.flow_count(), 1);
        let mut out = Vec::new();
        table.tick(1_200, &mut out);
        assert!(out.is_empty());
        table.tick(1_600, &mut out);
        assert_eq!(out.len(), 1);
        assert!(!out[0].message.body_complete);
        assert_eq!(out[0].message.body, b"only-a-bit");
        assert_eq!(table.flow_count(), 0);
    }

    #[test]
    fn distinct_connections_are_tracked_separately() {
        let mut table = table();
        let mut out = Vec::new();
        let mut first = client_header(1, 20);
        first.src_port = 40000;
        table.push_segment(1, &first, b"GET /a HTTP/1.1\r\n\r\n", &mut out);
        let mut second = client_header(1, 20);
        second.src_port = 40001;
        table.push_segment(1, &second, b"GET /b HTTP/1.1\r\n\r\n", &mut out);
        assert_eq!(table.flow_count(), 2);
        assert_eq!(out.len(), 2);
        assert_ne!(out[0].key, out[1].key);
    }

    #[test]
    fn flow_capacity_evicts_the_oldest_connection() {
        let mut config = FlowConfig::default();
        config.max_flows = 2;
        let mut table = FlowTable::new(config);
        for (index, port) in [40000u16, 40001, 40002].into_iter().enumerate() {
            let mut header = client_header(1, 20);
            header.src_port = port;
            let mut out = Vec::new();
            table.push_segment(index as u64, &header, b"GET /x HTTP/1.1\r\n\r\n", &mut out);
        }
        assert_eq!(table.flow_count(), 2);
        assert_eq!(table.evicted_flows(), 1);
    }

    #[test]
    fn unsupported_versions_do_not_break_the_stream() {
        let mut table = table();
        // HTTP/2 connection preface sent to a plaintext HTTP port.
        let messages = push_client(&mut table, 1, 1, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert!(messages.is_empty());
        let messages = push_client(
            &mut table,
            2,
            30,
            b"GET /after-h2 HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.target.as_deref(), Some("/after-h2"));
    }

    #[test]
    fn sequence_wraparound_is_handled() {
        let mut table = table();
        let start = u32::MAX - 5;
        let request = b"GET /wrap HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(push_client(&mut table, 1, start, &request[..4]).is_empty());
        // Sequence numbers wrap past u32::MAX.
        let messages = push_client(&mut table, 2, start.wrapping_add(4), &request[4..]);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.target.as_deref(), Some("/wrap"));
    }
}

//! Incremental HTTP/1.x parser.
//!
//! The parser is fed the reassembled byte stream of one direction of a TCP
//! connection and emits complete messages (plus, on an idle timeout or a
//! detected hole in the stream, messages marked as incomplete).
//!
//! It is deliberately tolerant: capture usually starts in the middle of a
//! connection, so instead of giving up it resynchronises on the next plausible
//! request or status line.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Default cap on the request/response head (start line plus headers).
pub const DEFAULT_MAX_HEAD: usize = 64 * 1024;
/// Default cap on a single message body.
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_head: usize,
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head: DEFAULT_MAX_HEAD,
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
}

/// One HTTP/1.x message.
#[derive(Clone, Debug)]
pub struct HttpMessage {
    pub kind: MessageKind,
    /// Request method (`GET`, `POST`, ...).
    pub method: Option<String>,
    /// Request target as it appeared on the wire.
    pub target: Option<String>,
    /// `HTTP/1.0` or `HTTP/1.1`.
    pub version: String,
    /// Response status code.
    pub status: Option<u16>,
    /// Response reason phrase.
    pub reason: Option<String>,
    /// Headers in wire order, values with surrounding whitespace trimmed.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// False when the body was cut short by a limit, a stream gap or an idle
    /// flush. A message that has no body is always complete.
    pub body_complete: bool,
    /// True when the head or the body hit a parser limit.
    pub truncated: bool,
    /// Unparseable bytes skipped while resynchronising before this message.
    pub skipped_bytes: usize,
}

impl HttpMessage {
    pub fn is_request(&self) -> bool {
        self.kind == MessageKind::Request
    }

    /// Case-insensitive header lookup, returning the first match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// `GET /index.html HTTP/1.1` or `HTTP/1.1 200 OK`.
    pub fn start_line(&self) -> String {
        match self.kind {
            MessageKind::Request => format!(
                "{} {} {}",
                self.method.as_deref().unwrap_or("?"),
                self.target.as_deref().unwrap_or("?"),
                self.version
            ),
            MessageKind::Response => match (self.status, self.reason.as_deref()) {
                (Some(status), Some(reason)) if !reason.is_empty() => {
                    format!("{} {} {}", self.version, status, reason)
                }
                (Some(status), _) => format!("{} {}", self.version, status),
                (None, _) => self.version.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Default)]
struct StartLine {
    kind: MessageKind,
    method: Option<String>,
    target: Option<String>,
    version: String,
    status: Option<u16>,
    reason: Option<String>,
}

impl Default for MessageKind {
    fn default() -> Self {
        MessageKind::Request
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// No body at all.
    None,
    /// Body length taken from `Content-Length`.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Body runs until the connection closes.
    UntilClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    /// Reading the `size[;ext]` line.
    Size,
    /// Reading chunk data.
    Data,
    /// Expecting the CRLF that terminates chunk data.
    DataCrlf,
    /// Reading trailers after the final chunk.
    Trailer,
}

#[derive(Clone, Copy, Debug)]
struct Chunked {
    state: ChunkState,
    remaining: usize,
}

#[derive(Debug)]
enum State {
    /// Looking for the start line of the next message.
    Idle,
    /// Start line parsed, still reading headers.
    Head(StartLine),
    Body {
        start: StartLine,
        headers: Vec<(String, String)>,
        framing: Framing,
        chunked: Option<Chunked>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    /// Keep stepping: input was consumed.
    Continue,
    /// Not enough bytes buffered.
    NeedMore,
}

/// Incremental HTTP/1.x parser for one direction of a TCP connection.
#[derive(Debug)]
pub struct Http1Parser {
    /// Bytes received but not yet consumed.
    buf: Vec<u8>,
    state: State,
    limits: Limits,
    /// Body bytes of the message currently being assembled.
    body: Vec<u8>,
    /// Messages produced by the last call; drained with [`Self::take_messages`].
    messages: Vec<HttpMessage>,
    skipped: usize,
    /// Set by the flow layer after a `HEAD` request: the next response carries
    /// no body even if it advertises a `Content-Length`.
    bodyless_next_response: bool,
}

impl Default for Http1Parser {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Http1Parser {
    pub fn new(limits: Limits) -> Self {
        Self {
            buf: Vec::new(),
            state: State::Idle,
            limits,
            body: Vec::new(),
            messages: Vec::new(),
            skipped: 0,
            bodyless_next_response: false,
        }
    }

    /// Feed bytes of the connection, in the order they were sent.
    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.buf.extend_from_slice(data);
        while self.step() == Progress::Continue {}
    }

    /// Tell the parser that the stream has a hole at this position: whatever is
    /// in flight is emitted as incomplete and parsing restarts.
    pub fn notify_gap(&mut self) {
        self.flush();
        self.buf.clear();
    }

    /// Mark that the response following this point carries no body.
    pub fn expect_bodyless_response(&mut self) {
        self.bodyless_next_response = true;
    }

    /// Emit anything in flight, marked as incomplete. Used on idle timeouts and
    /// when a flow is evicted.
    pub fn flush(&mut self) {
        let (start, headers) = match core::mem::replace(&mut self.state, State::Idle) {
            State::Idle => return,
            State::Head(start) => (start, Vec::new()),
            State::Body { start, headers, .. } => (start, headers),
        };
        let body = core::mem::take(&mut self.body);
        self.emit(start, headers, body, false, false);
        self.buf.clear();
    }

    /// Take the messages parsed so far.
    pub fn take_messages(&mut self) -> Vec<HttpMessage> {
        core::mem::take(&mut self.messages)
    }

    /// Messages produced by the last `push`, without draining them.
    pub fn messages(&self) -> &[HttpMessage] {
        &self.messages
    }

    /// True when nothing is in flight.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle) && self.buf.is_empty()
    }

    fn emit(
        &mut self,
        start: StartLine,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        body_complete: bool,
        truncated: bool,
    ) {
        self.messages.push(HttpMessage {
            kind: start.kind,
            method: start.method,
            target: start.target,
            version: start.version,
            status: start.status,
            reason: start.reason,
            headers,
            body,
            body_complete,
            truncated,
            skipped_bytes: core::mem::take(&mut self.skipped),
        });
    }

    fn step(&mut self) -> Progress {
        match &self.state {
            State::Idle => self.step_idle(),
            State::Head(_) => self.step_head(),
            State::Body {
                framing, chunked, ..
            } => match (*framing, *chunked) {
                (Framing::None, _) => {
                    self.state = State::Idle;
                    Progress::Continue
                }
                (Framing::Length(_), _) => self.step_length_body(),
                (Framing::UntilClose, _) => self.step_until_close(),
                (Framing::Chunked, Some(chunked)) => self.step_chunked(chunked),
                (Framing::Chunked, None) => {
                    self.state = State::Idle;
                    Progress::Continue
                }
            },
        }
    }

    fn step_idle(&mut self) -> Progress {
        let Some((line, consumed)) = self.peek_line() else {
            if self.buf.len() > self.limits.max_head {
                self.skipped += self.buf.len();
                self.buf.clear();
            }
            return Progress::NeedMore;
        };
        if line.is_empty() {
            // Stray CRLF between messages.
            self.buf.drain(..consumed);
            return Progress::Continue;
        }
        // Note: the start line is *not* consumed here, so that the head parser
        // sees the complete head (start line plus headers) as one block.
        match classify_start_line(line) {
            Some(start) => {
                self.state = State::Head(start);
                Progress::Continue
            }
            None => {
                self.buf.drain(..consumed);
                self.skipped += consumed;
                Progress::Continue
            }
        }
    }

    fn step_head(&mut self) -> Progress {
        let State::Head(start) = &self.state else {
            return Progress::Continue;
        };
        let start = start.clone();

        let Some(head_end) = find_head_end(&self.buf) else {
            if self.buf.len() > self.limits.max_head {
                // Head too large: emit what we have and resynchronise.
                let head = core::mem::take(&mut self.buf);
                let headers = parse_headers(&head);
                self.state = State::Idle;
                self.emit(start, headers, Vec::new(), false, true);
                return Progress::Continue;
            }
            return Progress::NeedMore;
        };

        let head = self.buf[..head_end].to_vec();
        self.buf.drain(..head_end);
        let headers = parse_headers(&head);
        let framing = framing_for(&start, &headers, &mut self.bodyless_next_response);
        self.body.clear();
        self.state = match framing {
            Framing::None | Framing::Length(0) => {
                self.emit(start, headers, Vec::new(), true, false);
                State::Idle
            }
            Framing::Chunked => State::Body {
                start,
                headers,
                framing,
                chunked: Some(Chunked {
                    state: ChunkState::Size,
                    remaining: 0,
                }),
            },
            other => State::Body {
                start,
                headers,
                framing: other,
                chunked: None,
            },
        };
        Progress::Continue
    }

    fn step_length_body(&mut self) -> Progress {
        let State::Body {
            framing: Framing::Length(len),
            ..
        } = self.state
        else {
            return Progress::Continue;
        };
        let remaining = len.saturating_sub(self.body.len());
        let room = self.limits.max_body.saturating_sub(self.body.len());
        let take = remaining.min(self.buf.len()).min(room);
        if take > 0 {
            self.body.extend_from_slice(&self.buf[..take]);
            self.buf.drain(..take);
        }
        if self.body.len() >= len {
            self.finish_body(true, false);
            return Progress::Continue;
        }
        if self.body.len() >= self.limits.max_body {
            // Body limit reached: emit what we have and resynchronise.
            self.finish_body(false, true);
            return Progress::Continue;
        }
        Progress::NeedMore
    }

    fn step_until_close(&mut self) -> Progress {
        let room = self.limits.max_body.saturating_sub(self.body.len());
        let take = room.min(self.buf.len());
        if take > 0 {
            self.body.extend_from_slice(&self.buf[..take]);
            self.buf.drain(..take);
        }
        if self.body.len() >= self.limits.max_body {
            self.finish_body(false, true);
            return Progress::Continue;
        }
        // Never completes by itself: waits for `flush`.
        Progress::NeedMore
    }

    fn step_chunked(&mut self, chunked: Chunked) -> Progress {
        match chunked.state {
            ChunkState::Size => {
                let Some((line, consumed)) = self.peek_line() else {
                    return Progress::NeedMore;
                };
                let size = parse_chunk_size(line);
                self.buf.drain(..consumed);
                match size {
                    Some(0) => {
                        self.set_chunk(ChunkState::Trailer, 0);
                        Progress::Continue
                    }
                    Some(size) => {
                        self.set_chunk(ChunkState::Data, size);
                        Progress::Continue
                    }
                    None => {
                        // Malformed chunk header.
                        self.finish_body(false, true);
                        Progress::Continue
                    }
                }
            }
            ChunkState::Data => {
                let room = self.limits.max_body.saturating_sub(self.body.len());
                let take = chunked.remaining.min(self.buf.len()).min(room);
                if take > 0 {
                    self.body.extend_from_slice(&self.buf[..take]);
                    self.buf.drain(..take);
                }
                let remaining = chunked.remaining.saturating_sub(take);
                if remaining > 0 {
                    if self.body.len() >= self.limits.max_body {
                        self.finish_body(false, true);
                        return Progress::Continue;
                    }
                    return Progress::NeedMore;
                }
                self.set_chunk(ChunkState::DataCrlf, 0);
                Progress::Continue
            }
            ChunkState::DataCrlf => {
                let Some((line, consumed)) = self.peek_line() else {
                    return Progress::NeedMore;
                };
                let empty = line.is_empty();
                self.buf.drain(..consumed);
                if empty {
                    self.set_chunk(ChunkState::Size, 0);
                } else {
                    self.finish_body(false, true);
                }
                Progress::Continue
            }
            ChunkState::Trailer => {
                let Some((line, consumed)) = self.peek_line() else {
                    return Progress::NeedMore;
                };
                let empty = line.is_empty();
                self.buf.drain(..consumed);
                if empty {
                    self.finish_body(true, false);
                }
                Progress::Continue
            }
        }
    }

    fn set_chunk(&mut self, state: ChunkState, remaining: usize) {
        if let State::Body { chunked, .. } = &mut self.state {
            *chunked = Some(Chunked { state, remaining });
        }
    }

    /// Emit the message currently in [`State::Body`] and go back to idle.
    fn finish_body(&mut self, body_complete: bool, truncated: bool) {
        let (start, headers) = match core::mem::replace(&mut self.state, State::Idle) {
            State::Body { start, headers, .. } => (start, headers),
            other => {
                self.state = other;
                return;
            }
        };
        let body = core::mem::take(&mut self.body);
        self.emit(start, headers, body, body_complete, truncated);
    }

    /// Peek a line terminated by `\n` (with an optional trailing `\r`).
    ///
    /// Returns the line without its terminator plus the number of bytes it
    /// occupies including the terminator.
    fn peek_line(&self) -> Option<(&[u8], usize)> {
        let lf = self.buf.iter().position(|&b| b == b'\n')?;
        let mut end = lf;
        if end > 0 && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        Some((&self.buf[..end], lf + 1))
    }
}

/// Index just past the blank line that terminates a header block, or `None`
/// while it has not been received yet.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    while cursor < buf.len() {
        let lf = buf[cursor..].iter().position(|&b| b == b'\n')? + cursor;
        let mut end = lf;
        if end > cursor && buf[end - 1] == b'\r' {
            end -= 1;
        }
        if end == cursor {
            // Empty line: end of the head.
            return Some(lf + 1);
        }
        cursor = lf + 1;
    }
    None
}

fn classify_start_line(line: &[u8]) -> Option<StartLine> {
    let text = core::str::from_utf8(line).ok()?;
    if let Some(rest) = text.strip_prefix("HTTP/") {
        // Status line: HTTP/1.1 200 OK
        let mut parts = rest.splitn(2, ' ');
        let minor = parts.next()?;
        if !minor.starts_with('1') {
            return None;
        }
        let rest = parts.next()?.trim_start();
        let mut parts = rest.splitn(2, ' ');
        let status: u16 = parts.next()?.parse().ok()?;
        if !(100..1000).contains(&status) {
            return None;
        }
        return Some(StartLine {
            kind: MessageKind::Response,
            method: None,
            target: None,
            version: format!("HTTP/{minor}"),
            status: Some(status),
            reason: parts.next().map(|r| r.trim_end().to_string()),
        });
    }

    // Request line: GET /path HTTP/1.1
    let mut parts = text.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if !method.bytes().all(is_token_byte) || method.is_empty() {
        return None;
    }
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    if !target.is_empty() && target.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return None;
    }
    Some(StartLine {
        kind: MessageKind::Request,
        method: Some(method.to_string()),
        target: Some(target.to_string()),
        version: version.to_string(),
        status: None,
        reason: None,
    })
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parse a header block (start line included) into `(name, value)` pairs.
fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut lines = head.split(|&b| b == b'\n');
    lines.next(); // start line
    for raw in lines {
        let mut line = raw;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            break;
        }
        // Obsolete line folding: a line starting with whitespace continues the
        // previous header value.
        if (line[0] == b' ' || line[0] == b'\t') && !headers.is_empty() {
            let value = String::from_utf8_lossy(line).trim().to_string();
            let last = headers.last_mut().expect("checked non-empty");
            last.1.push(' ');
            last.1.push_str(&value);
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
        headers.push((name, value));
    }
    headers
}

fn framing_for(
    start: &StartLine,
    headers: &[(String, String)],
    bodyless_next_response: &mut bool,
) -> Framing {
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .to_ascii_lowercase()
                .split(',')
                .any(|part| part.trim() == "chunked")
    });
    // The last Content-Length wins, per RFC 9112.
    let content_length = headers
        .iter()
        .rev()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .find_map(|(_, value)| value.trim().parse::<usize>().ok());

    match start.kind {
        MessageKind::Request => {
            if chunked {
                Framing::Chunked
            } else {
                match content_length {
                    Some(len) => Framing::Length(len),
                    None => Framing::None,
                }
            }
        }
        MessageKind::Response => {
            let status = start.status.unwrap_or(0);
            if (100..200).contains(&status) || status == 204 || status == 304 {
                return Framing::None;
            }
            if core::mem::take(bodyless_next_response) {
                // Response to a HEAD request.
                return Framing::None;
            }
            if chunked {
                Framing::Chunked
            } else {
                match content_length {
                    Some(len) => Framing::Length(len),
                    None => Framing::UntilClose,
                }
            }
        }
    }
}

/// Cheap check: does this segment begin with a plausible HTTP start line?
///
/// Used by the reassembler to decide whether a segment can be handed to the
/// parser straight away, or whether it may still be preceded by a segment that
/// arrives later (in which case it is buffered briefly first).
pub fn starts_with_message(data: &[u8]) -> bool {
    let Some(lf) = data.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let mut end = lf;
    if end > 0 && data[end - 1] == b'\r' {
        end -= 1;
    }
    classify_start_line(&data[..end]).is_some()
}

/// Does any line of this data look like the start of an HTTP message?
///
/// Weaker than [`starts_with_message`]: used by the reassembler, where a few
/// bytes captured before the message start may already be buffered.
pub fn contains_message_start(data: &[u8]) -> bool {
    for raw in data.split(|&b| b == b'\n') {
        let mut line = raw;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        if classify_start_line(line).is_some() {
            return true;
        }
    }
    false
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let text = core::str::from_utf8(line).ok()?.trim();
    let digits = text
        .split(|c: char| c == ';' || c.is_ascii_whitespace())
        .next()?
        .trim();
    if digits.is_empty() {
        return None;
    }
    usize::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> Http1Parser {
        Http1Parser::new(Limits::default())
    }

    fn push_all(parser: &mut Http1Parser, data: &[u8]) -> Vec<HttpMessage> {
        parser.push(data);
        parser.take_messages()
    }

    #[test]
    fn simple_get_request() {
        let mut parser = parser();
        let messages = push_all(
            &mut parser,
            b"GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert!(message.is_request());
        assert_eq!(message.method.as_deref(), Some("GET"));
        assert_eq!(message.target.as_deref(), Some("/hello?x=1"));
        assert_eq!(message.version, "HTTP/1.1");
        assert_eq!(message.header("host"), Some("example.com"));
        assert_eq!(message.header("USER-AGENT"), Some("curl/8"));
        assert!(message.body.is_empty());
        assert!(message.body_complete);
        assert!(!message.truncated);
        assert_eq!(message.skipped_bytes, 0);
        assert_eq!(message.start_line(), "GET /hello?x=1 HTTP/1.1");
    }

    #[test]
    fn byte_at_a_time_delivery() {
        let request = b"POST /submit HTTP/1.0\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
        let mut parser = parser();
        let mut messages = Vec::new();
        for byte in request {
            parser.push(&[*byte]);
            messages.extend(parser.take_messages());
        }
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method.as_deref(), Some("POST"));
        assert_eq!(messages[0].body, b"hello");
        assert!(messages[0].body_complete);
    }

    #[test]
    fn content_length_body_split_across_segments() {
        let mut parser = parser();
        let head = b"POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\n";
        parser.push(head);
        assert!(parser.take_messages().is_empty());
        parser.push(b"hello ");
        assert!(parser.take_messages().is_empty());
        let messages = push_all(&mut parser, b"world");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"hello world");
        assert!(messages[0].body_complete);
    }

    #[test]
    fn chunked_response_with_trailers() {
        let mut parser = parser();
        let messages = push_all(
            &mut parser,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.kind, MessageKind::Response);
        assert_eq!(message.status, Some(200));
        assert_eq!(message.reason.as_deref(), Some("OK"));
        assert_eq!(message.body, b"hello world");
        assert!(message.body_complete);
        assert_eq!(message.header("transfer-encoding"), Some("chunked"));
    }

    #[test]
    fn pipelined_requests_in_one_segment() {
        let mut parser = parser();
        let messages = push_all(
            &mut parser,
            b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].target.as_deref(), Some("/a"));
        assert_eq!(messages[1].target.as_deref(), Some("/b"));
    }

    #[test]
    fn resynchronises_after_garbage() {
        let mut parser = parser();
        // Capture started in the middle of a previous response body.
        let messages = push_all(
            &mut parser,
            b"dy bytes of a previous message\r\nGET /after HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].target.as_deref(), Some("/after"));
        assert!(messages[0].skipped_bytes > 0);
    }

    #[test]
    fn folded_header_is_joined() {
        let mut parser = parser();
        let messages = push_all(
            &mut parser,
            b"GET / HTTP/1.1\r\nX-Long: first\r\n  second\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header("x-long"), Some("first second"));
    }

    #[test]
    fn lf_only_line_endings_are_accepted() {
        let mut parser = parser();
        let messages = push_all(&mut parser, b"GET /lf HTTP/1.1\nHost: h\n\n");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].target.as_deref(), Some("/lf"));
    }

    #[test]
    fn head_request_makes_next_response_bodyless() {
        let mut response_parser = parser();
        response_parser.expect_bodyless_response();
        let messages = push_all(
            &mut response_parser,
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].kind, MessageKind::Response);
        assert!(messages[0].body.is_empty());
        assert!(messages[0].body_complete);
        // The hint is consumed by the first response only.
        assert_eq!(messages[1].target.as_deref(), Some("/next"));
    }

    #[test]
    fn bodyless_status_codes() {
        for status_line in [
            &b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"[..],
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 5\r\n\r\n",
        ] {
            let mut parser = parser();
            let messages = push_all(&mut parser, status_line);
            assert_eq!(messages.len(), 1, "{status_line:?}");
            assert!(messages[0].body.is_empty());
            assert!(messages[0].body_complete);
        }
    }

    #[test]
    fn until_close_body_is_flushed_incomplete() {
        let mut parser = parser();
        parser.push(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npartial body");
        assert!(parser.take_messages().is_empty());
        parser.flush();
        let messages = parser.take_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"partial body");
        assert!(!messages[0].body_complete);
    }

    #[test]
    fn gap_marks_message_incomplete() {
        let mut parser = parser();
        parser.push(b"POST /big HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-a-few");
        parser.notify_gap();
        let messages = parser.take_messages();
        assert_eq!(messages.len(), 1);
        assert!(!messages[0].body_complete);
        assert_eq!(messages[0].body, b"only-a-few");
        // Parsing continues normally afterwards.
        let messages = push_all(&mut parser, b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].target.as_deref(), Some("/next"));
    }

    #[test]
    fn body_limit_truncates_instead_of_growing_forever() {
        let mut parser = Http1Parser::new(Limits {
            max_head: 1024,
            max_body: 16,
        });
        let messages = push_all(
            &mut parser,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789abcdefghij",
        );
        assert_eq!(messages.len(), 1);
        assert!(messages[0].truncated);
        assert!(!messages[0].body_complete);
        assert_eq!(messages[0].body.len(), 16);
    }

    #[test]
    fn oversized_head_is_emitted_as_truncated() {
        let mut parser = Http1Parser::new(Limits {
            max_head: 64,
            max_body: 1024,
        });
        let mut request = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        request.extend_from_slice(&[b'X'; 400]);
        let messages = push_all(&mut parser, &request);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].truncated);
        assert_eq!(messages[0].method.as_deref(), Some("GET"));
    }

    #[test]
    fn invalid_content_length_falls_back_to_no_body_for_requests() {
        let mut parser = parser();
        let messages = push_all(
            &mut parser,
            b"GET / HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\nGET /next HTTP/1.1\r\n\r\n",
        );
        assert_eq!(messages.len(), 2);
        assert!(messages[0].body.is_empty());
        assert!(messages[0].body_complete);
        assert_eq!(messages[1].target.as_deref(), Some("/next"));
    }

    #[test]
    fn huge_content_length_does_not_reserve_the_world() {
        let mut parser = parser();
        parser.push(b"POST / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\nabc");
        // Nothing emitted yet, and the parser stays responsive.
        assert!(parser.take_messages().is_empty());
        parser.flush();
        assert_eq!(parser.take_messages().len(), 1);
    }

    #[test]
    fn response_without_version_is_not_a_start_line() {
        assert!(classify_start_line(b"HTTP/2 200").is_none());
        assert!(classify_start_line(b"HTTP/1.1 twohundred OK").is_none());
        assert!(classify_start_line(b"not a request line").is_none());
        assert!(classify_start_line(b"GET /").is_none());
    }
}

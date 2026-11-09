//! M8 webui: a hand-rolled minimal HTTP/1.1 subset (docs/design.md
//! §7-M8.1/M8.4).
//!
//! Decision (fixed by design): **not axum** —— the exposed surface is only
//! loopback + the tun VIP with ~22 JSON endpoints; pulling in the whole tower
//! stack for that contradicts the repository discipline (§3.6 "an adapter per
//! imagined seam"; the hand-rolled frame protocol in admin.rs is the
//! precedent). Subset boundary (not implementing ambiguous features means no
//! request-smuggling surface):
//!
//! - HTTP/1.0 and HTTP/1.1, methods GET/POST, keep-alive, `Content-Length`
//!   fixed-length bodies;
//! - **rejects `Transfer-Encoding` (any value) and duplicate
//!   `Content-Length` (including comma multi-values)** ⇒ 400 and close;
//! - limits: request line ≤ 2KiB, header block ≤ 8KiB, body ≤ 64KiB —— over
//!   the limit 400/413 and close;
//! - header names read case-insensitively; no cookie parsing (the single-key
//!   cookie parse lives in api.rs —— the session decision of [`super::api`]);
//! - two-layer read timeouts: 15s per read (half-open connections) + **a 30s
//!   total per-request time limit** (the whole head+body read loop —— a
//!   byte-by-byte drip that keeps every read within the per-read timeout
//!   still cannot get past the total budget) ⇒ on timeout, silently close
//!   (total-limit expiry closes the connection and counts it).
//!
//! Parser and connection loop are separate: [`parse_head`] is a pure function
//! (the malformed-vector unit-test surface), [`serve_conn`] is the connection
//! loop with timeouts/limits/keep-alive.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Request-line limit (2KiB, §M8.4).
pub const MAX_REQUEST_LINE: usize = 2 * 1024;
/// Header-block limit (8KiB —— all header bytes after the request line and
/// before `\r\n\r\n`).
pub const MAX_HEAD: usize = 8 * 1024;
/// Request-body limit (64KiB).
pub const MAX_BODY: usize = 64 * 1024;
/// Single read timeout (half-open connections —— on timeout, silently close;
/// does not hold a concurrency permit).
pub const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Total per-request time limit (the whole head+body read loop): a
/// byte-by-byte drip can keep every read within READ_TIMEOUT while holding
/// the connection indefinitely, exhausting MAX_CONCURRENCY permits (on the
/// VIP surface any VPN member could DoS the admin surface) ⇒ when the total
/// budget expires, close the connection + count it ([`slow_request_kills`]).
/// keep-alive resets the budget per request.
pub const REQUEST_TOTAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Cumulative counter of connections closed on REQUEST_TOTAL expiry
/// (diagnostics/test surface —— observability of slow-attack vectors being
/// cut).
static SLOW_KILLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Read the current value of [`SLOW_KILLS`].
pub fn slow_request_kills() -> u64 {
    SLOW_KILLS.load(std::sync::atomic::Ordering::Relaxed)
}

// ============================================================================
// Request/response types
// ============================================================================

/// Parsed request (head + body; the body is assembled by the connection loop
/// after filling per Content-Length).
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Path (query excluded; starts with '/').
    pub path: String,
    /// Raw query (no '?'; empty = none).
    pub query: String,
    /// Headers (original names preserved; reads go through
    /// [`Request::header`], case-insensitive).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header read.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Single-key parse of the `flock_session` cookie (value = the 64-hex
    /// sid; absent ⇒ None).
    pub fn session_cookie(&self) -> Option<&str> {
        let cookies = self.header("cookie")?;
        for pair in cookies.split(';') {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?.trim();
            if k == "flock_session" {
                return it.next().map(|v| v.trim());
            }
        }
        None
    }
}

/// Response (the http layer adds `Content-Length`/`Connection`; the
/// `Connection` header belongs to this layer —— handlers must not set it).
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// JSON body (`application/json; charset=utf-8` + `Cache-Control:
    /// no-store` —— API responses are not cached, §M8.1).
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Response::new(status)
            .with_header("Content-Type", "application/json; charset=utf-8")
            .with_header("Cache-Control", "no-store")
            .body(serde_json::to_vec(value).unwrap_or_default())
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// Status-line reason (only the codes this subset uses).
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

// ============================================================================
// Head parsing (pure function —— the malformed-vector unit-test surface)
// ============================================================================

/// Head parse failure (all carry "400/413 and close" semantics; payload
/// over-limit listed separately for 413).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Bad request line / bad version / bad header shape / bad
    /// Content-Length value.
    BadRequest,
    /// Request-smuggling surface: a `Transfer-Encoding` header is present.
    TransferEncoding,
    /// Request-smuggling surface: duplicate / multi-value `Content-Length`.
    DuplicateContentLength,
    /// Body over 64KiB (413).
    PayloadTooLarge,
    /// Request line / header block over the limit (400).
    HeadTooLarge,
}

/// Head parse product (body not read —— content_length is handed to the
/// connection loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHead {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    /// keep-alive default (decided by version + Connection header).
    pub keep_alive: bool,
}

/// Parse the head (the request header block ending with `\r\n\r\n`).
///
/// - `Ok(None)` = insufficient bytes (keep reading);
/// - `Ok(Some)` = parsed successfully;
/// - `Err` = fatally malformed (the caller replies 400/413 and closes).
///
/// The byte-limit check precedes the syntax check: if the bytes read so far
/// exceed the "request line + header block" limit without the header block
/// ending in sight ⇒ `HeadTooLarge` (stop burning memory).
pub fn parse_head(buf: &[u8]) -> Result<Option<ParsedHead>, ParseError> {
    // ① Locate the header-block end (limit before syntax: an absolute bound
    //    of 2K+8K+4 for the whole block).
    let head_end = match find_sub(buf, b"\r\n\r\n") {
        Some(i) => i,
        None => {
            if buf.len() > MAX_REQUEST_LINE + MAX_HEAD + 4 {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        }
    };
    let head = &buf[..head_end];
    // ② Request line (≤ 2KiB; CRLF-separated).
    let (line, rest) = match find_sub(head, b"\r\n") {
        Some(i) => (&head[..i], &head[i + 2..]),
        None => (head, &head[head.len()..]), // no headers (request line + empty block only)
    };
    if line.len() > MAX_REQUEST_LINE {
        return Err(ParseError::HeadTooLarge);
    }
    if rest.len() > MAX_HEAD {
        return Err(ParseError::HeadTooLarge);
    }
    let line = std::str::from_utf8(line).map_err(|_| ParseError::BadRequest)?;
    // Strictly three tokens (extra spaces ⇒ reject —— an ambiguous request
    // line is a smuggling surface).
    let mut parts = line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) if parts.next().is_none() => (m, t, v),
        _ => return Err(ParseError::BadRequest),
    };
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(ParseError::BadRequest);
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ParseError::BadRequest);
    }
    // target must be origin-form (absolute URI / proxy form ⇒ reject).
    if !target.starts_with('/') || target.contains(' ') || target.contains('\t') {
        return Err(ParseError::BadRequest);
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    // ③ Header lines (strict `Name: value`; obs-fold (leading whitespace) ⇒
    //    reject —— smuggling surface).
    let rest_str = std::str::from_utf8(rest).map_err(|_| ParseError::BadRequest)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<Option<u64>> = None; // outer = seen yet; inner = value
    let mut keep_alive = version == "HTTP/1.1";
    if !rest_str.is_empty() {
        for hl in rest_str.split("\r\n") {
            if hl.is_empty() {
                return Err(ParseError::BadRequest);
            }
            if hl.starts_with(' ') || hl.starts_with('\t') {
                return Err(ParseError::BadRequest); // obs-fold
            }
            let (name, value) = hl.split_once(':').ok_or(ParseError::BadRequest)?;
            // Header names strictly token (whitespace inside the name ⇒
            // reject, RFC 7230 security baseline).
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(ParseError::BadRequest);
            }
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(ParseError::TransferEncoding);
            }
            if name.eq_ignore_ascii_case("content-length") {
                // Duplicate header or multi-value (comma) ⇒ reject (smuggling
                // surface).
                if content_length.is_some() || value.contains(',') {
                    return Err(ParseError::DuplicateContentLength);
                }
                let v: u64 = value
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| value.parse().ok())
                    .flatten()
                    .ok_or(ParseError::BadRequest)?;
                if v > MAX_BODY as u64 {
                    return Err(ParseError::PayloadTooLarge);
                }
                content_length = Some(Some(v));
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                let v = value.to_ascii_lowercase();
                if v.contains("close") {
                    keep_alive = false;
                } else if v.contains("keep-alive") {
                    keep_alive = true;
                }
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }
    Ok(Some(ParsedHead {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        content_length: content_length.flatten(),
        keep_alive,
    }))
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ============================================================================
// Connection loop (per-read timeout + request total limit / limits /
// keep-alive)
// ============================================================================

/// Handler type (api dispatch; remote = the connection peer —— the decision
/// input of the access matrix).
pub type HandlerReturn = Pin<Box<dyn Future<Output = Response> + Send>>;
pub type Handler = Box<dyn Fn(Request, SocketAddr) -> HandlerReturn + Send + Sync>;

/// Serve one connection until close (keep-alive loop; malformed ⇒ 400/413 and
/// close).
///
/// Every request (the whole head+body read loop) runs under the
/// [`REQUEST_TOTAL`] total-budget deadline —— a byte-by-byte drip can keep
/// every read inside the per-read timeout while holding a concurrency permit
/// indefinitely; on budget expiry the connection is closed and counted
/// ([`slow_request_kills`]). Dispatch/response writing does not count toward
/// the budget (the read side is the attacker-controlled pace surface).
pub async fn serve_conn(io: &mut TcpStream, remote: SocketAddr, handler: Handler) {
    serve_conn_with_budget(io, remote, handler, REQUEST_TOTAL).await
}

/// Budget-injection variant of [`serve_conn`] (tests drive the slow-drip
/// vector with a short budget).
pub async fn serve_conn_with_budget(
    io: &mut TcpStream,
    remote: SocketAddr,
    handler: Handler,
    total_budget: std::time::Duration,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        // ①② head accumulation + body fill, all under the total-budget
        //    deadline.
        let outcome =
            tokio::time::timeout(total_budget, read_request(io, &mut buf, &mut chunk)).await;
        let (head, body) = match outcome {
            // Total budget expired (slow drip): silently close + count.
            Err(_) => {
                SLOW_KILLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            Ok(ReadOutcome::Closed) => return, // EOF / per-read timeout / read error: silent close
            Ok(ReadOutcome::Bad(e)) => {
                let status = match e {
                    ParseError::PayloadTooLarge => 413,
                    _ => 400,
                };
                let _ =
                    write_response(io, &Response::json(status, &err_envelope(status)), false).await;
                return;
            }
            Ok(ReadOutcome::Request { head, body }) => (head, body),
        };
        let req = Request {
            method: head.method.clone(),
            path: head.path.clone(),
            query: head.query.clone(),
            headers: head.headers.clone(),
            body,
        };
        // ③ Dispatch (handler panics are backstopped as 500 by the assembly
        //    layer —— see the wrapping in mod.rs).
        let resp = handler(req, remote).await;
        let keep = head.keep_alive;
        if write_response(io, &resp, keep).await.is_err() {
            return;
        }
        if !keep {
            return;
        }
    }
}

/// Single-request read-loop product (the merged state of head parsing + body
/// filling).
enum ReadOutcome {
    /// Complete request (head + body ready).
    Request { head: ParsedHead, body: Vec<u8> },
    /// Fatally malformed (the caller replies 400/413 and closes).
    Bad(ParseError),
    /// EOF / per-read timeout / read error (silent close).
    Closed,
}

/// Read one complete request (head accumulation → body filled per
/// Content-Length); `buf` is reused across requests (leftover pipelined
/// bytes carry over naturally).
async fn read_request(
    io: &mut TcpStream,
    buf: &mut Vec<u8>,
    chunk: &mut [u8; 4096],
) -> ReadOutcome {
    // ① Head accumulation (no header-block end found within limits ⇒ 400
    //    and close).
    let head = loop {
        match parse_head(buf) {
            Ok(Some(h)) => break h,
            Ok(None) => {}
            Err(e) => return ReadOutcome::Bad(e),
        }
        match tokio::time::timeout(READ_TIMEOUT, io.read(chunk)).await {
            Ok(Ok(0)) | Err(_) => return ReadOutcome::Closed, // EOF / read timeout: silent close
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return ReadOutcome::Closed,
        }
    };
    // Consume the head bytes (including the trailing \r\n\r\n); leftover
    // bytes belong to the body (or the next request —— the pipelined case
    // carries over naturally).
    let head_len = find_sub(buf, b"\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    buf.drain(..head_len);
    // ② Fill the body per Content-Length.
    let want = head.content_length.unwrap_or(0) as usize;
    while buf.len() < want {
        match tokio::time::timeout(READ_TIMEOUT, io.read(chunk)).await {
            Ok(Ok(0)) | Err(_) => return ReadOutcome::Closed, // partial-packet timeout / EOF: close
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return ReadOutcome::Closed,
        }
    }
    let body: Vec<u8> = buf.drain(..want).collect();
    ReadOutcome::Request { head, body }
}

/// Write a response (adds Content-Length/Connection; a Connection header set
/// by the handler is stripped —— that header belongs to the connection
/// layer).
async fn write_response(
    io: &mut TcpStream,
    resp: &Response,
    keep_alive: bool,
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(128 + resp.body.len());
    out.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status)).as_bytes(),
    );
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n", resp.body.len()).as_bytes());
    out.extend_from_slice(if keep_alive {
        &b"connection: keep-alive\r\n"[..]
    } else {
        &b"connection: close\r\n"[..]
    });
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&resp.body);
    io.write_all(&out).await?;
    io.flush().await
}

/// The connection layer's own minimal error envelope (malformed request ——
/// the dispatch layer never took part; whitelisted message).
fn err_envelope(status: u16) -> serde_json::Value {
    let code = match status {
        413 => "payload_too_large",
        _ => "bad_request",
    };
    serde_json::json!({
        "error": {"code": code, "message": "malformed request"}
    })
}

// ============================================================================
// Unit tests: parser malformed vectors + connection-loop round trips
// (valid / malformed / limits / smuggling / partial-packet timeout)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn head(bytes: &[u8]) -> Result<Option<ParsedHead>, ParseError> {
        parse_head(bytes)
    }

    /// Valid GET/POST parsing: path/query/header reads/keep-alive decision/
    /// Content-Length.
    #[test]
    fn parse_valid_get_and_post() {
        let h = head(b"GET /api/peers HTTP/1.1\r\nHost: 127.0.0.1:9800\r\n\r\n")
            .expect("parse")
            .expect("complete");
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/api/peers");
        assert_eq!(h.query, "");
        assert_eq!(
            h.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("HOST"))
                .map(|(_, v)| v.as_str()),
            Some("127.0.0.1:9800"),
            "header reads case-insensitive"
        );
        assert!(h.keep_alive, "HTTP/1.1 defaults to keep-alive");
        assert_eq!(h.content_length, None);

        let h = head(
            b"POST /api/login-begin?x=1 HTTP/1.1\r\nContent-Type: application/json\r\ncontent-length: 7\r\nConnection: close\r\n\r\n",
        )
        .expect("parse")
        .expect("complete");
        assert_eq!(h.method, "POST");
        assert_eq!(h.path, "/api/login-begin");
        assert_eq!(h.query, "x=1");
        assert_eq!(h.content_length, Some(7));
        assert!(!h.keep_alive, "Connection: close disables keep-alive");

        // HTTP/1.0: defaults to close; explicit keep-alive enables it.
        let h10 = head(b"GET / HTTP/1.0\r\n\r\n").unwrap().unwrap();
        assert!(!h10.keep_alive);
        let h10k = head(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
            .unwrap()
            .unwrap();
        assert!(h10k.keep_alive);
        // Incomplete ⇒ None (keep reading).
        assert!(head(b"GET / HTTP/1.1\r\nHost: x").unwrap().is_none());
    }

    /// Bad request line / bad version / ambiguous tokens / absolute URI ⇒
    /// BadRequest.
    #[test]
    fn parse_rejects_bad_request_line() {
        for bad in [
            &b"GET  / HTTP/1.1\r\n\r\n"[..], // double space (four tokens)
            &b"GET /\r\n\r\n"[..],           // two tokens
            &b"GET / HTTP/2.0\r\n\r\n"[..],  // version
            &b"get / HTTP/1.1\r\n\r\n"[..],  // lowercase method
            &b"GET http://evil/ HTTP/1.1\r\n\r\n"[..], // absolute URI (proxy form)
            &b"GET /a HTTP/1.1 extra\r\n\r\n"[..], // four tokens
            &b"GET\x00 / HTTP/1.1\r\n\r\n"[..], // control character
            &b"GET / HTT\r\n\r\n"[..],
            &b"GET /a b HTTP/1.1\r\n\r\n"[..], // target contains a space (ambiguous)
        ] {
            assert_eq!(head(bad), Err(ParseError::BadRequest), "reject: {bad:?}");
        }
    }

    /// Smuggling surfaces rejected: Transfer-Encoding (any value / any case)
    /// and duplicate Content-Length (including comma multi-values) ⇒ dedicated
    /// error codes (the connection layer uniformly 400s and closes).
    #[test]
    fn parse_rejects_smuggling_vectors() {
        assert_eq!(
            head(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::TransferEncoding)
        );
        assert_eq!(
            head(b"POST /x HTTP/1.1\r\ntransfer-encoding: identity\r\n\r\n"),
            Err(ParseError::TransferEncoding)
        );
        assert_eq!(
            head(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
            Err(ParseError::DuplicateContentLength)
        );
        assert_eq!(
            head(b"POST /x HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n"),
            Err(ParseError::DuplicateContentLength)
        );
        // Bad Content-Length values (minus sign / hexadecimal / non-digit) ⇒
        // BadRequest.
        for v in ["-1", "0x10", "abc", "+5", ""] {
            let req = format!("POST /x HTTP/1.1\r\nContent-Length: {v}\r\n\r\n");
            assert_eq!(
                head(req.as_bytes()),
                Err(ParseError::BadRequest),
                "CL value {v:?} rejected"
            );
        }
    }

    /// Limits: request line > 2KiB / header block > 8KiB ⇒ HeadTooLarge
    /// (400); body > 64KiB ⇒ PayloadTooLarge (413).
    #[test]
    fn parse_enforces_size_limits() {
        let long_line = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST_LINE));
        assert_eq!(head(long_line.as_bytes()), Err(ParseError::HeadTooLarge));
        let big_header = format!(
            "GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n",
            "h".repeat(MAX_HEAD + 1)
        );
        assert_eq!(head(big_header.as_bytes()), Err(ParseError::HeadTooLarge));
        let big_body = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(head(big_body.as_bytes()), Err(ParseError::PayloadTooLarge));
        // Exactly within limits passes (boundary: total request-line length
        // exactly MAX_REQUEST_LINE; "GET /" + pad + " HTTP/1.1" = 14 + pad).
        let pad = MAX_REQUEST_LINE - 14;
        let ok_line = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(pad));
        assert_eq!(
            ok_line.find("\r\n").unwrap(),
            MAX_REQUEST_LINE,
            "boundary self-check: request line exactly 2KiB"
        );
        assert!(head(ok_line.as_bytes()).unwrap().is_some());
        let over = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(pad + 1));
        assert_eq!(head(over.as_bytes()), Err(ParseError::HeadTooLarge));
        let ok_body = format!("POST /x HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n");
        assert!(head(ok_body.as_bytes()).unwrap().is_some());
    }

    /// Bad header shapes rejected: obs-fold (leading whitespace), whitespace
    /// inside names, missing colon, empty header name.
    #[test]
    fn parse_rejects_bad_header_shapes() {
        assert_eq!(
            head(b"GET / HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n"),
            Err(ParseError::BadRequest),
            "obs-fold rejected"
        );
        assert_eq!(
            head(b"GET / HTTP/1.1\r\nBad Header: 1\r\n\r\n"),
            Err(ParseError::BadRequest),
            "whitespace in name rejected"
        );
        assert_eq!(
            head(b"GET / HTTP/1.1\r\nNoColon\r\n\r\n"),
            Err(ParseError::BadRequest),
            "missing colon rejected"
        );
        assert_eq!(
            head(b"GET / HTTP/1.1\r\n: v\r\n\r\n"),
            Err(ParseError::BadRequest),
            "empty header name rejected"
        );
        // Legal header names with -/_ pass.
        assert!(head(b"GET / HTTP/1.1\r\nX-Flock-Web: 1\r\nX_A: 2\r\n\r\n")
            .unwrap()
            .is_some());
    }

    /// Single-key cookie parsing.
    #[test]
    fn session_cookie_extraction() {
        let mut req = Request {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            headers: vec![(
                "Cookie".into(),
                "other=1; flock_session=abc123; more=2".into(),
            )],
            body: vec![],
        };
        assert_eq!(req.session_cookie(), Some("abc123"));
        req.headers.clear();
        assert_eq!(req.session_cookie(), None);
        req.headers.push(("Cookie".into(), "flock_session=".into()));
        assert_eq!(req.session_cookie(), Some(""));
    }

    // —— Connection loop (real socket): valid round trips / keep-alive /
    // malformed close / partial-packet timeout ——

    /// Test vehicle: start an echo-handler server, return the listen address.
    async fn spawn_echo() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut io, remote)) = listener.accept().await else {
                    return;
                };
                let handler: Handler = Box::new(move |req: Request, r: SocketAddr| {
                    Box::pin(async move {
                        let body = format!(
                            "{} {} q={} body={} remote={}",
                            req.method,
                            req.path,
                            req.query,
                            String::from_utf8_lossy(&req.body),
                            r.ip()
                        );
                        Response::new(200).body(body.into_bytes())
                    })
                });
                tokio::spawn(async move {
                    serve_conn(&mut io, remote, handler).await;
                });
            }
        });
        addr
    }

    async fn roundtrip(addr: std::net::SocketAddr, raw: &[u8]) -> (String, bool) {
        let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
        io.write_all(raw).await.unwrap();
        let mut out = Vec::new();
        let _ = io.read_to_end(&mut out).await;
        let text = String::from_utf8_lossy(&out).into_owned();
        let closed = !text.is_empty(); // read_to_end returning means the peer closed
        (text, closed)
    }

    #[tokio::test]
    async fn conn_valid_roundtrip_and_keepalive() {
        let addr = spawn_echo().await;
        // GET round trip (with query and headers; roundtrip closes to avoid
        // the read side hanging on keep-alive).
        let (text, _) = roundtrip(
            addr,
            b"GET /api/x?v=1 HTTP/1.1\r\nHost: h\r\nX-Flock-Web: 1\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("content-length:"), "Content-Length added");
        assert!(
            text.contains("GET /api/x q=v=1 body= remote=127.0.0.1"),
            "{text}"
        );

        // keep-alive: two requests on one connection (the second with a
        // body).
        let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
        io.write_all(
            b"POST /a HTTP/1.1\r\nContent-Type: application/json\r\ncontent-length: 3\r\n\r\nxyz",
        )
        .await
        .unwrap();
        let mut first = vec![0u8; 256];
        let n = io.read(&mut first).await.unwrap();
        let first = String::from_utf8_lossy(&first[..n]).into_owned();
        assert!(first.contains("POST /a q= body=xyz"), "{first}");
        assert!(first.contains("connection: keep-alive"), "{first}");
        io.write_all(b"GET /b HTTP/1.1\r\n\r\n").await.unwrap();
        let mut second = vec![0u8; 256];
        let n = io.read(&mut second).await.unwrap();
        let second = String::from_utf8_lossy(&second[..n]).into_owned();
        assert!(
            second.contains("GET /b q= body="),
            "keep-alive second request: {second}"
        );

        // Connection: close ⇒ explicit close.
        let (text, closed) = roundtrip(addr, b"GET /c HTTP/1.1\r\nConnection: close\r\n\r\n").await;
        assert!(closed && text.contains("connection: close"), "{text}");
    }

    #[tokio::test]
    async fn conn_malformed_close_and_oversized() {
        let addr = spawn_echo().await;
        // Transfer-Encoding ⇒ 400 + close.
        let (text, _) = roundtrip(
            addr,
            b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
        assert!(text.contains("connection: close"), "{text}");
        assert!(text.contains("\"code\":\"bad_request\""), "{text}");
        // Duplicate Content-Length ⇒ 400.
        let (text, _) = roundtrip(
            addr,
            b"POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
        // Body > 64KiB (declared) ⇒ 413.
        let big = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let (text, _) = roundtrip(addr, big.as_bytes()).await;
        assert!(text.starts_with("HTTP/1.1 413"), "{text}");
        assert!(text.contains("\"code\":\"payload_too_large\""), "{text}");
        // Header block over the limit ⇒ 400.
        let big_header = format!(
            "GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n",
            "h".repeat(MAX_HEAD + 16)
        );
        let (text, _) = roundtrip(addr, big_header.as_bytes()).await;
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    }

    /// Partial-packet timeout: send an incomplete head then stay silent ——
    /// after READ_TIMEOUT the connection is closed (EOF arrives).
    /// (READ_TIMEOUT=15s is too long for tests: this test only verifies that
    /// the "an incomplete request does not hang forever" mechanism exists ——
    /// after sending the partial packet, wait 300ms and assert the connection
    /// is still open (not killed by mistake); the peer-close side is left to
    /// real deployments; the shortened wait avoids a 15s block on the test
    /// surface.)
    #[tokio::test]
    async fn conn_partial_request_held_open_until_timeout_or_eof() {
        let addr = spawn_echo().await;
        let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
        io.write_all(b"GET / HTTP/1.1\r\nHost: x").await.unwrap();
        // Partial packet: the connection must not be closed within the
        // timeout window (read returns WouldBlock/0 bytes).
        io.async_read_no_close_probe().await;
        // Peer closes (EOF) ⇒ the server winds down silently (no response
        // written —— no panic).
        drop(io);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// Slow-drip vector (review item 1): 25ms between bytes (each single read
    /// is far inside READ_TIMEOUT=15s) but the head never completes and the
    /// total duration exceeds the total budget ⇒ the connection is cut by the
    /// total limit + the counter increments (otherwise a MAX_CONCURRENCY=64
    /// permit could be held indefinitely —— a VIP-surface DoS on the admin
    /// surface). Budget injected as 300ms (serve_conn_with_budget) —— the
    /// same mechanism as the production REQUEST_TOTAL=30s.
    #[tokio::test]
    async fn conn_slow_drip_killed_by_request_total_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut io, remote)) = listener.accept().await else {
                    return;
                };
                let handler: Handler = Box::new(|_req: Request, _r: SocketAddr| {
                    Box::pin(async { Response::new(200) })
                });
                tokio::spawn(async move {
                    serve_conn_with_budget(
                        &mut io,
                        remote,
                        handler,
                        std::time::Duration::from_millis(300),
                    )
                    .await;
                });
            }
        });
        let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
        let before = slow_request_kills();
        // Byte-by-byte drip: a head that never completes (22B × 25ms = 550ms
        // > 300ms budget).
        let drip = b"GET / HTTP/1.1\r\nHost: x\r\n";
        for b in drip.iter() {
            if io.write_all(&[*b]).await.is_err() {
                break; // server already cut (expected path —— writing after Windows half-close RSTs)
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        // Assert the cut: read-side EOF or error (within 2s), and the counter
        // incremented.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_secs(2), io.read(&mut probe)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {} // EOF / connection reset —— both count as "cut"
            Ok(Ok(n)) => panic!("a slow drip should not receive {n}B of response data"),
            Err(_) => panic!("slow-drip connection not cut by the total limit (permit still held)"),
        }
        assert!(
            slow_request_kills() > before,
            "total-limit expiry closing a connection must count ({} → {})",
            before,
            slow_request_kills()
        );
    }

    /// Helper: non-blocking probe —— reading 0 bytes within a short window
    /// (no data and not closed) means the connection is still open.
    trait NoCloseProbe {
        async fn async_read_no_close_probe(&mut self);
    }
    impl NoCloseProbe for tokio::net::TcpStream {
        async fn async_read_no_close_probe(&mut self) {
            self.set_nodelay(true).ok();
            let mut probe = [0u8; 1];
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                tokio::net::TcpStream::read(self, &mut probe),
            )
            .await
            {
                // No bytes and no EOF within 200ms ⇒ connection still open
                // (partial packet held).
                Err(_) => {}
                Ok(Ok(0)) => panic!("a partial-packet request must not be closed immediately"),
                Ok(Ok(n)) => panic!("no data expected: {n}"),
                Ok(Err(e)) => panic!("probe err: {e}"),
            }
        }
    }
}

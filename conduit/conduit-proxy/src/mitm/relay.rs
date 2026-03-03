//! Inner HTTP relay for MITM-decrypted CONNECT tunnels.
//!
//! Parses each HTTP request/response inside the decrypted tunnel,
//! logs full details (method, path, headers, content-type, status),
//! then forwards bytes between client and upstream.
//! Loops for HTTP/1.1 keep-alive connections.

use conduit_common::types::{AuthMethod, LogEntry, PolicyAction};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::logging::LogSender;

/// Maximum header block size (request line + headers) before rejecting.
const MAX_HEADER_SIZE: usize = 65536;

/// Maximum chunk size for chunked transfer encoding (256 MB).
const MAX_CHUNK_SIZE: u64 = 256 * 1024 * 1024;

/// Parsed HTTP request line + headers.
struct ParsedRequest {
    method: String,
    path: String,
    #[allow(dead_code)]
    version: String,
    host: Option<String>,
    content_length: Option<u64>,
    is_chunked: bool,
    /// Raw header bytes to forward verbatim (request line + headers + \r\n).
    raw_head: Vec<u8>,
}

/// Parsed HTTP response status + headers.
struct ParsedResponse {
    status_code: u16,
    content_type: Option<String>,
    content_length: Option<u64>,
    is_chunked: bool,
    connection_close: bool,
    /// Raw header bytes to forward verbatim.
    raw_head: Vec<u8>,
}

/// Run the inner HTTP relay loop between two decrypted streams.
/// Logs each request/response as a separate LogEntry.
///
/// Returns total (client_to_server, server_to_client) byte counts.
pub async fn relay_loop<C, U>(
    client: C,
    upstream: U,
    host: &str,
    port: u16,
    upstream_addr: &str,
    log_tx: &LogSender,
    client_ip: &str,
    category: Option<&str>,
    username: Option<&str>,
    auth_method: Option<AuthMethod>,
) -> (u64, u64)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_r = BufReader::with_capacity(8192, client);
    let mut upstream = upstream;
    let mut total_up: u64 = 0;
    let mut total_down: u64 = 0;

    loop {
        let start = chrono::Utc::now();

        // --- Read request from client ---
        let req = match read_request(&mut client_r).await {
            Ok(Some(r)) => r,
            Ok(None) => break, // client closed cleanly
            Err(e) => {
                debug!(host, "Error reading inner request: {e}");
                break;
            }
        };

        let method = req.method.clone();
        let path = req.path.clone();
        let req_host = req.host.clone().unwrap_or_else(|| host.to_string());

        // --- Forward request head to upstream ---
        if upstream.write_all(&req.raw_head).await.is_err() {
            break;
        }
        total_up += req.raw_head.len() as u64;

        // --- Forward request body ---
        let req_body_bytes = match forward_body(&mut client_r, &mut upstream, &req.content_length, req.is_chunked).await {
            Ok(n) => n,
            Err(_) => break,
        };
        total_up += req_body_bytes;

        // --- Read response from upstream ---
        // We need to buffer upstream reads too for header parsing
        let mut upstream_buf = BufReader::with_capacity(8192, upstream);

        let resp = match read_response(&mut upstream_buf).await {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                debug!(host, "Error reading inner response: {e}");
                break;
            }
        };

        let status_code = resp.status_code;
        let content_type = resp.content_type.clone();
        let connection_close = resp.connection_close;

        // --- Forward response head to client ---
        // Get the inner writer back from BufReader for the client write
        let client_w = client_r.get_mut();
        if client_w.write_all(&resp.raw_head).await.is_err() {
            break;
        }
        total_down += resp.raw_head.len() as u64;

        // --- Forward response body ---
        let resp_body_bytes = match forward_body(&mut upstream_buf, client_w, &resp.content_length, resp.is_chunked).await {
            Ok(n) => n,
            Err(_) => break,
        };
        total_down += resp_body_bytes;

        // Flush to client
        let _ = client_w.flush().await;

        // Recover upstream from BufReader for next iteration
        upstream = upstream_buf.into_inner();

        // --- Log this request ---
        let full_url = format!("https://{req_host}{path}");
        let entry = LogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: start,
            client_ip: client_ip.to_string(),
            username: username.map(|s| s.to_string()),
            auth_method,
            method,
            scheme: "https".into(),
            host: req_host,
            port,
            path,
            full_url,
            category: category.map(|s| s.to_string()),
            action: PolicyAction::Allow,
            rule_id: None,
            status_code,
            request_bytes: req.raw_head.len() as u64 + req_body_bytes,
            response_bytes: resp.raw_head.len() as u64 + resp_body_bytes,
            duration_ms: (chrono::Utc::now() - start).num_milliseconds().max(0) as u64,
            tls_intercepted: true,
            upstream_addr: Some(upstream_addr.to_string()),
            content_type,
            node_id: None,
            node_name: None,
        };
        log_tx.send(entry);

        if connection_close {
            break;
        }
    }

    (total_up, total_down)
}

/// Read an HTTP request (request line + headers) from the client stream.
/// Returns `None` on clean EOF (connection closed).
async fn read_request<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> io::Result<Option<ParsedRequest>> {
    let mut raw_head = Vec::with_capacity(2048);

    // Read lines until we hit the empty line (\r\n)
    loop {
        let before = raw_head.len();
        let n = reader.read_until(b'\n', &mut raw_head).await?;
        if n == 0 {
            if raw_head.is_empty() {
                return Ok(None); // clean EOF
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed mid-headers"));
        }
        if raw_head.len() > MAX_HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request headers too large"));
        }
        // Check if this line is just \r\n (end of headers)
        let line = &raw_head[before..];
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }

    // Parse with httparse
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&raw_head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "incomplete request headers"));
        }
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid request: {e}")));
        }
    }

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

    let mut host = None;
    let mut content_length = None;
    let mut is_chunked = false;

    for h in req.headers.iter() {
        let name_lower = h.name.to_ascii_lowercase();
        match name_lower.as_str() {
            "host" => host = Some(String::from_utf8_lossy(h.value).to_string()),
            "content-length" => {
                content_length = std::str::from_utf8(h.value).ok().and_then(|s| s.trim().parse().ok());
            }
            "transfer-encoding" => {
                let val = String::from_utf8_lossy(h.value).to_ascii_lowercase();
                is_chunked = val.contains("chunked");
            }
            _ => {}
        }
    }

    Ok(Some(ParsedRequest {
        method,
        path,
        version,
        host,
        content_length,
        is_chunked,
        raw_head,
    }))
}

/// Read an HTTP response (status line + headers) from the upstream stream.
async fn read_response<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> io::Result<Option<ParsedResponse>> {
    let mut raw_head = Vec::with_capacity(4096);

    loop {
        let before = raw_head.len();
        let n = reader.read_until(b'\n', &mut raw_head).await?;
        if n == 0 {
            if raw_head.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed mid-response-headers"));
        }
        if raw_head.len() > MAX_HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response headers too large"));
        }
        let line = &raw_head[before..];
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&raw_head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "incomplete response headers"));
        }
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid response: {e}")));
        }
    }

    let status_code = resp.code.unwrap_or(0);
    let mut content_type = None;
    let mut content_length = None;
    let mut is_chunked = false;
    let mut connection_close = false;

    for h in resp.headers.iter() {
        let name_lower = h.name.to_ascii_lowercase();
        match name_lower.as_str() {
            "content-type" => {
                content_type = Some(String::from_utf8_lossy(h.value).to_string());
            }
            "content-length" => {
                content_length = std::str::from_utf8(h.value).ok().and_then(|s| s.trim().parse().ok());
            }
            "transfer-encoding" => {
                let val = String::from_utf8_lossy(h.value).to_ascii_lowercase();
                is_chunked = val.contains("chunked");
            }
            "connection" => {
                let val = String::from_utf8_lossy(h.value).to_ascii_lowercase();
                connection_close = val.contains("close");
            }
            _ => {}
        }
    }

    Ok(Some(ParsedResponse {
        status_code,
        content_type,
        content_length,
        is_chunked,
        connection_close,
        raw_head,
    }))
}

/// Forward a message body from reader to writer, based on Content-Length or chunked encoding.
/// Returns the number of body bytes forwarded.
async fn forward_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    content_length: &Option<u64>,
    is_chunked: bool,
) -> io::Result<u64>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    if is_chunked {
        forward_chunked(reader, writer).await
    } else if let Some(len) = content_length {
        forward_fixed(reader, writer, *len).await
    } else {
        // No body (GET, HEAD, etc.)
        Ok(0)
    }
}

/// Forward a fixed-length body.
async fn forward_fixed<R, W>(reader: &mut R, writer: &mut W, length: u64) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = length;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body truncated"));
        }
        writer.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    Ok(length)
}

/// Forward a chunked transfer-encoded body, including chunk framing.
async fn forward_chunked<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        // Read chunk size line
        let mut size_line = Vec::new();
        reader.read_until(b'\n', &mut size_line).await?;
        writer.write_all(&size_line).await?;
        total += size_line.len() as u64;

        // Parse chunk size (hex)
        let size_str = String::from_utf8_lossy(&size_line);
        let size_str = size_str.trim();
        // Chunk size might have extensions after semicolon
        let hex = size_str.split(';').next().unwrap_or("0").trim();
        let chunk_size = u64::from_str_radix(hex, 16).unwrap_or(0);

        if chunk_size > MAX_CHUNK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk size {chunk_size} exceeds maximum {MAX_CHUNK_SIZE}"),
            ));
        }

        if chunk_size == 0 {
            // Terminal chunk — read and forward trailing \r\n
            let mut trailer = Vec::new();
            reader.read_until(b'\n', &mut trailer).await?;
            writer.write_all(&trailer).await?;
            total += trailer.len() as u64;
            break;
        }

        // Forward chunk data + trailing \r\n
        let mut remaining = chunk_size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk data truncated"));
            }
            writer.write_all(&buf[..n]).await?;
            remaining -= n as u64;
            total += n as u64;
        }
        // Read trailing \r\n after chunk data
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        writer.write_all(&crlf).await?;
        total += 2;
    }
    Ok(total)
}

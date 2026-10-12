//! Opt-in, scoped assessment capture. Payloads are encrypted before entering Valkey.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use boring::symm::{decrypt_aead, encrypt_aead, Cipher};
use deadpool_redis::Pool;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const RUN_HEADER: &str = "x-conduit-assessment";
pub const TOKEN_HEADER: &str = "x-conduit-capture-token";
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_FLOWS: usize = 1000;
pub const MAX_TTL: u64 = 86400;
pub const MAX_HEADERS: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct AssessmentSession {
    pub id: String,
    pub token: String,
    pub origins: Vec<String>,
    pub expires_at: i64,
    pub max_body_bytes: usize,
    pub max_flows: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CapturedMessage {
    pub headers: Vec<(String, String)>,
    pub body_base64: String,
    pub truncated: bool,
    #[serde(default)]
    pub headers_truncated: bool,
}

impl CapturedMessage {
    pub fn set_headers(&mut self, headers: impl IntoIterator<Item = (String, String)>) {
        self.headers.clear();
        let mut size = 0;
        for (name, value) in headers {
            size += name.len() + value.len() + 4;
            if size > MAX_HEADERS || value == "[non-text]" {
                self.headers_truncated = true;
                break;
            }
            self.headers.push((name, value));
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedFlow {
    pub id: String,
    pub run_id: String,
    pub timestamp: i64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub request: CapturedMessage,
    pub response: CapturedMessage,
}

pub struct PendingCapture {
    pub session: AssessmentSession,
    pub flow: CapturedFlow,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
}

impl PendingCapture {
    pub fn append(&mut self, response: bool, bytes: &[u8]) {
        let (buffer, message) = if response {
            (&mut self.response_body, &mut self.flow.response)
        } else {
            (&mut self.request_body, &mut self.flow.request)
        };
        let available = self.session.max_body_bytes.saturating_sub(buffer.len());
        message.truncated |= bytes.len() > available;
        buffer.extend_from_slice(&bytes[..bytes.len().min(available)]);
    }

    pub fn finish(mut self) -> (AssessmentSession, CapturedFlow) {
        self.flow.request.body_base64 = STANDARD.encode(self.request_body);
        self.flow.response.body_base64 = STANDARD.encode(self.response_body);
        (self.session, self.flow)
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn origin(url: &str) -> Result<String> {
    let uri = url::Url::parse(url)?;
    let scheme = uri.scheme();
    if scheme != "http" && scheme != "https" {
        bail!("only HTTP and HTTPS are supported");
    }
    let host = uri.host_str().context("URL host required")?;
    if !uri.username().is_empty() || uri.password().is_some() {
        bail!("URL credentials are not allowed");
    }
    let port = uri.port_or_known_default().context("URL port required")?;
    Ok(format!("{scheme}://{}:{port}", host.to_ascii_lowercase()))
}

pub fn session_key(id: &str) -> String {
    format!("conduit:assessment:{id}:session")
}
pub fn index_key(id: &str) -> String {
    format!("conduit:assessment:{id}:flows")
}
pub fn flow_key(run: &str, flow: &str) -> String {
    format!("conduit:assessment:{run}:flow:{flow}")
}
pub fn summary_key(run: &str, flow: &str) -> String {
    format!("{}:summary", flow_key(run, flow))
}

/// Both API and proxy must receive the same base64-encoded 32-byte key.
pub fn encryption_key() -> Result<&'static [u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    KEY.get_or_init(|| {
        let encoded = std::env::var("CONDUIT_ASSESSMENT_KEY").ok()?;
        STANDARD.decode(encoded.trim()).ok()?.try_into().ok()
    }).as_ref().context("assessment capture disabled: set CONDUIT_ASSESSMENT_KEY to a base64-encoded 32-byte key in both services")
}

pub fn seal(aad: &str, plaintext: &[u8]) -> Result<String> {
    seal_with_key(encryption_key()?, aad, plaintext)
}

fn seal_with_key(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Result<String> {
    let mut nonce = [0u8; 12];
    boring::rand::rand_bytes(&mut nonce)?;
    let mut tag = [0u8; 16];
    let encrypted = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        aad.as_bytes(),
        plaintext,
        &mut tag,
    )?;
    let mut envelope = nonce.to_vec();
    envelope.extend_from_slice(&tag);
    envelope.extend_from_slice(&encrypted);
    Ok(STANDARD.encode(envelope))
}

pub fn open(aad: &str, envelope: &str) -> Result<Vec<u8>> {
    open_with_key(encryption_key()?, aad, envelope)
}

fn open_with_key(key: &[u8; 32], aad: &str, envelope: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(envelope)?;
    if bytes.len() < 28 {
        bail!("invalid encrypted capture");
    }
    Ok(decrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&bytes[..12]),
        aad.as_bytes(),
        &bytes[28..],
        &bytes[12..28],
    )?)
}

pub async fn load_session(pool: &Pool, id: &str) -> Result<Option<AssessmentSession>> {
    if !valid_id(id) {
        return Ok(None);
    }
    let mut conn = pool.get().await?;
    let key = session_key(id);
    let value: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut *conn).await?;
    value
        .map(|value| Ok(serde_json::from_slice(&open(&key, &value)?)?))
        .transpose()
}

pub async fn store_flow(
    pool: &Pool,
    session: &AssessmentSession,
    flow: &CapturedFlow,
) -> Result<()> {
    let key = flow_key(&session.id, &flow.id);
    let encrypted = seal(&key, &serde_json::to_vec(flow)?)?;
    let summary_key = summary_key(&session.id, &flow.id);
    let summary = serde_json::json!({"id": flow.id, "run_id": flow.run_id, "timestamp": flow.timestamp,
        "method": flow.method, "url": flow.url, "status": flow.status,
        "duration_ms": flow.duration_ms, "error": flow.error,
        "request_truncated": flow.request.truncated, "response_truncated": flow.response.truncated,
        "request_headers_truncated": flow.request.headers_truncated, "response_headers_truncated": flow.response.headers_truncated});
    let encrypted_summary = seal(&summary_key, &serde_json::to_vec(&summary)?)?;
    let mut conn = pool.get().await?;
    // Atomic reservation, bounded index, and absolute expiry. A deleted/expired session
    // cannot be resurrected by a request that was still in flight.
    let script = redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
        if redis.call('LLEN', KEYS[2]) >= tonumber(ARGV[3]) then return 0 end
        redis.call('SET', KEYS[3], ARGV[1])
        redis.call('EXPIREAT', KEYS[3], ARGV[2])
        redis.call('SET', KEYS[4], ARGV[5])
        redis.call('EXPIREAT', KEYS[4], ARGV[2])
        redis.call('LPUSH', KEYS[2], ARGV[4])
        redis.call('EXPIREAT', KEYS[2], ARGV[2])
        return 1
    "#,
    );
    let _: i64 = script
        .key(session_key(&session.id))
        .key(index_key(&session.id))
        .key(key)
        .key(summary_key)
        .arg(encrypted)
        .arg(session.expires_at)
        .arg(session.max_flows)
        .arg(&flow.id)
        .arg(encrypted_summary)
        .invoke_async(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_have_a_separate_bound_and_preserve_duplicates() {
        let mut message = CapturedMessage::default();
        message.set_headers(vec![
            ("cookie".into(), "a=1".into()),
            ("cookie".into(), "b=2".into()),
            ("large".into(), "x".repeat(MAX_HEADERS)),
        ]);
        assert_eq!(message.headers.len(), 2);
        assert!(message.headers_truncated);
        assert!(!message.truncated);
    }
    #[test]
    fn ciphertext_is_randomized_and_bound_to_its_key_namespace() {
        let key = [42; 32];
        let one = seal_with_key(&key, "flow:1", b"Bearer secret").unwrap();
        let two = seal_with_key(&key, "flow:1", b"Bearer secret").unwrap();
        assert_ne!(one, two);
        assert_eq!(
            open_with_key(&key, "flow:1", &one).unwrap(),
            b"Bearer secret"
        );
        assert!(open_with_key(&key, "flow:2", &one).is_err());
        assert!(open_with_key(&[43; 32], "flow:1", &one).is_err());
        let mut bytes = STANDARD.decode(one).unwrap();
        bytes[28] ^= 1;
        assert!(open_with_key(&key, "flow:1", &STANDARD.encode(bytes)).is_err());
    }
    #[test]
    fn origins_match_scheme_host_and_port() {
        assert_eq!(
            origin("https://EXAMPLE.com/path").unwrap(),
            "https://example.com:443"
        );
        assert_ne!(
            origin("http://example.com").unwrap(),
            origin("https://example.com").unwrap()
        );
        assert_ne!(
            origin("http://example.com:8080").unwrap(),
            origin("http://example.com:8081").unwrap()
        );
        assert!(origin("file:///etc/passwd").is_err());
        assert!(origin("http://user:pass@example.com").is_err());
    }
    #[test]
    fn capture_buffers_are_bounded_and_mark_truncation() {
        let session = AssessmentSession {
            id: "run".into(),
            token: "token".into(),
            origins: vec![],
            expires_at: 0,
            max_body_bytes: 3,
            max_flows: 1,
        };
        let flow = CapturedFlow {
            id: "flow".into(),
            run_id: "run".into(),
            timestamp: 0,
            method: "POST".into(),
            url: "http://example.com".into(),
            status: 0,
            duration_ms: 0,
            error: None,
            request: CapturedMessage::default(),
            response: CapturedMessage::default(),
        };
        let mut capture = PendingCapture {
            session,
            flow,
            request_body: vec![],
            response_body: vec![],
        };
        capture.append(false, b"ab");
        capture.append(false, b"cdef");
        capture.append(true, b"ok");
        let (_, flow) = capture.finish();
        assert_eq!(STANDARD.decode(flow.request.body_base64).unwrap(), b"abc");
        assert!(flow.request.truncated);
        assert!(!flow.response.truncated);
    }
    #[test]
    fn ids_cannot_escape_key_namespace() {
        assert!(valid_id("run-123_abc"));
        assert!(!valid_id("run:session"));
        assert!(!valid_id(""));
    }
}

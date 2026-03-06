//! Tier 2: Content inspection for response bodies.
//!
//! Analyzes the first N bytes of response bodies for:
//! - JavaScript obfuscation patterns
//! - Phishing HTML indicators
//! - Suspicious binary content
//! - Redirect chain abuse

use conduit_common::types::{ThreatSignal, ThreatTier};
use flate2::read::{DeflateDecoder, GzDecoder};
use once_cell::sync::Lazy;
use std::io::Read;
use regex::RegexSet;

// ---------------------------------------------------------------------------
// JavaScript obfuscation detection
// ---------------------------------------------------------------------------

static JS_OBFUSCATION_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"(?i)\beval\s*\(",
        r"(?i)\batob\s*\(",
        r"(?i)String\.fromCharCode",
        r"(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
        r"(?i)\\u[0-9a-f]{4}\\u[0-9a-f]{4}",
        r"(?i)document\.write\s*\(",
        r"(?i)unescape\s*\(",
        r"(?i)decodeURIComponent\s*\(",
    ])
    .expect("invalid JS obfuscation regex")
});

/// Detect JavaScript obfuscation patterns in response body.
pub fn detect_js_obfuscation(body: &[u8]) -> Vec<ThreatSignal> {
    // Only analyze if it looks like JS/HTML
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let matches: Vec<_> = JS_OBFUSCATION_PATTERNS.matches(text).into_iter().collect();
    if matches.is_empty() {
        return vec![];
    }

    let score = (matches.len() as f32 * 0.15).min(0.8);

    // Check entropy of any inline script blocks for additional signal
    let high_entropy = text.contains("<script") && {
        // Simple heuristic: look for long hex or base64 strings
        text.contains("\\x") || (text.len() > 1000 && super::entropy::shannon_entropy(text) > 5.5)
    };

    let final_score = if high_entropy {
        (score + 0.15).min(0.9)
    } else {
        score
    };

    vec![ThreatSignal {
        name: "js_obfuscation".into(),
        score: final_score,
        tier: ThreatTier::Tier2,
    }]
}

// ---------------------------------------------------------------------------
// Phishing HTML detection
// ---------------------------------------------------------------------------

static PHISHING_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Credential harvesting — specific input types
        r#"(?i)<input[^>]*type\s*=\s*["']?password"#,
        r#"(?i)<input[^>]*type\s*=\s*["']?email"#,
        r#"(?i)<input[^>]*name\s*=\s*["']?(email|user|login|passwd|pass)"#,
        // Forms with POST method (credential submission)
        r#"(?i)<form[^>]*method\s*=\s*["']?post"#,
        r#"(?i)<form[^>]*action\s*=\s*["']?https?://"#,
        // Generic text inputs with required attribute (credential forms)
        r#"(?i)<input[^>]*type\s*=\s*["']?text[^>]*required"#,
        // Hidden/deceptive elements
        r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh"#,
        r#"(?i)<iframe[^>]*style\s*=\s*["'][^"']*display\s*:\s*none"#,
        r#"(?i)<iframe[^>]*width\s*=\s*["']?0"#,
        // Phishing language (English)
        r"(?i)sign\s*in|log\s*in|verify\s*your\s*account",
        r"(?i)your\s*account\s*(has\s*been|is)\s*(suspended|locked|compromised)",
        r"(?i)verify\s*your\s*(identity|email|information)",
        r"(?i)unusual\s*(activity|sign.?in|login)",
        r"(?i)confirm\s*your\s*(identity|account|payment)",
        r"(?i)update\s*your\s*(payment|billing|account)",
        r"(?i)review\s*(this\s*)?document",
        r"(?i)action\s*required",
        // Phishing language (multilingual — German, French, Spanish, Italian)
        r"(?i)anmelden|einloggen|passwort|kennwort|benutzername",
        r"(?i)connecter|mot\s*de\s*passe|identifiant|connexion",
        r"(?i)iniciar\s*sesi|contrase|usuario|verificar\s*su\s*cuenta",
        r"(?i)accedi|password|nome\s*utente|verifica",
        // Anti-analysis / evasion
        r"(?i)navigator\.webdriver",
        r#"(?i)document\.referrer\s*===?\s*["']"#,
    ])
    .expect("invalid phishing regex")
});

/// Detect phishing indicators in HTML/JS response body.
pub fn detect_phishing_html(body: &[u8], host: &str) -> Vec<ThreatSignal> {
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return vec![], // Non-UTF8 content — skip (phishing pages are always UTF-8)
    };

    // Fast pre-check: skip regex if no relevant HTML/JS tokens present
    if !text.contains('<') && !text.contains("sign") && !text.contains("login")
        && !text.contains("password") && !text.contains("Sign")
        && !text.contains("Login") && !text.contains("Password")
    {
        return vec![];
    }

    detect_phishing_in_text(text, host)
}

fn detect_phishing_in_text(text: &str, host: &str) -> Vec<ThreatSignal> {
    let matches: Vec<_> = PHISHING_PATTERNS.matches(text).into_iter().collect();
    if matches.is_empty() {
        return vec![];
    }

    // Scale by number of indicators — more matches = higher confidence
    let mut score = match matches.len() {
        1 => 0.3,
        2 => 0.5,
        3 => 0.65,
        _ => 0.8,
    };

    // Bonus: form action points to a different domain (credential exfiltration)
    let text_lower = text.to_lowercase();
    if let Some(pos) = text_lower.find("action=") {
        let after = &text_lower[pos + 7..];
        let action_url: String = after
            .chars()
            .skip_while(|c| *c == '"' || *c == '\'')
            .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect();
        if action_url.starts_with("http") && !action_url.contains(host) {
            score = (score + 0.15_f32).min(0.95_f32);
        }
    }

    vec![ThreatSignal {
        name: format!("phishing_html({}matches)", matches.len()),
        score,
        tier: ThreatTier::Tier2,
    }]
}

// ---------------------------------------------------------------------------
// Thin page detection
// ---------------------------------------------------------------------------

/// Detect HTML pages with almost no visible text content.
/// Phishing captcha gates, blank loader shells, and JS-only redirectors all
/// share the same trait: the page is mostly markup/script with very little
/// human-readable text. Legitimate pages — even minimal ones — have headings,
/// paragraphs, or navigation text.
///
/// Extracts visible text by stripping tags, then measures the ratio of text
/// characters to total body size. Pages below a threshold are flagged.
fn detect_thin_page(body: &[u8]) -> Vec<ThreatSignal> {
    // Only works on UTF-8 HTML
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return vec![],
    };

    // Need a minimum body size to avoid flagging tiny legitimate responses
    if body.len() < 512 {
        return vec![];
    }

    let visible_chars = extract_visible_text_len(text);

    // Ratio of visible text to total body
    let ratio = visible_chars as f32 / body.len() as f32;

    // Threshold: pages with < 5% visible text relative to body size.
    // Typical web pages are 10-40% text. Pure loader/challenge shells are < 3%.
    if ratio < 0.05 && visible_chars < 200 {
        return vec![ThreatSignal {
            name: format!("thin_page(visible={visible_chars},ratio={ratio:.3})"),
            score: 0.3,
            tier: ThreatTier::Tier2,
        }];
    }

    vec![]
}

/// Count visible text characters by stripping HTML tags and script/style blocks.
/// Operates directly on the original bytes with ASCII case-insensitive comparisons
/// to avoid allocating a lowercased copy of the entire HTML body.
fn extract_visible_text_len(html: &str) -> usize {
    let mut count = 0usize;
    let mut in_tag = false;
    let mut in_script = false;
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !in_tag && bytes[i] == b'<' {
            // Check for <script (7 chars) or <style (6 chars) opening tags
            if i + 7 <= len && bytes[i..i + 7].eq_ignore_ascii_case(b"<script") {
                in_script = true;
            } else if i + 6 <= len && bytes[i..i + 6].eq_ignore_ascii_case(b"<style") {
                in_script = true;
            }
            // Check for </script> (9 chars) or </style> (8 chars) closing tags
            if in_script {
                if i + 9 <= len && bytes[i..i + 9].eq_ignore_ascii_case(b"</script>") {
                    in_script = false;
                    i += 9;
                    continue;
                } else if i + 8 <= len && bytes[i..i + 8].eq_ignore_ascii_case(b"</style>") {
                    in_script = false;
                    i += 8;
                    continue;
                }
            }
            in_tag = true;
            i += 1;
            continue;
        }

        if in_tag {
            if bytes[i] == b'>' {
                in_tag = false;
            }
            i += 1;
            continue;
        }

        if !in_script && !bytes[i].is_ascii_whitespace() {
            count += 1;
        }
        i += 1;
    }

    count
}

// ---------------------------------------------------------------------------
// Suspicious binary detection
// ---------------------------------------------------------------------------

/// Detect suspicious binary content from non-standard MIME types.
pub fn detect_suspicious_binary(body: &[u8], content_type: Option<&str>) -> Vec<ThreatSignal> {
    if body.len() < 4 {
        return vec![];
    }

    // PE executable magic bytes
    let is_pe = body.starts_with(b"MZ");
    // ELF executable magic bytes
    let is_elf = body.starts_with(b"\x7fELF");
    // Mach-O magic bytes
    let is_macho = body.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || body.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || body.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || body.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]);

    if !is_pe && !is_elf && !is_macho {
        return vec![];
    }

    // Check if content type is misleading (e.g., claiming to be image/text but serving EXE)
    let ct = content_type.unwrap_or("");
    let suspicious_ct = ct.is_empty()
        || ct.contains("text/")
        || ct.contains("image/")
        || ct.contains("application/json")
        || ct.contains("application/xml");

    let score = if suspicious_ct { 0.85 } else { 0.3 };
    let name = if is_pe {
        "pe_binary"
    } else if is_elf {
        "elf_binary"
    } else {
        "macho_binary"
    };

    vec![ThreatSignal {
        name: name.into(),
        score,
        tier: ThreatTier::Tier2,
    }]
}

/// Detect suspicious redirect chains (3xx to different suspicious domain).
pub fn detect_redirect_chain(
    status_code: u16,
    location_header: Option<&str>,
    original_host: &str,
) -> Vec<ThreatSignal> {
    if !(300..400).contains(&status_code) {
        return vec![];
    }

    let Some(location) = location_header else {
        return vec![];
    };

    // Extract host from redirect URL
    let redirect_host = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())
        .unwrap_or("");

    if redirect_host.is_empty() || redirect_host == original_host {
        return vec![];
    }

    // Redirect to a different domain is mildly suspicious
    let score = 0.2;

    vec![ThreatSignal {
        name: "cross_domain_redirect".into(),
        score,
        tier: ThreatTier::Tier2,
    }]
}

/// Maximum decompressed size (1MB).
const MAX_DECOMPRESS: u64 = 1_048_576;
/// Maximum compression ratio before we suspect a zip bomb.
const MAX_COMPRESSION_RATIO: usize = 100;

/// Zstandard frame magic: 0xFD2FB528 (little-endian).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Try to decompress gzip/deflate/zstd/brotli content. Returns decompressed data or None.
/// Guards against zip bombs via size limit AND compression ratio check.
/// `content_encoding_br`: true when Content-Encoding indicates brotli (needed because
/// brotli has no magic bytes — without the hint we'd try to decompress every binary blob).
fn try_decompress(body: &[u8], content_encoding_br: bool) -> Option<Vec<u8>> {
    if body.len() < 4 {
        return None;
    }

    // Gzip magic: 0x1f 0x8b
    if body[0] == 0x1f && body[1] == 0x8b {
        return decompress_with_reader(GzDecoder::new(body), body.len());
    }

    // Zstandard magic: 0x28 0xB5 0x2F 0xFD
    if body.starts_with(&ZSTD_MAGIC) {
        return decompress_with_reader(zstd::Decoder::new(body).ok()?, body.len());
    }

    // Raw deflate (zlib): magic 0x78 {0x01, 0x5E, 0x9C, 0xDA}
    if body[0] == 0x78 && matches!(body[1], 0x01 | 0x5E | 0x9C | 0xDA) {
        return decompress_with_reader(DeflateDecoder::new(body), body.len());
    }

    // Brotli has no magic bytes — only attempt if the caller indicated brotli
    // encoding. Without that hint we'd waste CPU attempting to decompress every
    // binary blob (images, wasm, PDFs, etc.).
    if content_encoding_br {
        let mut decompressed = Vec::new();
        let mut reader = brotli::Decompressor::new(body, 4096);
        if reader
            .by_ref()
            .take(MAX_DECOMPRESS)
            .read_to_end(&mut decompressed)
            .is_ok()
            && !decompressed.is_empty()
            && decompressed.len() / body.len().max(1) <= MAX_COMPRESSION_RATIO
        {
            return Some(decompressed);
        }
    }

    None
}

/// Helper: decompress using any `Read` impl with zip-bomb guards.
fn decompress_with_reader<R: Read>(reader: R, compressed_len: usize) -> Option<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut limited = reader.take(MAX_DECOMPRESS);
    match limited.read_to_end(&mut decompressed) {
        Ok(_) if !decompressed.is_empty() => {
            if decompressed.len() / compressed_len.max(1) > MAX_COMPRESSION_RATIO {
                return None;
            }
            Some(decompressed)
        }
        _ => None,
    }
}

/// Run all content analysis on a response body.
pub fn analyze_response(
    body: &[u8],
    host: &str,
    content_type: Option<&str>,
    status_code: u16,
    location_header: Option<&str>,
) -> (f32, Vec<ThreatSignal>) {
    analyze_response_inner(body, host, content_type, status_code, location_header, false)
}

/// Like `analyze_response` but with an explicit brotli hint.
/// Pass `content_encoding_br = true` when the response had `Content-Encoding: br`.
#[allow(dead_code)] // used in tests; will be called from relay when CE parsing is wired up
pub fn analyze_response_with_encoding(
    body: &[u8],
    host: &str,
    content_type: Option<&str>,
    status_code: u16,
    location_header: Option<&str>,
    content_encoding_br: bool,
) -> (f32, Vec<ThreatSignal>) {
    analyze_response_inner(body, host, content_type, status_code, location_header, content_encoding_br)
}

fn analyze_response_inner(
    body: &[u8],
    host: &str,
    content_type: Option<&str>,
    status_code: u16,
    location_header: Option<&str>,
    content_encoding_br: bool,
) -> (f32, Vec<ThreatSignal>) {
    // Decompress if needed (proxied responses are often compressed).
    // Brotli has no magic bytes so we require the caller to indicate it.
    let decompressed;
    let body = if let Some(d) = try_decompress(body, content_encoding_br) {
        decompressed = d;
        &decompressed[..]
    } else {
        body
    };

    let mut all_signals = Vec::new();

    let ct = content_type.unwrap_or("");

    // JS obfuscation (only for JS/HTML content)
    if ct.contains("javascript") || ct.contains("html") || ct.is_empty() {
        all_signals.extend(detect_js_obfuscation(body));
    }

    // Phishing patterns — check both HTML and JavaScript.
    // Client-side rendered apps (React/Vue/Nuxt) put phishing strings
    // ("Sign In", "Password", brand names) in JS bundles, not the HTML shell.
    if ct.contains("html") || ct.contains("javascript") || ct.is_empty() {
        all_signals.extend(detect_phishing_html(body, host));
    }

    // Thin page detection (HTML only) — flags loader shells, captcha gates, etc.
    if ct.contains("html") || ct.is_empty() {
        all_signals.extend(detect_thin_page(body));
    }

    // Suspicious binary
    all_signals.extend(detect_suspicious_binary(body, content_type));

    // Redirect chain
    all_signals.extend(detect_redirect_chain(status_code, location_header, host));

    // Take the max signal score
    let max_score = all_signals
        .iter()
        .map(|s| s.score)
        .fold(0.0f32, f32::max);

    (max_score, all_signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_eval_obfuscation() {
        let body = b"<script>eval(atob('dGVzdA=='))</script>";
        let signals = detect_js_obfuscation(body);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detect_password_form() {
        let body = b"<form action='https://evil.com/login'><input type='password'></form>";
        let signals = detect_phishing_html(body, "bank.com");
        assert!(!signals.is_empty());
    }

    #[test]
    fn detect_pe_binary() {
        let mut body = b"MZ".to_vec();
        body.extend(vec![0u8; 100]);
        let signals = detect_suspicious_binary(&body, Some("text/html"));
        assert!(!signals.is_empty());
        assert!(signals[0].score > 0.5);
    }

    #[test]
    fn no_binary_for_correct_ct() {
        let mut body = b"MZ".to_vec();
        body.extend(vec![0u8; 100]);
        let signals = detect_suspicious_binary(&body, Some("application/octet-stream"));
        assert!(signals.is_empty() || signals[0].score < 0.5);
    }

    #[test]
    fn redirect_to_different_domain() {
        let signals = detect_redirect_chain(302, Some("https://evil.com/login"), "bank.com");
        assert!(!signals.is_empty());
    }

    #[test]
    fn brotli_decompression_phishing() {
        // Compress a phishing HTML page with Brotli, then verify analyze_response detects it
        let html = b"<html><body><form method='post'><input type='password' name='pass'>Sign In</form></body></html>";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            std::io::Write::write_all(&mut writer, html).unwrap();
        }
        // Raw HTML should not be valid UTF-8... actually it is, but compressed data won't be
        assert!(std::str::from_utf8(&compressed).is_err(), "compressed data should not be valid UTF-8");

        let (score, signals) = analyze_response_with_encoding(
            &compressed, "evil.top", Some("text/html"), 200, None, true,
        );
        assert!(
            score > 0.0,
            "brotli-compressed phishing HTML should be detected, score={score}, signals={signals:?}"
        );
        let has_phishing = signals.iter().any(|s| s.name.starts_with("phishing_html"));
        assert!(has_phishing, "should detect phishing patterns after brotli decompression, signals={signals:?}");
    }

    #[test]
    fn zstd_decompression_phishing() {
        let html = b"<html><body><form method='post'><input type='password' name='pass'>Sign In</form></body></html>";
        let compressed = zstd::encode_all(&html[..], 3).unwrap();
        assert!(compressed.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]), "should have zstd magic");

        let (score, signals) = analyze_response(
            &compressed, "evil.top", Some("text/html"), 200, None,
        );
        assert!(
            score > 0.0,
            "zstd-compressed phishing HTML should be detected, score={score}, signals={signals:?}"
        );
        let has_phishing = signals.iter().any(|s| s.name.starts_with("phishing_html"));
        assert!(has_phishing, "should detect phishing after zstd decompression, signals={signals:?}");
    }

    #[test]
    fn gzip_decompression_still_works() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let html = b"<html><body><input type='password'>Sign In</body></html>";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, html).unwrap();
        let compressed = encoder.finish().unwrap();

        let (score, _) = analyze_response(&compressed, "evil.top", Some("text/html"), 200, None);
        assert!(score > 0.0, "gzip-compressed phishing should still be detected");
    }

    #[test]
    fn thin_page_loader_shell() {
        // Minimal HTML with scripts but almost no visible text
        let html = br#"<html><head><title>.</title>
        <script src="/static/app.js"></script><script src="/static/vendor.js"></script>
        <link rel="stylesheet" href="/static/app.css"><link rel="stylesheet" href="/static/vendor.css">
        </head><body><div id="root"></div>
        <script>window.__config={api:"/api",ver:"3.2.1"};document.getElementById("root").innerHTML="";</script>
        <script src="/challenge.js"></script><script src="/metrics.js"></script>
        <noscript>Enable JavaScript</noscript></body></html>"#;
        let sigs = detect_thin_page(html);
        assert!(!sigs.is_empty(), "thin loader shell should flag, got {sigs:?}");
    }

    #[test]
    fn thin_page_real_site() {
        // Real page with substantial visible text
        let html = br#"<html><head><title>Welcome to Example</title></head>
        <body><header><nav>Home About Contact Products Blog</nav></header>
        <main><h1>Welcome to Our Website</h1>
        <p>We provide excellent services for our customers worldwide.
        Our team of dedicated professionals is here to help you succeed
        in your business endeavors. Contact us today to learn more about
        what we can offer.</p>
        <p>Founded in 2020, we have grown to serve thousands of clients
        across multiple industries. Our commitment to quality and customer
        satisfaction sets us apart from the competition.</p>
        </main><footer>Copyright 2026 Example Inc. All rights reserved.</footer></body></html>"#;
        let sigs = detect_thin_page(html);
        assert!(sigs.is_empty(), "real page should not flag as thin, got {sigs:?}");
    }
}

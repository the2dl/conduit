//! Tier 2: Content inspection for response bodies.
//!
//! Analyzes the first N bytes of response bodies for:
//! - JavaScript obfuscation patterns
//! - Phishing HTML indicators
//! - Suspicious binary content
//! - Redirect chain abuse

use conduit_common::types::{ThreatSignal, ThreatTier};
use flate2::read::GzDecoder;
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
        // Brand impersonation in page content
        r"(?i)(docusign|docu\s*sign).*review",
        r"(?i)(microsoft|office\s*365).*sign\s*in",
        r"(?i)(apple\s*id|icloud).*verify",
        r"(?i)paypal.*confirm",
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

    // Bonus: page title contains brand names but host doesn't match
    if let Some(title_start) = text_lower.find("<title") {
        let title_end = text_lower[title_start..].find("</title").unwrap_or(200) + title_start;
        let title_text = &text_lower[title_start..title_end.min(text_lower.len())];
        let brand_in_title = ["docusign", "microsoft", "apple", "paypal", "google", "amazon",
                              "netflix", "facebook", "instagram", "chase", "wellsfargo", "bankofamerica"]
            .iter()
            .any(|brand| title_text.contains(brand) && !host.contains(brand));
        if brand_in_title {
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

/// Try to decompress gzip/deflate content. Returns decompressed data or None.
/// Guards against zip bombs via size limit AND compression ratio check.
fn try_decompress(body: &[u8]) -> Option<Vec<u8>> {
    // Gzip magic: 0x1f 0x8b
    if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
        let mut decoder = GzDecoder::new(body);
        let mut decompressed = Vec::new();
        match decoder.by_ref().take(MAX_DECOMPRESS).read_to_end(&mut decompressed) {
            Ok(_) if !decompressed.is_empty() => {
                // Reject if compression ratio is suspiciously high (zip bomb)
                if body.len() > 0 && decompressed.len() / body.len().max(1) > MAX_COMPRESSION_RATIO {
                    return None;
                }
                Some(decompressed)
            }
            _ => None,
        }
    } else {
        None
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
    // Decompress gzip/deflate if needed (proxied responses are often compressed)
    let decompressed;
    let body = if let Some(d) = try_decompress(body) {
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
}

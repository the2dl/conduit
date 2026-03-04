//! Tier 0 heuristic checks: DGA detection, TLD risk, suspicious paths,
//! unusual ports, and homoglyph detection.

use conduit_common::types::{ThreatSignal, ThreatTier};
use once_cell::sync::Lazy;
use regex::RegexSet;
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

use super::entropy::shannon_entropy;

// ---------------------------------------------------------------------------
// TLD risk map
// ---------------------------------------------------------------------------

/// Known-good TLDs that contribute zero risk.
static TRUSTED_TLDS: Lazy<std::collections::HashSet<&'static str>> = Lazy::new(|| {
    [
        // Legacy gTLDs
        "com", "org", "net", "edu", "gov", "mil", "int",
        // Country codes with strong registration policies
        "us", "uk", "ca", "au", "de", "fr", "nl", "se", "no", "dk", "fi",
        "ch", "at", "be", "ie", "nz", "jp", "kr", "sg", "il",
        // Common modern gTLDs with real usage
        "io", "dev", "app", "co", "me", "ai", "sh", "is", "fm", "tv",
        "gg", "cc", "ly", "to", "im", "it", "es", "pt", "pl", "cz",
        "eu", "asia", "pro", "info", "biz", "name", "museum", "coop",
        // Tech / cloud
        "cloud", "tech", "systems", "network", "digital", "solutions",
        "software", "engineering", "design", "studio",
    ]
    .into_iter()
    .collect()
});

/// Known-bad TLDs that are heavily abused (free registration, no verification).
static BAD_TLDS: Lazy<HashMap<&'static str, f32>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Free TLDs with rampant abuse
    m.insert("tk", 0.8);
    m.insert("ml", 0.8);
    m.insert("ga", 0.8);
    m.insert("cf", 0.8);
    m.insert("gq", 0.8);
    // Confusing / deceptive TLDs
    m.insert("zip", 0.7);
    m.insert("mov", 0.7);
    // Cheap TLDs popular with phishing/spam
    m.insert("top", 0.6);
    m.insert("click", 0.6);
    m.insert("loan", 0.6);
    m.insert("download", 0.6);
    m.insert("xyz", 0.5);
    m.insert("work", 0.5);
    m.insert("racing", 0.5);
    m.insert("win", 0.5);
    m.insert("bid", 0.5);
    m.insert("stream", 0.5);
    m.insert("gdn", 0.5);
    m.insert("icu", 0.5);
    m.insert("buzz", 0.4);
    m.insert("surf", 0.4);
    m.insert("rest", 0.4);
    m.insert("fit", 0.4);
    m
});

// ---------------------------------------------------------------------------
// Suspicious path patterns
// ---------------------------------------------------------------------------

static SUSPICIOUS_PATHS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"(?i)/wp-admin",
        r"(?i)/wp-login\.php",
        r"(?i)/administrator",
        r"(?i)/phpmyadmin",
        r"(?i)\.php\?.*cmd=",
        r"(?i)\.php\?.*exec=",
        r"(?i)\.php\?.*shell",
        r"(?i)eval\s*\(",
        r"(?i)/\.env",
        r"(?i)/\.git",
        r"(?i)/etc/passwd",
        r"(?i)/etc/shadow",
        r"(?i)/proc/self",
        r"(?i)\.\./\.\./",              // path traversal
        r"%25[0-9a-fA-F]{2}",           // double-encoded percent
        r"(?i)/cgi-bin/",
        r"(?i)\.aspx?\?.*=.*<script",   // XSS attempt
    ])
    .expect("invalid suspicious path regex")
});

// ---------------------------------------------------------------------------
// Homoglyph confusable map (ASCII lookalikes)
// ---------------------------------------------------------------------------

/// Map of Unicode characters to their ASCII confusable equivalents.
fn normalize_confusables(s: &str) -> String {
    s.nfkd()
        .map(|c| match c {
            '\u{0430}' => 'a', // Cyrillic а
            '\u{0435}' => 'e', // Cyrillic е
            '\u{043E}' => 'o', // Cyrillic о
            '\u{0440}' => 'p', // Cyrillic р
            '\u{0441}' => 'c', // Cyrillic с
            '\u{0443}' => 'y', // Cyrillic у
            '\u{0445}' => 'x', // Cyrillic х
            '\u{0456}' => 'i', // Ukrainian і
            '\u{0458}' => 'j', // Cyrillic ј
            '\u{04BB}' => 'h', // Cyrillic һ
            '\u{0501}' => 'd', // Cyrillic ԁ
            '\u{051B}' => 'q', // Cyrillic ԛ
            '0' => 'o',
            '1' => 'l',
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Simple edit distance (Levenshtein) for short strings.
/// Early exit when length difference exceeds the typical threshold (2).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = a.len();
    let m = b.len();

    // Fast path: if lengths differ by more than 2, distance is at least that
    if n.abs_diff(m) > 2 {
        return n.abs_diff(m);
    }

    if n == 0 { return m; }
    if m == 0 { return n; }

    let mut prev = vec![0usize; m + 1];
    let mut curr = vec![0usize; m + 1];

    for j in 0..=m {
        prev[j] = j;
    }

    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[m]
}

// ---------------------------------------------------------------------------
// Individual heuristic checks
// ---------------------------------------------------------------------------

/// Extract the registrable domain part (without TLD) for entropy analysis.
fn domain_without_tld(host: &str) -> &str {
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.rsplit_once('.') {
        Some((rest, _tld)) => rest,
        None => host,
    }
}

/// Extract the TLD from a host.
fn extract_tld(host: &str) -> &str {
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.rsplit_once('.') {
        Some((_rest, tld)) => tld,
        None => host,
    }
}

/// DGA detection via Shannon entropy on the domain part (excluding TLD).
pub fn dga_score(host: &str, threshold: f32) -> Vec<ThreatSignal> {
    let domain_part = domain_without_tld(host);
    let entropy = shannon_entropy(domain_part);
    let domain_len = domain_part.len();

    // High entropy + long domain = likely DGA
    if entropy >= threshold && domain_len >= 8 {
        let score = ((entropy - threshold) / 2.0).min(1.0) * 0.8;
        vec![ThreatSignal {
            name: "dga_entropy".into(),
            score,
            tier: ThreatTier::Tier0,
        }]
    } else if entropy >= threshold {
        let score = ((entropy - threshold) / 3.0).min(0.5);
        vec![ThreatSignal {
            name: "dga_entropy_mild".into(),
            score,
            tier: ThreatTier::Tier0,
        }]
    } else {
        vec![]
    }
}

/// TLD risk scoring.
///
/// Three tiers:
/// - Trusted (com/org/net/io/dev/etc): 0.0 — no signal
/// - Known-bad (tk/ml/ga/zip/etc): 0.4-0.8 — strong signal
/// - Unknown (everything else): 0.15 — mild signal, not in either list
pub fn tld_risk(host: &str) -> Vec<ThreatSignal> {
    let tld = extract_tld(host);

    // Trusted → no signal at all
    if TRUSTED_TLDS.contains(tld) {
        return vec![];
    }

    // Known-bad → strong signal
    if let Some(&risk) = BAD_TLDS.get(tld) {
        return vec![ThreatSignal {
            name: "tld_risk_bad".into(),
            score: risk * 0.3,
            tier: ThreatTier::Tier0,
        }];
    }

    // Unknown TLD — not trusted, not known-bad. Mild flag.
    vec![ThreatSignal {
        name: "tld_risk_unknown".into(),
        score: 0.15 * 0.3,
        tier: ThreatTier::Tier0,
    }]
}

/// Suspicious URL path patterns.
pub fn suspicious_path(path: &str) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();

    // Regex-based pattern matching
    let matches: Vec<_> = SUSPICIOUS_PATHS.matches(path).into_iter().collect();
    if !matches.is_empty() {
        let score = (matches.len() as f32 * 0.3).min(0.9);
        signals.push(ThreatSignal {
            name: "suspicious_path_pattern".into(),
            score,
            tier: ThreatTier::Tier0,
        });
    }

    // Excessively long paths
    if path.len() > 500 {
        signals.push(ThreatSignal {
            name: "excessive_path_length".into(),
            score: 0.2,
            tier: ThreatTier::Tier0,
        });
    }

    // Check for base64-like segments (length divisible by 4, valid charset, long enough)
    for segment in path.split('/') {
        if segment.len() >= 20
            && segment.len() % 4 == 0
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            signals.push(ThreatSignal {
                name: "base64_in_path".into(),
                score: 0.25,
                tier: ThreatTier::Tier0,
            });
            break;
        }
    }

    signals
}

/// Flag unusual ports (not standard web ports).
pub fn unusual_port(port: u16) -> Vec<ThreatSignal> {
    match port {
        80 | 443 | 8080 | 8443 => vec![],
        _ => vec![ThreatSignal {
            name: "unusual_port".into(),
            score: 0.15,
            tier: ThreatTier::Tier0,
        }],
    }
}

/// Check for homoglyph/typosquatting attacks against top domains.
pub fn homoglyph_check(host: &str, top_domains: &[String]) -> Vec<ThreatSignal> {
    let host_lower = host.to_ascii_lowercase();

    // Skip if the host IS a top domain exactly (not suspicious)
    if top_domains.iter().any(|d| d == &host_lower) {
        return vec![];
    }

    let normalized = normalize_confusables(host);

    // Check: does normalizing confusables make it match a top domain?
    // If so, the original was using homoglyphs to impersonate.
    for top_domain in top_domains {
        if normalized == *top_domain {
            return vec![ThreatSignal {
                name: format!("homoglyph_{top_domain}"),
                score: 0.8,
                tier: ThreatTier::Tier0,
            }];
        }
    }

    // Check for close edit-distance matches
    for top_domain in top_domains {
        let dist = edit_distance(&normalized, top_domain);
        if dist > 0 && dist <= 2 {
            let score = if dist == 1 { 0.7 } else { 0.4 };
            return vec![ThreatSignal {
                name: format!("homoglyph_{top_domain}"),
                score,
                tier: ThreatTier::Tier0,
            }];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Subdomain brand impersonation
// ---------------------------------------------------------------------------

/// Check if a host is on a known free hosting / dynamic DNS platform.
pub fn is_free_hosting(host: &str) -> bool {
    let host_lower = host.to_ascii_lowercase();
    FREE_HOSTING_DOMAINS.iter().any(|p| host_lower.ends_with(p))
}

/// Known free hosting / site builder platforms commonly abused for phishing.
static FREE_HOSTING_DOMAINS: Lazy<std::collections::HashSet<&'static str>> = Lazy::new(|| {
    [
        "webflow.io", "herokuapp.com", "netlify.app", "vercel.app",
        "pages.dev", "web.app", "firebaseapp.com", "glitch.me",
        "replit.dev", "github.io", "gitlab.io", "blogspot.com",
        "wordpress.com", "wixsite.com", "weebly.com", "carrd.co",
        "godaddysites.com", "square.site", "myshopify.com",
        // Dynamic DNS providers (heavily abused for phishing)
        "duckdns.org", "ddns.net", "hopto.org", "zapto.org",
        "sytes.net", "no-ip.org", "freedns.org", "dynu.com",
    ]
    .into_iter()
    .collect()
});

/// Phishing-related keywords commonly found in subdomain impersonation.
static PHISHING_KEYWORDS: &[&str] = &[
    "login", "signin", "sign-in", "sso", "auth", "secure", "verify",
    "account", "update", "confirm", "banking", "wallet", "recover",
    "unlock", "suspend", "alert", "notification", "password",
];

/// Detect phishing subdomain patterns structurally — no brand list needed.
///
/// Catches patterns like:
///   `secure---sso--robinhud-com-auth.webflow.io`  (auth keywords + free hosting + TLD mimicry)
///   `paypal-login-verify.herokuapp.com`            (auth keywords + free hosting)
///   `account-update-confirm-id8832.netlify.app`    (auth keywords + free hosting + long subdomain)
///
/// Signals stack: each suspicious trait adds to the score.
pub fn suspicious_subdomain(host: &str) -> Vec<ThreatSignal> {
    let host_lower = host.to_ascii_lowercase();

    let parts: Vec<&str> = host_lower.split('.').collect();
    if parts.len() < 3 {
        return vec![];
    }

    // Base domain (last two labels)
    let base_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

    // Subdomain is everything before the base (safe extraction via strip_suffix)
    let subdomain = match host_lower.strip_suffix(&format!(".{base_domain}")) {
        Some(s) => s,
        None => return vec![], // shouldn't happen, but don't panic
    };

    // Normalize separators for word extraction
    let normalized: String = subdomain
        .replace("---", " ")
        .replace("--", " ")
        .replace('-', " ")
        .replace('_', " ")
        .replace('.', " ");
    let words: Vec<&str> = normalized.split_whitespace().collect();

    let mut score = 0.0f32;
    let mut reasons = Vec::new();

    // 1. Free hosting / site builder platform
    let is_free_hosting = FREE_HOSTING_DOMAINS.contains(base_domain.as_str());
    if is_free_hosting {
        score += 0.15;
        reasons.push("free_hosting");
    }

    // 2. Auth/security phishing keywords in subdomain
    let keyword_count = PHISHING_KEYWORDS
        .iter()
        .filter(|kw| words.iter().any(|w| w == *kw))
        .count();
    if keyword_count > 0 {
        score += (keyword_count as f32 * 0.15).min(0.4);
        reasons.push("auth_keywords");
    }

    // 3. TLD-like words embedded in subdomain (mimicking URL structure)
    //    e.g., "robinhud-com-auth" has "com" as a word — pretending to be a domain
    let tld_words = words.iter().filter(|w| {
        matches!(**w, "com" | "org" | "net" | "io" | "co" | "us" | "uk" | "de")
    }).count();
    if tld_words > 0 {
        score += 0.2;
        reasons.push("tld_mimicry");
    }

    // 4. Excessive subdomain length (legitimate subdomains are short)
    if subdomain.len() > 30 {
        score += 0.1;
        reasons.push("long_subdomain");
    }
    if subdomain.len() > 50 {
        score += 0.1; // extra penalty
    }

    // 5. Many dash-separated segments (URL-structure mimicry)
    let dash_segments = subdomain.matches('-').count();
    if dash_segments >= 4 {
        score += 0.15;
        reasons.push("excessive_dashes");
    }

    // 6. Numbers embedded in word-like segments (account-id-38821, verify-0x8a)
    let has_mixed_alphanum = words.iter().any(|w| {
        w.len() >= 4
            && w.chars().any(|c| c.is_ascii_digit())
            && w.chars().any(|c| c.is_ascii_alphabetic())
    });
    if has_mixed_alphanum {
        score += 0.05;
        reasons.push("mixed_alphanum");
    }

    // Only emit a signal if there's a real accumulation of evidence
    if score < 0.2 {
        return vec![];
    }

    vec![ThreatSignal {
        name: format!("suspicious_subdomain({})", reasons.join("+")),
        score: score.min(1.0),
        tier: ThreatTier::Tier0,
    }]
}

// ---------------------------------------------------------------------------
// Master evaluation
// ---------------------------------------------------------------------------

/// Weights for combining signals into a final Tier 0 score.
const WEIGHT_DGA: f32 = 0.25;
const WEIGHT_TLD: f32 = 0.15;
const WEIGHT_PATH: f32 = 0.20;
const WEIGHT_PORT: f32 = 0.05;
const WEIGHT_HOMOGLYPH: f32 = 0.20;
const WEIGHT_BRAND_IMPERSONATION: f32 = 0.35;
const WEIGHT_BLOOM: f32 = 0.30;
const WEIGHT_NRD: f32 = 0.15;
const NRD_SCORE_HIGH_ENTROPY: f32 = 0.5;   // NRD + entropy > 4.0 → likely DGA
const NRD_SCORE_MED_ENTROPY: f32 = 0.3;    // NRD + entropy > 3.2 → suspicious
const NRD_SCORE_BASELINE: f32 = 0.15;      // NRD alone → mild signal
const NRD_ENTROPY_HIGH: f32 = 4.0;
const NRD_ENTROPY_MED: f32 = 3.2;
const WEIGHT_IP_REP: f32 = 0.25;

/// Run all Tier 0 heuristics and return a combined score + signals.
pub fn evaluate_all(
    host: &str,
    port: u16,
    path: &str,
    _scheme: &str,
    _category: Option<&str>,
    _reputation_score: Option<f32>, // unused since reputation refactor; kept for API compat
    dga_threshold: f32,
    bloom_hit: bool,
    nrd_hit: bool,
    ip_bad: bool,
    homoglyph_enabled: bool,
    top_domains: &[String],
) -> (f32, Vec<ThreatSignal>) {
    let mut signals = Vec::new();
    let mut weighted_sum = 0.0f32;
    let mut weight_total = 0.0f32;

    // DGA entropy
    let dga = dga_score(host, dga_threshold);
    if let Some(s) = dga.first() {
        weighted_sum += s.score * WEIGHT_DGA;
        weight_total += WEIGHT_DGA;
    }
    signals.extend(dga);

    // TLD risk
    let tld = tld_risk(host);
    if let Some(s) = tld.first() {
        weighted_sum += s.score * WEIGHT_TLD;
        weight_total += WEIGHT_TLD;
    }
    signals.extend(tld);

    // Suspicious path
    let path_signals = suspicious_path(path);
    if !path_signals.is_empty() {
        let max_score = path_signals.iter().map(|s| s.score).fold(0.0f32, f32::max);
        weighted_sum += max_score * WEIGHT_PATH;
        weight_total += WEIGHT_PATH;
    }
    signals.extend(path_signals);

    // Unusual port
    let port_signals = unusual_port(port);
    if let Some(s) = port_signals.first() {
        weighted_sum += s.score * WEIGHT_PORT;
        weight_total += WEIGHT_PORT;
    }
    signals.extend(port_signals);

    // Bloom filter hit (from threat feeds)
    // Score 0.6: strong signal but not enough to block alone (bloom has false positives).
    // Needs corroboration from other signals to reach block threshold.
    if bloom_hit {
        let sig = ThreatSignal {
            name: "bloom_hit".into(),
            score: 0.6,
            tier: ThreatTier::Tier0,
        };
        weighted_sum += sig.score * WEIGHT_BLOOM;
        weight_total += WEIGHT_BLOOM;
        signals.push(sig);
    }

    // NRD hit (newly registered domain)
    // Score depends on corroborating signals: NRD alone is mild, but NRD + entropy
    // or NRD + homoglyph is a strong phishing indicator.
    if nrd_hit {
        let entropy = shannon_entropy(domain_without_tld(host));
        let nrd_score = if entropy > NRD_ENTROPY_HIGH {
            NRD_SCORE_HIGH_ENTROPY
        } else if entropy > NRD_ENTROPY_MED {
            NRD_SCORE_MED_ENTROPY
        } else {
            NRD_SCORE_BASELINE
        };
        let sig = ThreatSignal {
            name: "nrd_hit".into(),
            score: nrd_score,
            tier: ThreatTier::Tier0,
        };
        weighted_sum += sig.score * WEIGHT_NRD;
        weight_total += WEIGHT_NRD;
        signals.push(sig);
    }

    // Bad IP
    if ip_bad {
        let sig = ThreatSignal {
            name: "bad_ip".into(),
            score: 0.9,
            tier: ThreatTier::Tier0,
        };
        weighted_sum += sig.score * WEIGHT_IP_REP;
        weight_total += WEIGHT_IP_REP;
        signals.push(sig);
    }

    // Homoglyph check (only when entropy is suspicious-ish)
    if homoglyph_enabled && !top_domains.is_empty() {
        let entropy = shannon_entropy(domain_without_tld(host));
        if entropy >= 2.0 {
            let hg = homoglyph_check(host, top_domains);
            if let Some(s) = hg.first() {
                weighted_sum += s.score * WEIGHT_HOMOGLYPH;
                weight_total += WEIGHT_HOMOGLYPH;
            }
            signals.extend(hg);
        }
    }

    // Suspicious subdomain structure (phishing patterns, free hosting, auth keywords)
    let sub_signals = suspicious_subdomain(host);
    if let Some(s) = sub_signals.first() {
        weighted_sum += s.score * WEIGHT_BRAND_IMPERSONATION;
        weight_total += WEIGHT_BRAND_IMPERSONATION;
    }
    signals.extend(sub_signals);

    // Normalize: weighted average of all signals
    let avg_score = if weight_total > 0.0 {
        weighted_sum / weight_total
    } else {
        0.0
    };

    // Floor logic: prevent weak signals from diluting strong ones.
    // - 2+ signals with any strong one (>0.5): floor at 70% of max (prevents dilution)
    // - 1 strong signal (>0.6): floor at 50% of max (single signal can't reach block alone)
    let max_raw = signals.iter().map(|s| s.score).fold(0.0f32, f32::max);
    let signal_count = signals.len();
    let floor = if max_raw > 0.5 && signal_count >= 2 {
        max_raw * 0.7
    } else if max_raw > 0.6 {
        max_raw * 0.5
    } else {
        0.0
    };

    let final_score = avg_score.max(floor).clamp(0.0, 1.0);

    (final_score, signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_domain() {
        let (score, signals) = evaluate_all(
            "google.com", 443, "/search?q=hello", "https",
            None, None, 3.5, false, false, false, false, &[],
        );
        assert!(score < 0.3, "google.com score={score}, signals={signals:?}");
    }

    #[test]
    fn dga_domain() {
        let (score, signals) = evaluate_all(
            "xk7m2p4q8r1w3z9.tk", 443, "/", "https",
            None, None, 3.5, false, false, false, false, &[],
        );
        assert!(score > 0.1, "DGA domain score={score}, signals={signals:?}");
    }

    #[test]
    fn bloom_hit_domain() {
        let (score, _) = evaluate_all(
            "example.com", 443, "/", "https",
            None, None, 3.5, true, false, false, false, &[],
        );
        assert!(score > 0.5, "bloom hit score={score}");
    }

    #[test]
    fn suspicious_path_detected() {
        let sigs = suspicious_path("/wp-admin/admin.php?cmd=whoami");
        assert!(!sigs.is_empty());
    }

    #[test]
    fn homoglyph_detection() {
        let top = vec!["google.com".to_string(), "paypal.com".to_string()];
        let sigs = homoglyph_check("g00gle.com", &top);
        assert!(!sigs.is_empty(), "should detect g00gle.com as homoglyph");
    }

    #[test]
    fn tld_risk_high() {
        let sigs = tld_risk("malware.tk");
        assert!(!sigs.is_empty());
        assert!(sigs[0].score > 0.1);
    }

    #[test]
    fn tld_risk_safe() {
        let sigs = tld_risk("google.com");
        assert!(sigs.is_empty(), "trusted TLD should produce no signal");
    }

    #[test]
    fn tld_risk_trusted_modern() {
        // io, dev, app should all be trusted — zero signal
        assert!(tld_risk("example.io").is_empty());
        assert!(tld_risk("example.dev").is_empty());
        assert!(tld_risk("example.app").is_empty());
        assert!(tld_risk("example.co").is_empty());
    }

    #[test]
    fn tld_risk_unknown() {
        // Some obscure TLD not in either list → mild signal
        let sigs = tld_risk("example.horse");
        assert!(!sigs.is_empty());
        assert!(sigs[0].score < 0.1, "unknown TLD should be mild, got {}", sigs[0].score);
    }

    #[test]
    fn suspicious_subdomain_webflow_phishing() {
        // Classic phishing: auth keywords + free hosting + TLD mimicry + long subdomain + dashes
        let sigs = suspicious_subdomain("secure---sso--robinhud-com-auth.webflow.io");
        assert!(!sigs.is_empty(), "should detect phishing subdomain pattern");
        assert!(sigs[0].score > 0.5, "score should be high, got {}", sigs[0].score);
    }

    #[test]
    fn suspicious_subdomain_heroku_login() {
        let sigs = suspicious_subdomain("paypal-login-verify.herokuapp.com");
        assert!(!sigs.is_empty(), "should detect login phishing on heroku");
        assert!(sigs[0].score > 0.3, "score should be moderate+, got {}", sigs[0].score);
    }

    #[test]
    fn suspicious_subdomain_legit_short() {
        // Legitimate short subdomains shouldn't trigger
        let sigs = suspicious_subdomain("mail.google.com");
        assert!(sigs.is_empty(), "legit subdomain shouldn't trigger");
    }

    #[test]
    fn suspicious_subdomain_legit_hosting() {
        // Simple app on free hosting — no phishing signals
        let sigs = suspicious_subdomain("myapp.herokuapp.com");
        assert!(sigs.is_empty() || sigs[0].score < 0.3,
            "simple app name on hosting shouldn't score high, got {:?}", sigs);
    }

    #[test]
    fn suspicious_subdomain_full_pipeline() {
        let top = vec!["google.com".to_string()];
        let (score, signals) = evaluate_all(
            "secure---sso--robinhud-com-auth.webflow.io", 443, "/", "https",
            None, None, 3.5, false, false, false, true, &top,
        );
        assert!(score > 0.4, "phishing domain should score high, got {score}");
        let sub_sig = signals.iter().find(|s| s.name.starts_with("suspicious_subdomain"));
        assert!(sub_sig.is_some(), "should have suspicious_subdomain signal, signals={signals:?}");
    }
}

//! Tier 1: ML-based threat scoring.
//!
//! Default implementation uses a hand-coded decision tree (no external deps).
//! Optional ONNX model support can be added via `onnx` cargo feature.

use super::entropy::shannon_entropy;

/// Feature vector extracted from Tier 0 signals + reputation.
pub struct FeatureVector {
    pub domain_entropy: f32,
    pub domain_length: u16,
    pub subdomain_depth: u8,
    pub tld_risk: f32,
    pub port_is_standard: bool,
    pub path_length: u16,
    pub path_entropy: f32,
    pub has_base64_in_url: bool,
    pub bloom_hit: bool,
    pub reputation_score: f32,
    pub is_first_visit: bool,
    pub tier0_score: f32,
}

impl FeatureVector {
    /// Build a feature vector from request context.
    pub fn from_request(
        host: &str,
        port: u16,
        path: &str,
        tld_risk_score: f32,
        bloom_hit: bool,
        reputation_score: f32,
        is_first_visit: bool,
        tier0_score: f32,
    ) -> Self {
        let domain_part = host
            .rsplit_once('.')
            .map(|(rest, _)| rest)
            .unwrap_or(host);

        let subdomain_depth = host.matches('.').count().saturating_sub(1) as u8;

        let has_base64 = path.split('/').any(|seg| {
            seg.len() >= 20
                && seg.len() % 4 == 0
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        });

        Self {
            domain_entropy: shannon_entropy(domain_part),
            domain_length: host.len().min(u16::MAX as usize) as u16,
            subdomain_depth,
            tld_risk: tld_risk_score,
            port_is_standard: matches!(port, 80 | 443 | 8080 | 8443),
            path_length: path.len().min(u16::MAX as usize) as u16,
            path_entropy: shannon_entropy(path),
            has_base64_in_url: has_base64,
            bloom_hit,
            reputation_score,
            is_first_visit,
            tier0_score,
        }
    }
}

/// Evaluate a feature vector using the hand-coded decision tree.
/// Returns a threat score between 0.0 and 1.0.
pub fn evaluate(features: &FeatureVector) -> f32 {
    // Gradient-boosted decision tree (hand-tuned, ~20 nodes)
    //
    // The tree combines multiple weak signals into a strong classifier.
    // Each branch contributes a partial score; they're summed and clamped.

    let mut score = 0.0f32;

    // Tree 1: Bloom filter is the strongest single signal
    if features.bloom_hit {
        score += 0.45;
    }

    // Tree 2: Domain entropy + length
    if features.domain_entropy > 4.0 {
        if features.domain_length > 20 {
            score += 0.25; // Very likely DGA
        } else {
            score += 0.12;
        }
    } else if features.domain_entropy > 3.5 {
        score += 0.06;
    }

    // Tree 3: Reputation + first visit
    if features.is_first_visit {
        if features.domain_entropy > 3.2 {
            score += 0.10;
        } else {
            score += 0.03;
        }
    }
    if features.reputation_score > 0.6 {
        score += (features.reputation_score - 0.6) * 0.5;
    }

    // Tree 4: Subdomain depth
    if features.subdomain_depth >= 3 {
        score += 0.08;
    } else if features.subdomain_depth >= 2 {
        score += 0.03;
    }

    // Tree 5: TLD risk
    if features.tld_risk > 0.5 {
        score += features.tld_risk * 0.15;
    }

    // Tree 6: Path analysis
    if features.has_base64_in_url {
        score += 0.08;
    }
    if features.path_length > 200 {
        score += 0.05;
    }
    if features.path_entropy > 4.5 {
        score += 0.06;
    }

    // Tree 7: Non-standard port
    if !features.port_is_standard {
        score += 0.04;
    }

    // Tree 8: Tier 0 score amplifier
    // If T0 already scored high, amplify slightly
    if features.tier0_score > 0.5 {
        score += (features.tier0_score - 0.5) * 0.2;
    }

    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_features_low_score() {
        let f = FeatureVector {
            domain_entropy: 2.5,
            domain_length: 10,
            subdomain_depth: 1,
            tld_risk: 0.0,
            port_is_standard: true,
            path_length: 20,
            path_entropy: 2.0,
            has_base64_in_url: false,
            bloom_hit: false,
            reputation_score: 0.1,
            is_first_visit: false,
            tier0_score: 0.05,
        };
        let score = evaluate(&f);
        assert!(score < 0.15, "safe features score={score}");
    }

    #[test]
    fn suspicious_features_high_score() {
        let f = FeatureVector {
            domain_entropy: 4.5,
            domain_length: 25,
            subdomain_depth: 3,
            tld_risk: 0.8,
            port_is_standard: false,
            path_length: 300,
            path_entropy: 5.0,
            has_base64_in_url: true,
            bloom_hit: true,
            reputation_score: 0.8,
            is_first_visit: true,
            tier0_score: 0.6,
        };
        let score = evaluate(&f);
        assert!(score > 0.7, "suspicious features score={score}");
    }

    #[test]
    fn bloom_hit_alone_significant() {
        let f = FeatureVector {
            domain_entropy: 2.5,
            domain_length: 10,
            subdomain_depth: 0,
            tld_risk: 0.0,
            port_is_standard: true,
            path_length: 10,
            path_entropy: 1.5,
            has_base64_in_url: false,
            bloom_hit: true,
            reputation_score: 0.5,
            is_first_visit: false,
            tier0_score: 0.3,
        };
        let score = evaluate(&f);
        assert!(score > 0.4, "bloom hit alone score={score}");
    }
}

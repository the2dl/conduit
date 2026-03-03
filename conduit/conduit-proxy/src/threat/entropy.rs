//! Shannon entropy calculation for DGA detection.

/// Calculate Shannon entropy of a string.
/// Returns 0.0 for empty strings, typically 3.0-4.0 for English words,
/// and 4.5+ for random/DGA-generated strings.
pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    let mut len = 0u32;

    for b in s.bytes() {
        freq[b as usize] += 1;
        len += 1;
    }

    let len_f = len as f64;
    let mut entropy = 0.0f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn normal_domain() {
        let e = shannon_entropy("google");
        assert!(e > 1.5 && e < 3.5, "google entropy = {e}");
    }

    #[test]
    fn dga_domain() {
        let e = shannon_entropy("x7k9m2p4q8r1w3");
        assert!(e > 3.5, "DGA-like entropy = {e}");
    }

    #[test]
    fn high_entropy_random() {
        let e = shannon_entropy("a1b2c3d4e5f6g7h8");
        assert!(e > 3.5, "random string entropy = {e}");
    }
}

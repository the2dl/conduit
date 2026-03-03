/// Constant-time byte comparison to prevent timing side-channel attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// HTML-escape a string to prevent XSS in rendered HTML.
pub fn html_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Escape RFC 5424 structured-data param values (`"`, `\`, `]`).
pub fn escape_sd_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// Escape a string for safe inclusion in a CSV field.
/// Wraps in double quotes, escapes embedded quotes, and prefixes formula-trigger
/// characters with an apostrophe to prevent spreadsheet formula injection.
/// Covers Excel (=, +, -, @), LibreOffice/Lotus (|), and whitespace-prefixed variants.
pub fn csv_escape(s: &str) -> String {
    let escaped = s.replace('"', "\"\"");
    let first = escaped.chars().next();
    let needs_prefix = matches!(first, Some('=' | '+' | '-' | '@' | '|' | '\t' | '\r' | '\n'));
    if needs_prefix {
        format!("\"'{}\"", escaped)
    } else {
        format!("\"{}\"", escaped)
    }
}

/// Escape Redis glob metacharacters in a user-supplied search string.
pub fn escape_redis_glob(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("safe"), "safe");
    }

    #[test]
    fn test_escape_sd_value() {
        assert_eq!(escape_sd_value(r#"a"b]c\d"#), r#"a\"b\]c\\d"#);
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("normal"), "\"normal\"");
        assert_eq!(csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(csv_escape("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(csv_escape("=SUM(A1)"), "\"'=SUM(A1)\"");
        assert_eq!(csv_escape("+cmd"), "\"'+cmd\"");
        assert_eq!(csv_escape("|cmd"), "\"'|cmd\"");
        assert_eq!(csv_escape("@SUM"), "\"'@SUM\"");
    }

    #[test]
    fn test_escape_redis_glob() {
        assert_eq!(escape_redis_glob("hello*world"), "hello\\*world");
        assert_eq!(escape_redis_glob("test[0]"), "test\\[0\\]");
        assert_eq!(escape_redis_glob("normal"), "normal");
    }
}

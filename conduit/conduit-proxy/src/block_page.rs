use conduit_common::config::ClearGateConfig;
use conduit_common::util::html_escape;

pub const DEFAULT_BLOCK_PAGE: &str = include_str!("block.html");

/// Extract or derive the node name from configuration.
pub fn get_node_name(config: &ClearGateConfig) -> String {
    config
        .node
        .as_ref()
        .and_then(|n| n.name.clone())
        .or_else(|| config.node.as_ref().map(|n| n.node_id.clone()))
        .unwrap_or_else(|| "conduit-01".to_string())
}

/// Generate a unique reference ID formatted like `cnd-7f3a-91c2`.
#[allow(dead_code)]
pub fn generate_ref_id() -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("cnd-{}-{}", &u[..4], &u[4..8])
}

/// Derive a formatted reference ID (`cnd-xxxx-xxxx`) from an existing UUID or string.
#[allow(dead_code)]
pub fn ref_id_from_uuid(id: &str) -> String {
    let cleaned: String = id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() >= 8 {
        format!("cnd-{}-{}", &cleaned[..4], &cleaned[4..8])
    } else {
        generate_ref_id()
    }
}

/// Mask sensitive values (e.g. API keys, credit cards) for safe display on block pages.
pub fn mask_sensitive(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len >= 12 {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[len - 4..].iter().collect();
        format!("{prefix}••••••••••••{suffix}")
    } else if len >= 6 {
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[len - 2..].iter().collect();
        format!("{prefix}••••{suffix}")
    } else {
        "••••••••".to_string()
    }
}

/// Context containing all parameters needed to render the block page.
#[derive(Debug, Clone)]
pub struct BlockPageContext<'a> {
    pub reason_type: &'a str, // "threat" | "category" | "dlp"
    pub eyebrow: &'a str,
    pub title: &'a str,
    pub message: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub detail_1_label: &'a str,
    pub detail_1_value: &'a str,
    pub detail_2_label: &'a str,
    pub detail_2_value: &'a str,
    pub user: &'a str,
    pub client_ip: &'a str,
    pub timestamp: &'a str,
    pub request_url: &'a str,
    pub request_label: &'a str,
    pub ref_id: &'a str,
    pub node: &'a str,
}

impl<'a> BlockPageContext<'a> {
    /// Factory for threat blocks (malware, phishing, DGA, bad reputation, feed matches).
    pub fn for_threat(
        host: &'a str,
        path: &'a str,
        method: &'a str,
        reason: &'a str,
        category: Option<&'a str>,
        user: Option<&'a str>,
        client_ip: &'a str,
        timestamp: &'a str,
        ref_id: &'a str,
        node: &'a str,
    ) -> Self {
        Self {
            reason_type: "threat",
            eyebrow: "Security threat",
            title: "This site was flagged as dangerous",
            message: "conduit stopped this request because the destination has a bad reputation for malware or phishing. Nothing was downloaded.",
            method: if method.is_empty() { "GET" } else { method },
            host,
            path: if path.is_empty() { "/" } else { path },
            detail_1_label: "Reason",
            detail_1_value: if reason.is_empty() { "Threat detected" } else { reason },
            detail_2_label: "Category",
            detail_2_value: category.unwrap_or("malicious"),
            user: match user {
                Some(u) if !u.is_empty() => u,
                _ => "unknown",
            },
            client_ip,
            timestamp,
            request_url: "#",
            request_label: "Report a false positive",
            ref_id,
            node,
        }
    }

    /// Factory for category/policy blocks (e.g. gambling, social media, adult content).
    pub fn for_policy(
        host: &'a str,
        path: &'a str,
        method: &'a str,
        policy_name: Option<&'a str>,
        category: Option<&'a str>,
        user: Option<&'a str>,
        client_ip: &'a str,
        timestamp: &'a str,
        ref_id: &'a str,
        node: &'a str,
    ) -> Self {
        Self {
            reason_type: "category",
            eyebrow: "Blocked by policy",
            title: "This site isn't available on this network",
            message: "Your organization blocks sites in this category. If you need it for work, request access and an administrator will review it.",
            method: if method.is_empty() { "GET" } else { method },
            host,
            path: if path.is_empty() { "/" } else { path },
            detail_1_label: "Policy",
            detail_1_value: policy_name.unwrap_or("Policy"),
            detail_2_label: "Category",
            detail_2_value: category.unwrap_or("uncategorized"),
            user: match user {
                Some(u) if !u.is_empty() => u,
                _ => "unknown",
            },
            client_ip,
            timestamp,
            request_url: "#",
            request_label: "Request access",
            ref_id,
            node,
        }
    }

    /// Factory for DLP (Data Loss Prevention) blocks.
    pub fn for_dlp(
        host: &'a str,
        path: &'a str,
        method: &'a str,
        rule_name: &'a str,
        matched_snippet: Option<&'a str>,
        user: Option<&'a str>,
        client_ip: &'a str,
        timestamp: &'a str,
        ref_id: &'a str,
        node: &'a str,
    ) -> Self {
        Self {
            reason_type: "dlp",
            eyebrow: "Sensitive data detected",
            title: "This upload contained sensitive data",
            message: "The request included data matching a data-protection rule, so it wasn't sent. Remove the sensitive content and try again.",
            method: if method.is_empty() { "POST" } else { method },
            host,
            path: if path.is_empty() { "/" } else { path },
            detail_1_label: "Rule",
            detail_1_value: if rule_name.is_empty() { "Sensitive Data" } else { rule_name },
            detail_2_label: "Match",
            detail_2_value: matched_snippet.unwrap_or("••••••••"),
            user: match user {
                Some(u) if !u.is_empty() => u,
                _ => "unknown",
            },
            client_ip,
            timestamp,
            request_url: "#",
            request_label: "Request an exception",
            ref_id,
            node,
        }
    }

    /// Render the block page HTML with all placeholders escaped.
    pub fn render(&self, custom_template: Option<&str>) -> String {
        let template = custom_template.unwrap_or(DEFAULT_BLOCK_PAGE);

        let escaped_reason = html_escape(self.reason_type);
        let escaped_eyebrow = html_escape(self.eyebrow);
        let escaped_title = html_escape(self.title);
        let escaped_message = html_escape(self.message);
        let escaped_method = html_escape(self.method);
        let escaped_host = html_escape(self.host);
        let escaped_path = html_escape(self.path);
        let escaped_d1_label = html_escape(self.detail_1_label);
        let escaped_d1_value = html_escape(self.detail_1_value);
        let escaped_d2_label = html_escape(self.detail_2_label);
        let escaped_d2_value = html_escape(self.detail_2_value);
        let escaped_user = html_escape(self.user);
        let escaped_client_ip = html_escape(self.client_ip);
        let escaped_timestamp = html_escape(self.timestamp);
        let escaped_request_url = html_escape(self.request_url);
        let escaped_request_label = html_escape(self.request_label);
        let escaped_ref_id = html_escape(self.ref_id);
        let escaped_node = html_escape(self.node);

        template
            .replace("{{reason}}", &escaped_reason)
            .replace("{{eyebrow}}", &escaped_eyebrow)
            .replace("{{title}}", &escaped_title)
            .replace("{{message}}", &escaped_message)
            .replace("{{method}}", &escaped_method)
            .replace("{{host}}", &escaped_host)
            .replace("{{path}}", &escaped_path)
            .replace("{{detail_1_label}}", &escaped_d1_label)
            .replace("{{detail_1_value}}", &escaped_d1_value)
            .replace("{{detail_2_label}}", &escaped_d2_label)
            .replace("{{detail_2_value}}", &escaped_d2_value)
            .replace("{{user}}", &escaped_user)
            .replace("{{client_ip}}", &escaped_client_ip)
            .replace("{{timestamp}}", &escaped_timestamp)
            .replace("{{request_url}}", &escaped_request_url)
            .replace("{{request_label}}", &escaped_request_label)
            .replace("{{ref_id}}", &escaped_ref_id)
            .replace("{{node}}", &escaped_node)
            // Backwards compatibility with legacy templates
            .replace("{{HOST}}", &escaped_host)
            .replace("{{CATEGORY}}", &escaped_d2_value)
            .replace("{{REASON}}", &escaped_d1_value)
    }
}

/// Fallback / universal block HTML builder matching the signature of the legacy `build_block_html`.
#[allow(dead_code)]
pub fn build_block_html(
    host: &str,
    category: &str,
    reason: &str,
    config: &ClearGateConfig,
) -> String {
    let node_name = get_node_name(config);
    let ref_id = generate_ref_id();
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let is_dlp = category == "dlp-violation" || reason.to_lowercase().contains("data loss prevention");
    let is_threat = category == "threat-detected" || reason.to_lowercase().contains("threat");

    let context = if is_dlp {
        let rule_name = if let Some(stripped) = reason.strip_prefix("Data loss prevention: ") {
            stripped
        } else {
            reason
        };
        BlockPageContext::for_dlp(
            host,
            "/",
            "POST",
            rule_name,
            None,
            None,
            "127.0.0.1",
            &timestamp,
            &ref_id,
            &node_name,
        )
    } else if is_threat {
        BlockPageContext::for_threat(
            host,
            "/",
            "GET",
            reason,
            Some(if category == "threat-detected" { "malicious" } else { category }),
            None,
            "127.0.0.1",
            &timestamp,
            &ref_id,
            &node_name,
        )
    } else {
        BlockPageContext::for_policy(
            host,
            "/",
            "GET",
            Some(reason),
            Some(category),
            None,
            "127.0.0.1",
            &timestamp,
            &ref_id,
            &node_name,
        )
    };

    context.render(config.block_page_html.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_threat_block() {
        let ctx = BlockPageContext::for_threat(
            "x7k9m2p4q8r1w3z9.com",
            "/test",
            "GET",
            "Threat detected (reputation)",
            Some("malicious"),
            Some("dan"),
            "10.0.4.18",
            "2026-09-29 14:18:10",
            "cnd-7f3a-91c2",
            "conduit-01",
        );

        let html = ctx.render(None);
        assert!(html.contains("data-reason=\"threat\""));
        assert!(html.contains("Security threat"));
        assert!(html.contains("This site was flagged as dangerous"));
        assert!(html.contains("x7k9m2p4q8r1w3z9.com"));
        assert!(html.contains("/test"));
        assert!(html.contains("Threat detected (reputation)"));
        assert!(html.contains("malicious"));
        assert!(html.contains("dan · 10.0.4.18"));
        assert!(html.contains("2026-09-29 14:18:10"));
        assert!(html.contains("Report a false positive"));
        assert!(html.contains("ref cnd-7f3a-91c2"));
        assert!(html.contains("conduit-01"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_policy_block() {
        let ctx = BlockPageContext::for_policy(
            "casinobpy.online",
            "/",
            "GET",
            Some("Block gambling & adult"),
            Some("gaming"),
            Some("dan"),
            "10.0.4.18",
            "2026-09-29 14:18:10",
            "cnd-7f3a-91c2",
            "conduit-01",
        );

        let html = ctx.render(None);
        assert!(html.contains("data-reason=\"category\""));
        assert!(html.contains("Blocked by policy"));
        assert!(html.contains("This site isn&#x27;t available on this network"));
        assert!(html.contains("casinobpy.online"));
        assert!(html.contains("Block gambling &amp; adult"));
        assert!(html.contains("gaming"));
        assert!(html.contains("dan · 10.0.4.18"));
        assert!(html.contains("Request access"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_dlp_block() {
        let ctx = BlockPageContext::for_dlp(
            "api.pastebin.com",
            "/api/api_post.php",
            "POST",
            "AWS Access Key",
            Some("AKIA••••••••••••7Q2L"),
            Some("dan"),
            "10.0.4.18",
            "2026-09-29 14:18:10",
            "cnd-7f3a-91c2",
            "conduit-01",
        );

        let html = ctx.render(None);
        assert!(html.contains("data-reason=\"dlp\""));
        assert!(html.contains("Sensitive data detected"));
        assert!(html.contains("This upload contained sensitive data"));
        assert!(html.contains("api.pastebin.com"));
        assert!(html.contains("/api/api_post.php"));
        assert!(html.contains("AWS Access Key"));
        assert!(html.contains("AKIA••••••••••••7Q2L"));
        assert!(html.contains("Request an exception"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_xss_escaping() {
        let ctx = BlockPageContext::for_threat(
            "<script>alert(1)</script>",
            "/path?q=<img src=x onerror=alert(2)>",
            "GET",
            "<b>malicious</b>",
            Some("<svg onload=alert(3)>"),
            Some("admin'\""),
            "192.168.1.1",
            "2026-09-29",
            "cnd-1234-5678",
            "node-test",
        );

        let html = ctx.render(None);
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<b>malicious</b>"));
        assert!(!html.contains("<svg onload="));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("admin&#x27;&quot;"));
    }

    #[test]
    fn test_mask_sensitive() {
        assert_eq!(mask_sensitive("AKIAIOSFODNN7EXAMPLE"), "AKIA••••••••••••MPLE");
        assert_eq!(mask_sensitive("4111222233334444"), "4111••••••••••••4444");
        assert_eq!(mask_sensitive("secret12"), "se••••12");
        assert_eq!(mask_sensitive("short"), "••••••••");
    }
}

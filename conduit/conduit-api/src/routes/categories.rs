use crate::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use conduit_common::redis::keys;
use conduit_common::types::CategoryEntry;
use conduit_common::util::escape_redis_glob;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tracing::{error, info, warn};

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
    search: Option<String>,
    category: Option<String>,
}

#[derive(Serialize)]
struct PaginatedCategories {
    entries: Vec<CategoryEntry>,
    next_cursor: Option<String>,
    total_estimate: Option<u64>,
}

async fn list_categories(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(PaginatedCategories {
                entries: vec![],
                next_cursor: None,
                total_estimate: None,
            }),
        );
    };

    let limit = q.limit.unwrap_or(100).min(500);
    let search = q.search.unwrap_or_default().to_lowercase();
    let category_filter = q.category.unwrap_or_default();

    let mut entries = Vec::with_capacity(limit);

    // If searching, try direct key lookups first (exact + common variations)
    if !search.is_empty() {
        let candidates = vec![
            search.clone(),
            format!("www.{search}"),
            format!("{search}.com"),
            format!("www.{search}.com"),
            format!("{search}.org"),
            format!("{search}.net"),
        ];
        for domain in &candidates {
            let key = keys::domain_category(domain);
            if let Ok(Some(cat)) = conn.get::<_, Option<String>>(&key).await {
                if category_filter.is_empty() || cat == category_filter {
                    entries.push(CategoryEntry {
                        domain: domain.clone(),
                        category: cat,
                        source: "feed".to_string(),
                    });
                }
            }
        }
    }

    // SCAN for more matches (larger budget when actively searching).
    // Escape glob metacharacters in user input to prevent pattern injection.
    let pattern = if search.is_empty() {
        "cleargate:domain:*".to_string()
    } else {
        format!("cleargate:domain:*{}*", escape_redis_glob(&search))
    };

    let scan_count: usize = if search.is_empty() { 500 } else { 10000 };
    let max_iterations: usize = if search.is_empty() { 200 } else { 2000 };

    let cursor_start: u64 = q
        .cursor
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let mut scan_cursor = cursor_start;
    let mut iterations = 0;

    // Track domains already added from direct lookup
    let existing: std::collections::HashSet<String> =
        entries.iter().map(|e| e.domain.clone()).collect();

    loop {
        let (next_cursor, batch_keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(scan_cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(scan_count)
            .query_async(&mut *conn)
            .await
            .unwrap_or((0, vec![]));

        for key in &batch_keys {
            let domain = key
                .strip_prefix("cleargate:domain:")
                .unwrap_or(key)
                .to_string();
            if existing.contains(&domain) {
                continue;
            }
            if let Ok(Some(cat)) = conn.get::<_, Option<String>>(key).await {
                if !category_filter.is_empty() && cat != category_filter {
                    continue;
                }
                entries.push(CategoryEntry {
                    domain,
                    category: cat,
                    source: "feed".to_string(),
                });
                if entries.len() >= limit {
                    break;
                }
            }
        }

        scan_cursor = next_cursor;
        iterations += 1;

        if entries.len() >= limit || scan_cursor == 0 || iterations >= max_iterations {
            break;
        }
    }

    for e in &mut entries {
        let is_manual: bool = conn
            .sismember(keys::CATEGORIES_MANUAL, &e.domain)
            .await
            .unwrap_or(false);
        e.source = if is_manual {
            "manual".to_string()
        } else {
            "feed".to_string()
        };
    }

    // Estimate total via DBSIZE (rough, includes non-category keys)
    let total_estimate: Option<u64> = redis::cmd("DBSIZE").query_async(&mut *conn).await.ok();

    let next_cursor = if scan_cursor == 0 {
        None
    } else {
        Some(scan_cursor.to_string())
    };

    (
        StatusCode::OK,
        Json(PaginatedCategories {
            entries,
            next_cursor,
            total_estimate,
        }),
    )
}

async fn add_category(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<CategoryEntry>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let key = keys::domain_category(&entry.domain);
    let _: () = conn.set(&key, &entry.category).await.unwrap_or(());
    let _: () = conn
        .sadd(keys::CATEGORIES_MANUAL, &entry.domain)
        .await
        .unwrap_or(());
    super::publish_reload(&state.pool, "categories").await;
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct DeleteQuery {
    domain: String,
}

async fn delete_category(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DeleteQuery>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };

    let key = keys::domain_category(&q.domain);
    let _: () = conn.del(&key).await.unwrap_or(());
    let _: () = conn
        .srem(keys::CATEGORIES_MANUAL, &q.domain)
        .await
        .unwrap_or(());
    super::publish_reload(&state.pool, "categories").await;
    StatusCode::NO_CONTENT
}

/// Bulk import domain categories from CSV or newline-delimited text.
/// Format: `domain,category` per line.
async fn import_categories(State(state): State<Arc<AppState>>, body: Body) -> impl IntoResponse {
    let Ok(bytes) = axum::body::to_bytes(body, 10 * 1024 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Body too large"})),
        );
    };
    let text = String::from_utf8_lossy(&bytes);

    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Redis unavailable"})),
        );
    };

    const MAX_IMPORT_ENTRIES: u64 = 100_000;

    let mut imported = 0u64;
    let mut pipe = redis::pipe();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((domain, category)) = line.split_once(',') {
            let domain = domain.trim();
            let category = category.trim();
            if !domain.is_empty() && !category.is_empty() {
                if imported >= MAX_IMPORT_ENTRIES {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(
                            serde_json::json!({"error": format!("import limited to {MAX_IMPORT_ENTRIES} entries per request")}),
                        ),
                    );
                }
                let key = keys::domain_category(domain);
                pipe.set(&key, category);
                imported += 1;
            }
        }
    }

    if imported > 0 {
        let _: () = pipe.query_async(&mut *conn).await.unwrap_or(());
        super::publish_reload(&state.pool, "categories").await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"imported": imported})),
    )
}

// ── Automated Agent Categorization ──────────────────────────────────

pub const CANONICAL_CATEGORIES: &[&str] = &[
    "search_engine",
    "social_media",
    "news_media",
    "shopping",
    "banking_finance",
    "email_messaging",
    "streaming_entertainment",
    "gaming",
    "education",
    "technology",
    "government",
    "healthcare",
    "adult",
    "advertising_tracking",
    "cdn_infrastructure",
    "vpn_proxy",
    "telecom_isp",
    "domain_hosting",
    "crypto_blockchain",
    "security_pki",
    "travel_transport",
    "jobs_freelance",
    "reference",
    "media_publishing",
    "business_services",
    "file_sharing",
    "other",
];

const KEY_LAST_AUTO_RUN: &str = "cleargate:categories:last_auto_run";
const KEY_LAST_UT1_RUN: &str = "cleargate:categories:last_ut1_run";

#[derive(Deserialize)]
struct PendingQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct PendingCategoriesResponse {
    count: usize,
    domains: Vec<String>,
}

#[derive(Deserialize, Default)]
struct AutoCategorizeRequest {
    agent: Option<String>,
    sync_ut1: Option<bool>,
    limit: Option<usize>,
    domains: Option<Vec<String>>,
}

#[derive(Serialize, Default, Debug)]
pub struct AutoCategorizeResult {
    pub success: bool,
    pub categorized_count: usize,
    pub categorized: Vec<CategoryEntry>,
    pub failed: Vec<String>,
    pub ut1_imported: bool,
    pub ut1_domains: u64,
    pub agent_used: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub fn resolve_agent_command(agent: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/dan".to_string());
    let candidates = match agent {
        "agy" => vec![
            format!("{home}/.local/share/mise/installs/antigravity-cli/latest/agy"),
            format!("{home}/.local/share/mise/shims/agy"),
            format!("{home}/.local/bin/agy"),
            "/usr/local/bin/agy".to_string(),
            "/usr/bin/agy".to_string(),
        ],
        "codex" => vec![
            format!("{home}/.local/share/mise/installs/codex/latest/bin/codex"),
            format!("{home}/.local/share/mise/shims/codex"),
            format!("{home}/.local/bin/codex"),
            "/usr/local/bin/codex".to_string(),
            "/usr/bin/codex".to_string(),
        ],
        "claude" => vec![
            format!("{home}/.local/share/mise/installs/npm-anthropic-ai-claude-code/latest/node_modules/.bin/claude"),
            format!("{home}/.local/share/mise/shims/claude"),
            format!("{home}/.local/bin/claude"),
            "/usr/local/bin/claude".to_string(),
            "/usr/bin/claude".to_string(),
        ],
        _ => vec![],
    };

    for path_str in candidates {
        let p = PathBuf::from(path_str);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let full = dir.join(agent);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

pub fn detect_available_agents() -> Vec<String> {
    ["agy", "codex", "claude"]
        .into_iter()
        .filter(|&a| resolve_agent_command(a).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let tag_end = lower[start..].find('>')? + start;
    let end = lower[tag_end..].find("</title>")? + tag_end;
    let title = html[tag_end + 1..end].trim();
    if title.is_empty() {
        return None;
    }
    let cleaned: String = title.split_whitespace().collect::<Vec<&str>>().join(" ");
    let truncated = if cleaned.len() > 100 {
        format!("{}...", &cleaned[..97])
    } else {
        cleaned
    };
    Some(truncated)
}

fn extract_meta_description(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    for marker in &[
        "name=\"description\"",
        "name='description'",
        "property=\"og:description\"",
        "property='og:description'",
    ] {
        if let Some(pos) = lower.find(marker) {
            let tag_start = lower[..pos].rfind("<meta")?;
            let tag_end = lower[pos..].find('>')? + pos;
            let tag = &html[tag_start..tag_end];
            if let Some(content_pos) = tag.to_lowercase().find("content=") {
                let rest = &tag[content_pos + 8..];
                let quote = rest.chars().next()?;
                if quote == '"' || quote == '\'' {
                    if let Some(end_quote) = rest[1..].find(quote) {
                        let desc = rest[1..=end_quote].trim();
                        if !desc.is_empty() {
                            let cleaned: String =
                                desc.split_whitespace().collect::<Vec<&str>>().join(" ");
                            let truncated = if cleaned.len() > 150 {
                                format!("{}...", &cleaned[..147])
                            } else {
                                cleaned
                            };
                            return Some(truncated);
                        }
                    }
                }
            }
        }
    }
    None
}

async fn probe_domain_metadata(client: &reqwest::Client, domain: &str) -> Option<String> {
    for scheme in &["https", "http"] {
        let url = format!("{scheme}://{domain}");
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() && resp.status().as_u16() >= 400 {
            continue;
        }
        let Ok(bytes) = resp.bytes().await else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(32768)]);
        let title = extract_html_title(&text);
        let desc = extract_meta_description(&text);

        match (title, desc) {
            (Some(t), Some(d)) => return Some(format!("Title: \"{t}\", Description: \"{d}\"")),
            (Some(t), None) => return Some(format!("Title: \"{t}\"")),
            (None, Some(d)) => return Some(format!("Description: \"{d}\"")),
            (None, None) => {}
        }
    }
    None
}

fn build_categorization_prompt(domains: &[(String, Option<String>)]) -> String {
    let mut domain_lines = Vec::new();
    for (d, meta) in domains {
        if let Some(m) = meta {
            domain_lines.push(format!("{d} ({m})"));
        } else {
            domain_lines.push(d.clone());
        }
    }
    let domain_list = domain_lines.join("\n");
    format!(
r#"You are a domain categorizer. For each domain, output ONLY the domain and its category separated by a comma. One per line. No headers, no explanations, no extra text. Do not use any tools.

Categories: search_engine, social_media, news_media, shopping, banking_finance, email_messaging, streaming_entertainment, gaming, education, technology, government, healthcare, adult, advertising_tracking, cdn_infrastructure, vpn_proxy, telecom_isp, domain_hosting, crypto_blockchain, security_pki, travel_transport, jobs_freelance, reference, media_publishing, business_services, file_sharing, other

Rules:
- Use ONLY the categories listed above
- If unsure, use "other"
- CDN, DNS, hosting infrastructure -> cdn_infrastructure
- Ad networks, analytics, tracking pixels -> advertising_tracking
- VPN, proxy, anonymizer services -> vpn_proxy
- Telcos, ISPs, mobile carriers -> telecom_isp
- Domain registrars, DNS registries, hosting providers -> domain_hosting
- Crypto, blockchain, Web3 RPC providers -> crypto_blockchain
- SSL/TLS certificates, CAPTCHAs, fraud prevention -> security_pki
- Travel, hotels, rideshare, logistics, shipping -> travel_transport
- Job boards, freelance marketplaces -> jobs_freelance
- Nonprofits, archives, standards bodies, wikis, weather -> reference
- Stock media, document sharing, blogs, CMS, publishing platforms -> media_publishing
- Consulting, reviews, crowdfunding, B2B SaaS -> business_services
- File hosting, torrents, cloud storage -> file_sharing
- URL shorteners, link redirectors -> technology
- Output nothing except domain,category lines

Domains to categorize:
{domain_list}"#
    )
}

fn parse_categorization_output(
    stdout: &str,
    requested_domains: &[String],
) -> (Vec<(String, String)>, Vec<String>) {
    let canonical: std::collections::HashSet<&str> = CANONICAL_CATEGORIES.iter().copied().collect();
    let mut results = Vec::new();
    let mut found_domains = std::collections::HashSet::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((dom_raw, cat_raw)) = line.split_once(',') {
            let dom = dom_raw.trim().to_lowercase();
            let cat = cat_raw.trim().to_lowercase();
            let dom = dom.trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
            let cat = cat.trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '.').to_string();

            if !dom.is_empty() && canonical.contains(cat.as_str()) {
                found_domains.insert(dom.clone());
                results.push((dom, cat));
            }
        }
    }

    let mut failed = Vec::new();
    for req in requested_domains {
        let req_lower = req.to_lowercase();
        if !found_domains.contains(&req_lower) {
            failed.push(req.clone());
        }
    }

    (results, failed)
}

pub async fn run_agent_categorization(
    agent: &str,
    binary: &Path,
    domains: &[String],
) -> anyhow::Result<(Vec<(String, String)>, Vec<String>)> {
    if domains.is_empty() {
        return Ok((vec![], vec![]));
    }

    // Probe domain metadata concurrently (up to 2s timeout)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .unwrap_or_default();

    let probe_futures = domains.iter().map(|d| {
        let client = client.clone();
        let d = d.clone();
        async move {
            let meta = probe_domain_metadata(&client, &d).await;
            (d, meta)
        }
    });
    let probed_domains = futures::future::join_all(probe_futures).await;

    let prompt = build_categorization_prompt(&probed_domains);
    let mut cmd = Command::new(binary);

    match agent {
        "agy" => {
            cmd.arg("--dangerously-skip-permissions");
            cmd.arg("-p");
            cmd.arg(&prompt);
        }
        "codex" => {
            cmd.arg("exec");
            cmd.arg("--skip-git-repo-check");
            cmd.arg(&prompt);
        }
        "claude" => {
            cmd.arg("-p");
            cmd.arg(&prompt);
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported agent: {agent}"));
        }
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/dan".to_string());
    let user = std::env::var("USER").unwrap_or_else(|_| "dan".to_string());
    let current_path = std::env::var("PATH").unwrap_or_default();
    let augmented_path = format!(
        "{home}/.local/share/mise/shims:{home}/.local/bin:{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:{current_path}"
    );

    cmd.env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env("HOME", &home)
        .env("USER", &user)
        .env("PATH", augmented_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(90), cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("Agent {agent} timed out after 90 seconds"))?
        .map_err(|e| anyhow::anyhow!("Failed to execute agent {agent}: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        warn!(
            agent,
            code = ?output.status.code(),
            stdout = %stdout,
            stderr = %stderr,
            "Agent command completed with non-zero status"
        );
    }

    let (results, failed) = parse_categorization_output(&stdout, domains);
    if results.is_empty() && !output.status.success() {
        let err_msg = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("Agent process exited with code {:?}", output.status.code())
        };
        return Err(anyhow::anyhow!("Agent failed: {err_msg}"));
    }

    Ok((results, failed))
}

pub async fn execute_auto_categorization(
    state: &AppState,
    agent_override: Option<String>,
    sync_ut1_override: Option<bool>,
    limit_override: Option<usize>,
    domain_override: Option<Vec<String>>,
) -> anyhow::Result<AutoCategorizeResult> {
    let start = std::time::Instant::now();
    let Ok(mut conn) = state.pool.get().await else {
        return Err(anyhow::anyhow!("Redis pool unavailable"));
    };

    // Determine agent
    let agent_name = if let Some(a) = agent_override {
        a
    } else {
        conn.get::<_, Option<String>>("cleargate:config:auto_categorize_agent")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "agy".to_string())
    };

    let binary = resolve_agent_command(&agent_name)
        .ok_or_else(|| anyhow::anyhow!("Agent executable not found for '{agent_name}'"))?;

    // Determine domains to categorize
    let domains_to_categorize: Vec<String> = if let Some(doms) = domain_override {
        doms
    } else {
        let limit = limit_override.unwrap_or(100).min(500);
        let res: Result<Vec<String>, _> = redis::cmd("SRANDMEMBER")
            .arg(keys::CATEGORIES_PENDING)
            .arg(limit as isize)
            .query_async(&mut *conn)
            .await;
        res.unwrap_or_default()
    };

    let mut result = AutoCategorizeResult {
        success: true,
        agent_used: agent_name.clone(),
        ..Default::default()
    };

    if !domains_to_categorize.is_empty() {
        info!(
            count = domains_to_categorize.len(),
            agent = %agent_name,
            "Running agent categorization"
        );

        match run_agent_categorization(&agent_name, &binary, &domains_to_categorize).await {
            Ok((categorized_pairs, failed)) => {
                if !categorized_pairs.is_empty() {
                    let mut pipe = redis::pipe();
                    for (d, c) in &categorized_pairs {
                        pipe.set(keys::domain_category(d), c);
                        pipe.srem(keys::CATEGORIES_PENDING, d);
                        result.categorized.push(CategoryEntry {
                            domain: d.clone(),
                            category: c.clone(),
                            source: format!("agent:{agent_name}"),
                        });
                    }
                    let _: () = pipe.query_async(&mut *conn).await.unwrap_or(());
                    super::publish_reload(&state.pool, "categories").await;
                }
                result.categorized_count = result.categorized.len();
                result.failed = failed;
            }
            Err(e) => {
                warn!(error = %e, agent = %agent_name, "Agent categorization failed");
                result.success = false;
                result.error = Some(e.to_string());
            }
        }
    }

    // UT1 sync if requested or enabled
    let should_sync_ut1 = if let Some(s) = sync_ut1_override {
        s
    } else {
        let cfg_val: Option<String> = conn
            .get("cleargate:config:auto_categorize_ut1")
            .await
            .unwrap_or(None);
        cfg_val.as_deref() == Some("true")
    };

    if should_sync_ut1 {
        info!("Fetching UT1 daily blacklist tarball");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(180))
            .no_proxy()
            .build();
        match client {
            Ok(cli) => {
                match cli
                    .get("https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz")
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.bytes().await {
                            Ok(bytes) => {
                                match crate::routes::import::import_ut1_data(state, bytes.to_vec()).await {
                                    Ok(stats) => {
                                        result.ut1_imported = true;
                                        result.ut1_domains = stats.total_domains;
                                        let now = chrono::Utc::now().timestamp();
                                        let _: Result<(), _> = conn.set(KEY_LAST_UT1_RUN, now).await;
                                    }
                                    Err(e) => {
                                        error!(error = %e, "UT1 import error during auto-categorize");
                                    }
                                }
                            }
                            Err(e) => error!(error = %e, "Failed reading UT1 bytes"),
                        }
                    }
                    Ok(resp) => error!(status = %resp.status(), "UT1 download returned non-200"),
                    Err(e) => error!(error = %e, "Failed to download UT1 tarball"),
                }
            }
            Err(e) => error!(error = %e, "Failed to create HTTP client for UT1"),
        }
    }

    let now = chrono::Utc::now().timestamp();
    let _: Result<(), _> = conn.set(KEY_LAST_AUTO_RUN, now).await;
    result.duration_ms = start.elapsed().as_millis() as u64;

    Ok(result)
}

pub fn spawn_auto_categorizer(state: Arc<AppState>) {
    tokio::spawn(async move {
        info!("Domain auto-categorization scheduler started");
        // Initial delay so services boot cleanly
        tokio::time::sleep(Duration::from_secs(10)).await;

        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let Ok(mut conn) = state.pool.get().await else {
                continue;
            };

            let enabled: Option<String> = conn
                .get("cleargate:config:auto_categorize_enabled")
                .await
                .unwrap_or(None);
            if enabled.as_deref() == Some("false") {
                continue;
            }

            let pending_count: usize = conn
                .scard(keys::CATEGORIES_PENDING)
                .await
                .unwrap_or(0);

            let now = chrono::Utc::now().timestamp();
            let last_run: i64 = conn
                .get(KEY_LAST_AUTO_RUN)
                .await
                .unwrap_or(0);

            let last_ut1: i64 = conn
                .get(KEY_LAST_UT1_RUN)
                .await
                .unwrap_or(0);

            let elapsed = now.saturating_sub(last_run);
            let ut1_elapsed = now.saturating_sub(last_ut1);

            let is_ut1_due = ut1_elapsed >= 86400;
            let is_agent_due = pending_count > 0 && (elapsed >= 86400 || pending_count >= 50);

            if is_agent_due || (is_ut1_due && pending_count > 0) {
                info!(
                    pending_count,
                    elapsed_secs = elapsed,
                    is_ut1_due,
                    "Triggering scheduled auto-categorization sweep"
                );
                let _ = execute_auto_categorization(
                    &state,
                    None,
                    Some(is_ut1_due),
                    Some(100),
                    None,
                )
                .await;
            }
        }
    });
}

async fn get_pending_categories(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PendingQuery>,
) -> impl IntoResponse {
    let Ok(mut conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Redis unavailable" })),
        );
    };

    let count: usize = conn
        .scard(keys::CATEGORIES_PENDING)
        .await
        .unwrap_or(0);

    let limit = q.limit.unwrap_or(100).min(1000);
    let domains: Vec<String> = if count > 0 && limit > 0 {
        let res: Result<Vec<String>, _> = redis::cmd("SRANDMEMBER")
            .arg(keys::CATEGORIES_PENDING)
            .arg(limit as isize)
            .query_async(&mut *conn)
            .await;
        res.unwrap_or_default()
    } else {
        vec![]
    };

    (
        StatusCode::OK,
        Json(serde_json::json!(PendingCategoriesResponse { count, domains })),
    )
}

async fn get_categorization_agents() -> impl IntoResponse {
    let available = detect_available_agents();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "available": available,
            "default": "agy"
        })),
    )
}

async fn trigger_auto_categorize(
    State(state): State<Arc<AppState>>,
    body: Option<Json<AutoCategorizeRequest>>,
) -> impl IntoResponse {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    match execute_auto_categorization(
        &state,
        req.agent,
        req.sync_ut1,
        req.limit,
        req.domains,
    )
    .await
    {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string(), "success": false })),
        ),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/categories",
            get(list_categories)
                .post(add_category)
                .delete(delete_category),
        )
        .route("/categories/import", post(import_categories))
        .route("/categories/pending", get(get_pending_categories))
        .route("/categories/agents", get(get_categorization_agents))
        .route("/categories/auto-categorize", post(trigger_auto_categorize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_categorization_output_clean() {
        let stdout = "\
clickhouse.com,technology
dashboard.civo.com,domain_hosting
pkg.dev,technology
github.com,technology
example-unknown.xyz,other
";
        let requested = vec![
            "clickhouse.com".to_string(),
            "dashboard.civo.com".to_string(),
            "pkg.dev".to_string(),
            "github.com".to_string(),
            "example-unknown.xyz".to_string(),
        ];
        let (results, failed) = parse_categorization_output(stdout, &requested);
        assert_eq!(results.len(), 5);
        assert!(failed.is_empty());
        assert_eq!(results[0], ("clickhouse.com".to_string(), "technology".to_string()));
        assert_eq!(results[1], ("dashboard.civo.com".to_string(), "domain_hosting".to_string()));
    }

    #[test]
    fn test_parse_categorization_output_with_noise_and_invalid_categories() {
        let stdout = "\
OpenAI Codex v0.159.2
--------
user: categorize these domains
clickhouse.com, technology
invalid.test, not_a_real_category
missing.test
tokens used: 123
";
        let requested = vec![
            "clickhouse.com".to_string(),
            "invalid.test".to_string(),
            "missing.test".to_string(),
        ];
        let (results, failed) = parse_categorization_output(stdout, &requested);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ("clickhouse.com".to_string(), "technology".to_string()));
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&"invalid.test".to_string()));
        assert!(failed.contains(&"missing.test".to_string()));
    }

    #[test]
    fn test_detect_available_agents() {
        let agents = detect_available_agents();
        // agy is installed on this machine
        assert!(agents.contains(&"agy".to_string()));
    }

    #[test]
    fn test_extract_html_title_and_description() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>   ClickHouse: Fast Open-Source OLAP DBMS   </title>
    <meta name="description" content="ClickHouse is a high-performance column-oriented SQL database.">
</head>
<body><h1>Welcome</h1></body>
</html>"#;
        assert_eq!(
            extract_html_title(html),
            Some("ClickHouse: Fast Open-Source OLAP DBMS".to_string())
        );
        assert_eq!(
            extract_meta_description(html),
            Some("ClickHouse is a high-performance column-oriented SQL database.".to_string())
        );
    }
}

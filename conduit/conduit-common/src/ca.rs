use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use deadpool_redis::Pool;
use std::path::Path;
use tracing::info;

use crate::redis::keys;

/// Root CA certificate and private key used to sign per-domain certs.
#[derive(Clone)]
pub struct CertAuthority {
    pub cert: X509,
    pub key: PKey<Private>,
    pub cert_pem: Vec<u8>,
}

impl CertAuthority {
    /// Load from disk or auto-generate if files don't exist.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            info!("Loading CA from {:?} and {:?}", cert_path, key_path);
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let cert = X509::from_pem(&cert_pem)?;
            let key = PKey::private_key_from_pem(&key_pem)?;
            Ok(Self {
                cert,
                key,
                cert_pem,
            })
        } else {
            info!("Generating new CA certificate");
            let ca = Self::generate()?;
            std::fs::write(cert_path, &ca.cert_pem)?;
            // Write private key with restrictive permissions (0600)
            {
                let key_pem = ca.key.private_key_to_pem_pkcs8()?;
                #[cfg(unix)]
                {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(key_path)?;
                    f.write_all(&key_pem)?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(key_path, &key_pem)?;
                }
            }
            info!("CA saved to {:?} and {:?}", cert_path, key_path);
            Ok(ca)
        }
    }

    /// Construct from PEM-encoded cert and key bytes.
    pub fn from_pem_bytes(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Self> {
        let cert = X509::from_pem(cert_pem)?;
        let key = PKey::private_key_from_pem(key_pem)?;
        Ok(Self {
            cert,
            key,
            cert_pem: cert_pem.to_vec(),
        })
    }

    /// Serialize the private key as PKCS#8 PEM.
    pub fn key_pem(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.key.private_key_to_pem_pkcs8()?)
    }

    /// SHA-256 fingerprint of the certificate (colon-separated hex).
    pub fn fingerprint(&self) -> String {
        self.cert
            .digest(boring::hash::MessageDigest::sha256())
            .map(|d| {
                d.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            })
            .unwrap_or_default()
    }

    /// Human-readable subject line (e.g. "C=US, O=conduit proxy, CN=conduit root ca").
    pub fn subject_string(&self) -> String {
        self.cert
            .subject_name()
            .entries()
            .map(|e| {
                let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default();
                format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Certificate expiry (not_after) as a string.
    pub fn not_after_string(&self) -> String {
        self.cert.not_after().to_string()
    }

    /// Generate a new RSA 4096 root CA.
    pub fn generate() -> anyhow::Result<Self> {
        let rsa = Rsa::generate(4096)?;
        let key = PKey::from_rsa(rsa)?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("C", "US")?;
        name.append_entry_by_text("O", "conduit proxy")?;
        name.append_entry_by_text("CN", "conduit root ca")?;
        let name = name.build();

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?; // X509 v3

        // Random 128-bit serial
        let mut serial = BigNum::new()?;
        serial.rand(128, boring::bn::MsbOption::MAYBE_ZERO, false)?;
        let asn1_serial = serial.to_asn1_integer()?;
        builder.set_serial_number(asn1_serial.as_ref())?;

        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;

        // Valid for 10 years
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(3650)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        // CA extensions
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new()
                .build(&builder.x509v3_context(None, None))?,
        )?;

        builder.sign(&key, MessageDigest::sha256())?;
        let cert = builder.build();
        let cert_pem = cert.to_pem()?;

        Ok(Self {
            cert,
            key,
            cert_pem,
        })
    }
}

/// Load CA certificate and private key from Dragonfly (atomic MGET).
/// Returns `Err` if either key is missing or the PEM is invalid.
pub async fn load_ca_from_dragonfly(pool: &Pool) -> anyhow::Result<CertAuthority> {
    let mut conn = pool.get().await?;
    let (cert_pem, key_pem): (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
        .arg(keys::CA_CERT)
        .arg(keys::CA_KEY)
        .query_async(&mut *conn)
        .await?;

    let cert_pem = cert_pem.ok_or_else(|| anyhow::anyhow!("CA cert not found in Dragonfly"))?;
    let key_pem = key_pem.ok_or_else(|| anyhow::anyhow!("CA key not found in Dragonfly"))?;

    CertAuthority::from_pem_bytes(&cert_pem, &key_pem)
}

/// Store CA certificate and private key in Dragonfly.
pub async fn store_ca_to_dragonfly(pool: &Pool, ca: &CertAuthority) -> anyhow::Result<()> {
    let key_pem = ca.key_pem()?;
    let mut conn = pool.get().await?;
    redis::pipe()
        .atomic()
        .set(keys::CA_CERT, &ca.cert_pem)
        .set(keys::CA_KEY, &key_pem)
        .exec_async(&mut *conn)
        .await?;
    Ok(())
}

/// Publish a CA reload notification to all proxy nodes via pub/sub.
pub async fn publish_ca_reload(pool: &Pool) {
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("PUBLISH")
            .arg(keys::CA_RELOAD_CHANNEL)
            .arg("ca")
            .query_async(&mut *conn)
            .await;
    }
}

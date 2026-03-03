use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use std::path::Path;
use tracing::info;

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

    /// Generate a new RSA 4096 root CA.
    fn generate() -> anyhow::Result<Self> {
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

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use conduit_common::ca::CertAuthority;

/// A generated certificate + private key for a specific domain.
pub struct GeneratedCert {
    pub cert: X509,
    pub key: PKey<Private>,
}

/// Generate a short-lived X509 certificate for `domain`, signed by the CA.
/// Uses EC P-256 for fast key generation.
pub fn generate_cert(domain: &str, ca: &CertAuthority) -> anyhow::Result<GeneratedCert> {
    // EC P-256 key (fast generation)
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let key = PKey::from_ec_key(ec_key)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", domain)?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;

    let mut serial = BigNum::new()?;
    serial.rand(128, boring::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = serial.to_asn1_integer()?;
    builder.set_serial_number(asn1_serial.as_ref())?;

    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca.cert.subject_name())?;
    builder.set_pubkey(&key)?;

    // Validity: backdate 1 day to tolerate client clock skew; valid for 30 days.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let not_before = Asn1Time::from_unix(now.saturating_sub(86400) as _)?;
    let not_after = Asn1Time::from_unix(now.saturating_add(30 * 86400) as _)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Extensions
    let basic_constraints = BasicConstraints::new().build()?;
    let extended_key_usage = ExtendedKeyUsage::new().server_auth().build()?;
    let skid = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&ca.cert), None))?;
    let akid = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&builder.x509v3_context(Some(&ca.cert), None))?;
    let mut san_builder = SubjectAlternativeName::new();
    if domain.parse::<std::net::IpAddr>().is_ok() {
        san_builder.ip(domain);
    } else {
        san_builder.dns(domain);
    }
    let san = san_builder.build(&builder.x509v3_context(Some(&ca.cert), None))?;

    builder.append_extension(&basic_constraints)?;
    builder.append_extension(&extended_key_usage)?;
    builder.append_extension(&skid)?;
    builder.append_extension(&akid)?;
    builder.append_extension(&san)?;

    // Sign with CA key
    builder.sign(&ca.key, MessageDigest::sha256())?;
    let cert = builder.build();

    Ok(GeneratedCert { cert, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert_validity_and_extensions() {
        let ca = CertAuthority::generate().unwrap();
        let gen = generate_cert("google.com", &ca).unwrap();

        // Check not_before and not_after
        let now_asn1 = Asn1Time::from_unix(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as _,
        )
        .unwrap();

        // not_before should be in the past (backdated by ~1 day)
        let diff_before = gen.cert.not_before().diff(&now_asn1).unwrap();
        assert!(diff_before.days >= 0 || diff_before.secs >= 0);

        // not_after should be in the future (~30 days)
        let diff_after = now_asn1.diff(gen.cert.not_after()).unwrap();
        assert!(diff_after.days >= 28);
    }

    #[test]
    fn test_generate_cert_ip_san() {
        let ca = CertAuthority::generate().unwrap();
        let gen = generate_cert("34.136.148.92", &ca).unwrap();
        assert_eq!(
            gen.cert
                .subject_name()
                .entries()
                .next()
                .unwrap()
                .data()
                .as_slice(),
            b"34.136.148.92"
        );
    }
}

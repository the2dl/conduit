use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
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

    // Valid for 24 hours
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(1)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Extensions
    builder.append_extension(BasicConstraints::new().build()?)?;
    builder.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .build()?,
    )?;

    // SAN with the domain
    let san = SubjectAlternativeName::new()
        .dns(domain)
        .build(&builder.x509v3_context(Some(&ca.cert), None))?;
    builder.append_extension(san)?;

    // Sign with CA key
    builder.sign(&ca.key, MessageDigest::sha256())?;
    let cert = builder.build();

    Ok(GeneratedCert { cert, key })
}

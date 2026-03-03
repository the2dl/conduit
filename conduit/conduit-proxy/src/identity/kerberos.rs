use conduit_common::types::UserIdentity;
use pingora_proxy::Session;
use tracing::debug;

/// Attempt to extract Kerberos/SPNEGO identity from Proxy-Authorization: Negotiate header.
///
/// **NOT YET IMPLEMENTED.** Full GSSAPI validation requires linking against system
/// Kerberos libraries (libgssapi_krb5). This stub always returns `None` — it does not
/// grant any identity. To enable Kerberos authentication, integrate with the `libgssapi`
/// crate and validate tokens against a KDC.
pub fn try_negotiate(session: &Session) -> Option<UserIdentity> {
    let req = session.req_header();
    let auth_header = req.headers.get("proxy-authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    if !auth_str.starts_with("Negotiate ") {
        return None;
    }

    debug!("Received Negotiate/SPNEGO token but Kerberos is not implemented — ignoring");

    // Always returns None — no identity is granted without GSSAPI validation.
    None
}

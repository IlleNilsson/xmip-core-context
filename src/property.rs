//! The names a property travels under when one layer writes it and another
//! reads it: what a transport says about an arrival, which the identity
//! gates read, and what the runtime puts in the Message Context, which a
//! route reads.
//!
//! A name read on one side of a boundary and written on the other is one
//! name, declared once, here, below both sides. Until 2026-09-24 the peer's
//! address was `xmip-core-library-net`'s, the SSH names were declared by
//! the SFTP transport and again by the two `ssh-key` gates, the HTTP header
//! prefix by two identify technologies, and the runtime wrote the sending
//! Party under a literal `route/party` declared for itself (the owner,
//! 2026-09-24: this crate owns every property name one layer writes and
//! another reads). A name the identity gates hand one another and nobody
//! else writes is not here: that is `identify::evidence`.
//!
//! What each carries, and in what form, is said with it. A transport that
//! has nothing to say under a name writes nothing under it.

// The peer, as the transport saw the connection.

/// The socket peer's address: `192.0.2.10:4711`, `[2001:db8::1]:443` or a
/// bare address. Written by the transport, recorded as evidence by
/// identification, checked by authorization.
pub const PEER_ADDRESS: &str = "peer.address";
/// The peer's hardware address, as the transport reported it.
pub const PEER_MAC: &str = "peer.mac";

// HTTP, as the transport read the request.

/// What every request header travels under, its name in lower case after:
/// `http.header.x-api-key`.
pub const HTTP_HEADER_PREFIX: &str = "http.header.";
/// What every query parameter travels under, its name after it.
pub const HTTP_QUERY_PREFIX: &str = "http.query.";
/// The `Authorization` header, whole: scheme and credentials.
pub const HTTP_AUTHORIZATION: &str = "http.header.authorization";
/// The `Cookie` header, whole.
pub const HTTP_COOKIE: &str = "http.header.cookie";
/// The `Forwarded` header (RFC 7239), whole.
pub const HTTP_FORWARDED: &str = "http.header.forwarded";
/// The `X-Forwarded-For` header, whole.
pub const HTTP_X_FORWARDED_FOR: &str = "http.header.x-forwarded-for";
/// A posted form's `SAMLResponse` field, as posted: base64.
pub const HTTP_FORM_SAML_RESPONSE: &str = "http.form.samlresponse";
/// The request's method, `POST`.
pub const HTTP_METHOD: &str = "http.method";
/// The request's target, as the request line gave it: `/in/orders`.
pub const HTTP_URI: &str = "http.uri";

// TLS, as the transport's handshake left it.

/// The peer certificate's subject distinguished name.
pub const TLS_PEER_SUBJECT: &str = "tls.peer.subject";
/// The user principal name a smart-card certificate holds as a
/// subjectAltName otherName, OID 1.3.6.1.4.1.311.20.2.3.
pub const TLS_PEER_UPN: &str = "tls.peer.upn";
/// The chain the peer sent, as PEM, leaf first.
pub const TLS_PEER_CHAIN: &str = "tls.peer.chain";
/// The transport's word that its handshake verified the chain: `true`.
pub const TLS_PEER_VERIFIED: &str = "tls.peer.verified";
/// The peer certificate's issuer distinguished name.
pub const TLS_PEER_ISSUER: &str = "tls.peer.issuer";
/// The peer certificate's fingerprint, `SHA256:` and its hex.
pub const TLS_PEER_FINGERPRINT: &str = "tls.peer.fingerprint";

// SSH, as the transport ran the public-key exchange (RFC 4252).

/// The public key the peer presented, as OpenSSH prints its fingerprint:
/// `SHA256:<base64>`.
pub const SSH_KEY: &str = "ssh.key";
/// The user the peer authenticated as.
pub const SSH_USER: &str = "ssh.user";
/// The signature the peer made with its key, base64.
pub const SSH_SIGNATURE: &str = "ssh.signature";
/// The session identifier that signature covers, base64.
pub const SSH_SESSION: &str = "ssh.session";

// NTLM, the handshake legs only the transport saw.

/// The NEGOTIATE (type 1) message of the handshake, base64, where the
/// transport kept it. It rides on to the second gate under this name too.
pub const NTLM_NEGOTIATE: &str = "ntlm.negotiate";
/// The CHALLENGE (type 2) message the node answered with, base64, where
/// the transport kept it. It rides on to the second gate under this name
/// too.
pub const NTLM_CHALLENGE: &str = "ntlm.challenge";

// The Message Context, as the runtime wrote it.

/// The Party the message identity resolved to: the sender.
pub const PARTY: &str = "xmip.party";
/// The Party a Message is for, where one is named.
pub const PARTY_RECEIVER: &str = "xmip.party.receiver";

/// Every name here, for a test that holds them apart.
pub const ALL: &[&str] = &[
    PEER_ADDRESS,
    PEER_MAC,
    HTTP_HEADER_PREFIX,
    HTTP_QUERY_PREFIX,
    HTTP_AUTHORIZATION,
    HTTP_COOKIE,
    HTTP_FORWARDED,
    HTTP_X_FORWARDED_FOR,
    HTTP_FORM_SAML_RESPONSE,
    HTTP_METHOD,
    HTTP_URI,
    TLS_PEER_SUBJECT,
    TLS_PEER_UPN,
    TLS_PEER_CHAIN,
    TLS_PEER_VERIFIED,
    TLS_PEER_ISSUER,
    TLS_PEER_FINGERPRINT,
    SSH_KEY,
    SSH_USER,
    SSH_SIGNATURE,
    SSH_SESSION,
    NTLM_NEGOTIATE,
    NTLM_CHALLENGE,
    PARTY,
    PARTY_RECEIVER,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_two_names_are_one() {
        let mut sorted = ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL.len());
    }

    #[test]
    fn a_header_travels_under_the_header_prefix_in_lower_case() {
        for header in [
            HTTP_AUTHORIZATION,
            HTTP_COOKIE,
            HTTP_FORWARDED,
            HTTP_X_FORWARDED_FOR,
        ] {
            let name = header.strip_prefix(HTTP_HEADER_PREFIX).expect("a header");
            assert_eq!(name, name.to_ascii_lowercase());
        }
    }
}

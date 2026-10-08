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

// A header, whichever protocol carried it.

/// What stands between a protocol and a header's name, written once for
/// the builders below and the well-known header names after them.
macro_rules! header_infix {
    () => {
        ".header."
    };
}

/// The protocols whose specification compares a header's name without
/// regard to case, each with the clause that says so. A header of one of
/// these travels under its name in lower case, so two spellings are one
/// header; a header of any other protocol keeps its name exactly as it
/// was written, because there `Trace-Id` and `trace-id` are two headers —
/// Kafka record headers, AMQP application properties, NATS headers and
/// MQTT user properties are compared byte for byte. The one table of it
/// (ADR-0046, amendment 2026-09-25).
pub const HEADER_CASE_FOLDING: &[(&str, &str)] = &[
    (
        "http",
        "RFC 9110 section 5.1: field names are case-insensitive",
    ),
    ("https", "RFC 9110 section 5.1, as http"),
    (
        "as2",
        "RFC 4130 section 5: HTTP, whose field names fold (RFC 9110 5.1)",
    ),
    (
        "as4",
        "OASIS AS4 profile: ebMS 3.0 over HTTP (RFC 9110 5.1)",
    ),
    ("webdav", "RFC 4918 section 10: HTTP headers (RFC 9110 5.1)"),
    (
        "websocket",
        "RFC 6455 section 4.1: the handshake is HTTP (RFC 9110 5.1)",
    ),
    (
        "ssdp",
        "UPnP Device Architecture 2.0 section 1: HTTPU, names fold",
    ),
    (
        "smtp",
        "RFC 5322 section 1.2.2: header field names are case-insensitive",
    ),
    ("imap", "RFC 5322 section 1.2.2, the messages IMAP carries"),
    ("pop3", "RFC 5322 section 1.2.2, the messages POP3 carries"),
    ("mime", "RFC 2045 section 1 and RFC 5322 section 1.2.2"),
    (
        "sip",
        "RFC 3261 section 7.3.1: field names are case-insensitive",
    ),
];

/// Whether `protocol`'s specification folds a header name's case, by
/// [`HEADER_CASE_FOLDING`].
#[must_use]
pub fn header_folds_case(protocol: &str) -> bool {
    HEADER_CASE_FOLDING
        .iter()
        .any(|(folding, _)| folding.eq_ignore_ascii_case(protocol))
}

/// The name a header travels under, on the arrival and in the Message
/// Context alike: `<protocol>.header.<name>` — `http.header.content-type`,
/// `amqp.header.x-priority`, `kafka.header.Trace-Id`. The protocol is the
/// transport's own word for what it speaks, as a URI scheme gives it, in
/// lower case as a scheme compares; the name is in lower case where the
/// protocol folds it ([`HEADER_CASE_FOLDING`]) and as written everywhere
/// else. Every transport that writes a header and every reader of one
/// builds the name here (the owner, 2026-09-24).
#[must_use]
pub fn header(protocol: &str, name: &str) -> String {
    let name = if header_folds_case(protocol) {
        name.to_ascii_lowercase()
    } else {
        name.to_string()
    };
    format!(
        concat!("{}", header_infix!(), "{}"),
        protocol.to_ascii_lowercase(),
        name
    )
}

/// What every header of `protocol` begins with: `http.header.`.
#[must_use]
pub fn header_prefix(protocol: &str) -> String {
    format!(
        concat!("{}", header_infix!()),
        protocol.to_ascii_lowercase()
    )
}

// HTTP, as the transport read the request.

/// What every query parameter travels under, its name after it.
pub const HTTP_QUERY_PREFIX: &str = "http.query.";
/// The `Authorization` header, whole: scheme and credentials.
pub const HTTP_AUTHORIZATION: &str = concat!("http", header_infix!(), "authorization");
/// The `Cookie` header, whole.
pub const HTTP_COOKIE: &str = concat!("http", header_infix!(), "cookie");
/// The `Forwarded` header (RFC 7239), whole.
pub const HTTP_FORWARDED: &str = concat!("http", header_infix!(), "forwarded");
/// The `X-Forwarded-For` header, whole.
pub const HTTP_X_FORWARDED_FOR: &str = concat!("http", header_infix!(), "x-forwarded-for");
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
/// What that signature covers, base64: RFC 4252's signed data, which opens
/// with the session identifier and names the user and the key.
pub const SSH_SESSION: &str = "ssh.session";

// NTLM, the handshake legs only the transport saw.

/// The NEGOTIATE (type 1) message of the handshake, base64, where the
/// transport kept it. It rides on to the second gate under this name too.
pub const NTLM_NEGOTIATE: &str = "ntlm.negotiate";
/// The CHALLENGE (type 2) message the node answered with, base64, where
/// the transport kept it. It rides on to the second gate under this name
/// too.
pub const NTLM_CHALLENGE: &str = "ntlm.challenge";

// A protocol's own word for its sender, each named after its field in the
// standard and written by the transport that reads it (the owner,
// 2026-10-06: *that goes for all streams*; ADR-0019 amendment 2026-10-06).

/// The reverse-path of SMTP's `MAIL FROM` (RFC 5321 section 4.1.1.2).
pub const SMTP_MAIL_FROM: &str = "smtp.mail-from";
/// The Calling-AE-title of a DICOM A-ASSOCIATE request (PS3.8 section 9.3.2).
pub const DICOM_CALLING_AE_TITLE: &str = "dicom.calling-ae-title";
/// A CAN frame's identifier, hexadecimal (ISO 11898-1): the sender on a bus
/// and on what rides on it — ISO-TP, UDS, OBD-II.
pub const CAN_IDENTIFIER: &str = "can.identifier";
/// A J1939 message's source address (SAE J1939-21), decimal.
pub const J1939_SOURCE_ADDRESS: &str = "j1939.source-address";
/// A CANopen node's Node-ID (CiA 301), decimal.
pub const CANOPEN_NODE_ID: &str = "canopen.node-id";
/// An EtherCAT slave's configured station address (ETG.1000.4), hexadecimal.
pub const ETHERCAT_STATION_ADDRESS: &str = "ethercat.station-address";
/// The IO-Link master port a device answers on (IEC 61131-9).
pub const IO_LINK_PORT: &str = "io-link.port";
/// A HART field device's address (HART 7, the polling or long address).
pub const HART_ADDRESS: &str = "hart.address";
/// A WirelessHART device's nickname, its DLPDU source address (IEC 62591).
pub const WIRELESS_HART_NICKNAME: &str = "wireless-hart.nickname";
/// An M-Bus slave's primary address (EN 13757-2).
pub const M_BUS_PRIMARY_ADDRESS: &str = "m-bus.primary-address";
/// A wireless M-Bus meter's identification number (EN 13757-4).
pub const M_BUS_IDENTIFICATION_NUMBER: &str = "m-bus.identification-number";
/// The user id a Unix-domain socket's peer process runs as, as
/// `SO_PEERCRED` reports it.
pub const UNIX_PEER_UID: &str = "unix.peer.uid";
/// The group id of that process.
pub const UNIX_PEER_GID: &str = "unix.peer.gid";
/// The process id of that process.
pub const UNIX_PEER_PID: &str = "unix.peer.pid";
/// The process id of a named pipe's client.
pub const NAMED_PIPE_CLIENT_PROCESS_ID: &str = "named-pipe.client-process-id";
/// The user id that owns a file taken from a folder or a share.
pub const FILE_OWNER: &str = "file.owner";
/// The group id that owns it.
pub const FILE_GROUP: &str = "file.group";
/// Its permission bits, octal: `0640`.
pub const FILE_MODE: &str = "file.mode";
/// AMQP 0-9-1's `user-id` message property, which the broker validates.
pub const AMQP_USER_ID: &str = "amqp.user-id";
/// IBM MQ's `UserIdentifier`, in the message descriptor (MQMD).
pub const IBM_MQ_USER_IDENTIFIER: &str = "ibm-mq.user-identifier";
/// Amazon SQS's `SenderId` message system attribute.
pub const SQS_SENDER_ID: &str = "sqs.sender-id";

// The Message Context, as the runtime wrote it.

/// The Party the message identity resolved to: the sender.
pub const PARTY: &str = "xmip.party";
/// The Party a Message is for, where one is named.
pub const PARTY_RECEIVER: &str = "xmip.party.receiver";

/// Every name here, for a test that holds them apart.
pub const ALL: &[&str] = &[
    PEER_ADDRESS,
    PEER_MAC,
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
    SMTP_MAIL_FROM,
    DICOM_CALLING_AE_TITLE,
    CAN_IDENTIFIER,
    J1939_SOURCE_ADDRESS,
    CANOPEN_NODE_ID,
    ETHERCAT_STATION_ADDRESS,
    IO_LINK_PORT,
    HART_ADDRESS,
    WIRELESS_HART_NICKNAME,
    M_BUS_PRIMARY_ADDRESS,
    M_BUS_IDENTIFICATION_NUMBER,
    UNIX_PEER_UID,
    UNIX_PEER_GID,
    UNIX_PEER_PID,
    NAMED_PIPE_CLIENT_PROCESS_ID,
    FILE_OWNER,
    FILE_GROUP,
    FILE_MODE,
    AMQP_USER_ID,
    IBM_MQ_USER_IDENTIFIER,
    SQS_SENDER_ID,
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
    fn a_header_travels_under_its_protocol_and_its_name() {
        assert_eq!(header("http", "Content-Type"), "http.header.content-type");
        assert_eq!(header("AMQP", "x-priority"), "amqp.header.x-priority");
        assert_eq!(header("kafka", "Trace-Id"), "kafka.header.Trace-Id");
        assert_eq!(header_prefix("http"), "http.header.");
        assert!(header("http", "x-api-key").starts_with(&header_prefix("http")));
    }

    #[test]
    fn http_folds_a_header_names_case_and_kafka_keeps_it() {
        assert_eq!(header("http", "Trace-Id"), header("http", "trace-id"));
        assert_eq!(header("HTTP", "Trace-Id"), header("http", "TRACE-ID"));
        assert_ne!(header("kafka", "Trace-Id"), header("kafka", "trace-id"));
        for protocol in ["kafka", "amqp", "nats", "mqtt"] {
            assert!(!header_folds_case(protocol), "{protocol}");
        }
        for (protocol, clause) in HEADER_CASE_FOLDING {
            assert!(header_folds_case(protocol));
            assert_eq!(*protocol, protocol.to_ascii_lowercase());
            assert!(!clause.is_empty());
        }
    }

    #[test]
    fn the_well_known_http_headers_are_the_builders_names() {
        for (constant, name) in [
            (HTTP_AUTHORIZATION, "Authorization"),
            (HTTP_COOKIE, "Cookie"),
            (HTTP_FORWARDED, "Forwarded"),
            (HTTP_X_FORWARDED_FOR, "X-Forwarded-For"),
        ] {
            assert_eq!(constant, header("http", name));
        }
    }
}

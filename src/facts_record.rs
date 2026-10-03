//! What arrival concluded of a Message's identities, in one binary form:
//! what the Ledger keeps beside a Journey a paused Subscription holds, so
//! its departure reads back the identities the Message arrived with,
//! whichever node picks it up and however long after (ADR-0019 clause 6;
//! `runtime-model.md` section 9).
//!
//! The fields are written in their order — no names, no padding, as the
//! Message's and the Journey's records are: text as its length and its
//! UTF-8 bytes, an identifier as 16 bytes big-endian, a time as 16, each
//! enumeration as its number, an absent value as one byte saying so. The
//! first byte is the form's number, [`FORM`].
//!
//! **A mechanism is never built from a record** (`xcore::Mechanism`): the
//! record names it, and [`IdentityFacts::from_record`] is told which
//! mechanism of that name the reader carries. One the reader no longer
//! carries is refused, in words.

use codec::CodecError;
use codec::cursor::Cursor;
use codec::field::{many, optional, place, placed, read_many, read_optional, read_text, text};
use codec::writer::ByteWriter;
use xcore::{Established, Mechanism, PartyId};

use crate::{AlignmentResult, AuthenticatedIdentity, IdentityFacts, Verified};

/// The form's number, the first byte of every record written in it.
pub const FORM: u8 = 1;

impl IdentityFacts {
    /// Both identities and their alignment, in their one binary form.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.byte(FORM);
        identity(&mut out, &self.transport);
        optional(&mut out, self.message.as_ref(), identity);
        out.byte(place(&AlignmentResult::ALL, &self.alignment));
        out
    }

    /// The facts `bytes` hold in their one binary form, and nothing after
    /// them, each mechanism the one `carried` says the reader carries under
    /// the name recorded.
    ///
    /// # Errors
    ///
    /// Where the bytes are not one — another form, a field cut short, a
    /// number naming nothing, bytes after it — or a mechanism recorded is
    /// not carried.
    pub fn from_record(
        bytes: &[u8],
        carried: impl Fn(&str) -> Option<Mechanism>,
    ) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let form = cursor.byte()?;
        if form != FORM {
            return Err(CodecError::new(format!(
                "identity facts of form {form}, and this reads form {FORM}"
            )));
        }
        let transport = read_identity(&mut cursor, &carried)?;
        let message = read_optional(&mut cursor, |c| read_identity(c, &carried))?;
        let alignment = placed(&AlignmentResult::ALL, cursor.byte()?, "alignment")?;
        if !cursor.is_empty() {
            return Err(CodecError::new("bytes after the identity facts"));
        }
        Ok(Self {
            transport,
            message,
            alignment,
        })
    }
}

fn identity(out: &mut Vec<u8>, identity: &AuthenticatedIdentity) {
    text(out, identity.mechanism.name());
    text(out, &identity.value);
    out.byte(place(&Established::ALL, &identity.established))
        .byte(place(&Verified::ALL, &identity.verified));
    optional(out, identity.party_id, |out, party| {
        out.u128_be(party.value());
    });
    many(out, &identity.evidence, |out, (name, value)| {
        text(out, name);
        text(out, value);
    });
    out.i128_be(identity.authenticated_at);
}

fn read_identity(
    cursor: &mut Cursor<'_>,
    carried: &impl Fn(&str) -> Option<Mechanism>,
) -> Result<AuthenticatedIdentity, CodecError> {
    let name = read_text(cursor)?;
    let mechanism = carried(&name).ok_or_else(|| {
        CodecError::new(format!(
            "the mechanism '{name}' the identity was concluded by is not carried here"
        ))
    })?;
    let value = read_text(cursor)?;
    let established = placed(&Established::ALL, cursor.byte()?, "establishment")?;
    let verified = placed(&Verified::ALL, cursor.byte()?, "verification")?;
    let party_id = read_optional(cursor, |c| Ok(PartyId::new(c.u128_be()?)))?;
    let evidence = read_many(cursor, |c| Ok((read_text(c)?, read_text(c)?)))?;
    let mut identity =
        AuthenticatedIdentity::new(mechanism, value, established, verified).at(cursor.i128_be()?);
    identity.party_id = party_id;
    identity.evidence = evidence;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Alignment;
    use xcore::mechanism;

    fn carried(name: &str) -> Option<Mechanism> {
        [mechanism::circumstance()]
            .into_iter()
            .find(|mechanism| mechanism.name() == name)
    }

    fn facts() -> IdentityFacts {
        let identity = |value: &str| {
            AuthenticatedIdentity::new(
                mechanism::circumstance(),
                value,
                Established::Inferred,
                Verified::Claimed,
            )
            .at(-7)
        };
        IdentityFacts::evaluate(
            Alignment::Strict,
            identity("tcp://127.0.0.1:1")
                .resolving_to(PartyId::new(3))
                .with_evidence("peer", "127.0.0.1 — åäö"),
            Some(identity("ISA06=PARTYX")),
        )
    }

    #[test]
    fn the_facts_come_back_from_their_record_as_they_were() {
        let facts = facts();
        let record = facts.record();
        assert_eq!(record[0], FORM);
        assert_eq!(
            IdentityFacts::from_record(&record, carried).expect("read"),
            facts
        );
        let alone = IdentityFacts::evaluate(Alignment::None, facts.transport.clone(), None);
        let read = IdentityFacts::from_record(&alone.record(), carried).expect("read");
        assert_eq!(read, alone);
    }

    #[test]
    fn a_mechanism_not_carried_or_bytes_that_are_not_a_record_are_refused() {
        let record = facts().record();
        let refused = IdentityFacts::from_record(&record, |_| None).expect_err("not carried");
        assert!(refused.message.contains("'circumstance'"), "{refused}");
        for cut in [0, 1, record.len() - 1] {
            assert!(IdentityFacts::from_record(&record[..cut], carried).is_err());
        }
        let longer = [record.as_slice(), &[0]].concat();
        assert!(IdentityFacts::from_record(&longer, carried).is_err());
    }
}
